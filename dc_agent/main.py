import json
import asyncio
import httpx
import subprocess
import xml.etree.ElementTree as ET
import win32evtlog
import logging

CONFIG_PATH = "config.json"
DEBUG = False

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("main.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

event_queue = asyncio.Queue()
loop = None
config = {}
aliases_cache = {}
user_mapping = {}

def load_config():
    global config
    try:
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            config = json.load(f)
        logging.debug(f"[CONFIG] Configuration loaded. Allowed IPs count: {len(config.get('ip_list', []))}")
    except Exception as e:
        logging.error(f"[CONFIG] Failed to load config: {e}")
        raise

def get_users_in_group(group: str) -> set:
    cmd = f"Get-ADGroupMember -Identity '{group}' -Recursive | Select-Object -ExpandProperty SamAccountName"
    try:
        startupinfo = subprocess.STARTUPINFO()
        startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
        
        result = subprocess.check_output(
            ["powershell", "-NoProfile", "-Command", cmd], 
            text=True, 
            startupinfo=startupinfo
        )
        users = {u.strip().lower() for u in result.split('\n') if u.strip()}
        logging.debug(f"[AD] Group '{group}': Found {len(users)} users.")
        return users
    except subprocess.CalledProcessError:
        logging.error(f"[AD] Failed to fetch users for group: {group}")
        return set()

async def update_cache_periodically():
    while True:
        logging.debug("[CACHE] Refreshing AD group members...")
        for alias_name, groups in config.get('mapping', {}).items():
            all_users = set()
            for group in groups:
                all_users.update(get_users_in_group(group))
            user_mapping[alias_name] = all_users
            logging.debug(f"[CACHE] Alias '{alias_name}': Cached {len(all_users)} authorized users.")
        logging.debug("[CACHE] AD cache update complete.")
        logging.debug("[CACHE] Refreshing config.json cache...")
        load_config()
        await asyncio.sleep(600)

async def init_pfsense_state():
    global aliases_cache
    headers = {"X-API-Key": API_KEY, "Accept": "application/json"}
    
    async with httpx.AsyncClient(base_url=PFSENSE_URL, headers=headers, verify=False) as client:
        try:
            response = await client.get("/api/v2/firewall/aliases?type=host")
            response.raise_for_status()
            data = response.json().get("data", [])
            
            for alias in data:
                if alias["name"] in config.get("mapping", {}):
                    aliases_cache[alias["name"]] = {
                        "id": alias["id"],
                        "address": set(alias.get("address", []))
                    }
            logging.info(f"[PFSENSE] Cache initialized for aliases: {list(aliases_cache.keys())}")
        except Exception as e:
            logging.error(f"[PFSENSE] Failed to initialize state: {e}")
            raise

async def process_event_worker():
    headers = {"X-API-Key": API_KEY, "Accept": "application/json"}
    
    async with httpx.AsyncClient(base_url=PFSENSE_URL, headers=headers, verify=False) as client:
        while True:
            event = await event_queue.get()
            ip, username = event['ip'], event['username']
            needs_apply = False
            
            logging.debug(f"[WORKER] Processing event: User='{username}', IP='{ip}'")
            
            for alias_name, allowed_users in user_mapping.items():
                if alias_name not in aliases_cache:
                    continue
                    
                alias_data = aliases_cache[alias_name]
                current_ips = alias_data["address"]
                
                should_be_in_alias = username in allowed_users
                alias_changed = False
                
                if should_be_in_alias and ip not in current_ips:
                    current_ips.add(ip)
                    alias_changed = True
                    action_msg = "ADDED"
                elif not should_be_in_alias and ip in current_ips:
                    current_ips.remove(ip)
                    alias_changed = True
                    action_msg = "REMOVED"
                
                if alias_changed:
                    payload = {
                        "id": alias_data["id"],
                        "name": alias_name,
                        "type": "host",
                        "address": list(current_ips)
                    }
                    try:
                        resp = await client.patch("/api/v2/firewall/alias", json=payload)
                        resp.raise_for_status()
                        needs_apply = True
                        logging.info(f"[SYNC] Alias='{alias_name}': IP='{ip}' {action_msg} (User: {username})")
                    except Exception as e:
                        logging.error(f"[SYNC] API Error updating '{alias_name}': {e}")
                        # Rollback cache on failure
                        if should_be_in_alias: current_ips.remove(ip)
                        else: current_ips.add(ip)

            if needs_apply:
                try:
                    await client.post("/api/v2/firewall/apply")
                    logging.info("[PFSENSE] Changes applied successfully.")
                except Exception as e:
                    logging.error(f"[PFSENSE] Apply failed: {e}")
            
            event_queue.task_done()

def on_event_callback(action, context, event_handle):
    if action == win32evtlog.EvtSubscribeActionDeliver:
        try:
            xml_str = win32evtlog.EvtRender(event_handle, win32evtlog.EvtRenderEventXml)
            root = ET.fromstring(xml_str)
            ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
            
            user_node = root.find(".//ns:Data[@Name='TargetUserName']", ns)
            ip_node = root.find(".//ns:Data[@Name='IpAddress']", ns)
            
            if user_node is None or ip_node is None:
                return

            username = (user_node.text or "").strip()
            ip = (ip_node.text or "").strip()

            # Filter: System accounts
            if not username or username.endswith("$"):
                logging.debug(f"[EVT_FILTER] Skipped system account: {username}")
                return
            
            # Filter: Invalid/Local IPs
            if not ip or ip in ("-", "127.0.0.1", "::1"):
                logging.debug(f"[EVT_FILTER] Skipped invalid IP: {ip}")
                return
            
            # Filter: Allowed IP list from config
            allowed_ips = [str(i).strip() for i in config.get("ip_list", [])]
            if allowed_ips and ip not in allowed_ips:
                logging.debug(f"[EVT_FILTER] Skipped IP not in whitelist: {ip}")
                return

            logging.debug(f"[EVT_FILTER] Match found: User='{username}', IP='{ip}'. Queuing...")
            
            loop.call_soon_threadsafe(event_queue.put_nowait, {
                "ip": ip, 
                "username": username.lower()
            })

        except Exception as e:
            logging.error(f"[CALLBACK] Error processing event: {e}")

def start_windows_subscription():
    query = """
    <QueryList>
      <Query Id="0" Path="Security">
        <Select Path="Security">
          *[System[(EventID=4624)]] 
          and *[EventData[Data[@Name='LogonType']='2' or Data[@Name='LogonType']='3' or Data[@Name='LogonType']='10']]
        </Select>
      </Query>
    </QueryList>
    """
    subscription = win32evtlog.EvtSubscribe(
        'Security', 
        win32evtlog.EvtSubscribeToFutureEvents, 
        None, 
        Callback=on_event_callback, 
        Query=query
    )
    return subscription

async def main():
    global loop
    loop = asyncio.get_running_loop()
    
    logging.info("=== Starting AD -> pfSense Sync Service ===")
    load_config()
    global PFSENSE_URL, API_KEY
    PFSENSE_URL = config["PFSENSE_URL"]
    API_KEY = config["PFSENSE_RESTAPI_KEY"]

    if not PFSENSE_URL or not API_KEY:
        logging.error("[MAIN] Missing PFSENSE_URL or PFSENSE_RESTAPI_KEY in environment variables.")
        raise ValueError("pfSense parameters are not set.")
    await init_pfsense_state()
    
    logging.info("[MAIN] Initializing Windows Event subscription...")
    sub = start_windows_subscription() 
    
    logging.info("[MAIN] Launching background tasks...")
    asyncio.create_task(update_cache_periodically())
    worker_task = asyncio.create_task(process_event_worker())
    
    logging.info("[MAIN] Service is running and listening for events.")
    await asyncio.gather(worker_task)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logging.info("[MAIN] Service stopped by user.")