import os
import json
import asyncio
import httpx
import subprocess
import xml.etree.ElementTree as ET
import win32evtlog
import logging

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

DEBUG = os.getenv("DEBUG", "False").lower() in ("true", "1", "yes")

log_level = logging.DEBUG if DEBUG else logging.INFO
logging.basicConfig(
    level=log_level,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.FileHandler("pfsense_sync.log", encoding='utf-8'),
        logging.StreamHandler()
    ]
)

PFSENSE_URL = os.getenv("PFSENSE_URL")
API_KEY = os.getenv("PFSENSE_RESTAPI_KEY")

if not PFSENSE_URL or not API_KEY:
    logging.error("Не заданы PFSENSE_URL или PFSENSE_RESTAPI_KEY в окружении!")
    raise ValueError("Не заданы параметры pfSense!")

CONFIG_PATH = "config.json"

event_queue = asyncio.Queue()
loop = None
config = {}
aliases_cache = {}
user_mapping = {}

def load_config():
    global config
    with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
        config = json.load(f)
    logging.debug(f"Конфигурация загружена. Разрешенные IP: {config.get('ip_list', [])}")

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
        logging.debug(f"В группе {group} найдено {len(users)} пользователей.")
        return users
    except subprocess.CalledProcessError:
        logging.error(f"Ошибка получения пользователей группы {group}")
        return set()

async def update_ad_cache_periodically():
    while True:
        logging.debug("Запуск обновления кэша групп AD...")
        for alias_name, groups in config.get('mapping', {}).items():
            all_users = set()
            for group in groups:
                all_users.update(get_users_in_group(group))
            user_mapping[alias_name] = all_users
            logging.debug(f"Алиас '{alias_name}': закэшировано {len(all_users)} разрешенных юзеров.")
        await asyncio.sleep(600)

async def init_pfsense_state():
    global aliases_cache
    headers = {"X-API-Key": API_KEY, "Accept": "application/json"}
    
    async with httpx.AsyncClient(base_url=PFSENSE_URL, headers=headers, verify=False) as client:
        response = await client.get("/api/v2/firewall/aliases?type=host")
        response.raise_for_status()
        data = response.json().get("data", [])
        
        for alias in data:
            if alias["name"] in config.get("mapping", {}):
                aliases_cache[alias["name"]] = {
                    "id": alias["id"],
                    "address": set(alias.get("address", []))
                }
        logging.info(f"pfSense кэш инициализирован: {list(aliases_cache.keys())}")

async def process_event_worker():
    headers = {"X-API-Key": API_KEY, "Accept": "application/json"}
    
    async with httpx.AsyncClient(base_url=PFSENSE_URL, headers=headers, verify=False) as client:
        while True:
            event = await event_queue.get()
            ip, username = event['ip'], event['username']
            needs_apply = False
            
            logging.debug(f"Воркер проверяет: Юзер '{username}', IP '{ip}'")
            
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
                    action_msg = "добавлен"
                elif not should_be_in_alias and ip in current_ips:
                    current_ips.remove(ip)
                    alias_changed = True
                    action_msg = "удален"
                else:
                    logging.debug(f"Действие не требуется для {username} ({ip}) в алиасе {alias_name}.")
                    
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
                        logging.info(f"[OK] {alias_name}: IP {ip} {action_msg} (Юзер: {username})")
                    except Exception as e:
                        logging.error(f"Ошибка API pfSense при обновлении {alias_name}: {e}")
                        if should_be_in_alias: current_ips.remove(ip)
                        else: current_ips.add(ip)

            if needs_apply:
                try:
                    await client.post("/api/v2/firewall/apply")
                    logging.debug("Изменения применены в pfSense (Apply).")
                except Exception as e:
                    logging.error(f"Ошибка Apply в pfSense: {e}")
            
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

            logging.debug(f"Событие Windows: User='{username}', IP='{ip}'")

            if not username or username.endswith("$"):
                logging.debug(f"[SKIP] {username} системная учетка")
                return
            
            if not ip or ip in ("-", "127.0.0.1", "::1"):
                logging.debug(f"[SKIP] IP бесполезный: {ip}")
                return
            
            allowed_ips = [str(i).strip() for i in config.get("ip_list", [])]
            if allowed_ips and ip not in allowed_ips:
                logging.debug(f"[SKIP] IP {ip} не в белом списке")
                return

            logging.debug(f"ПРОШЛО ФИЛЬТР: {username} на {ip}. Отправляем в очередь...")
            
            loop.call_soon_threadsafe(event_queue.put_nowait, {
                "ip": ip, 
                "username": username.lower()
            })

        except Exception as e:
            logging.error(f"Ошибка в коллбэке события: {e}")

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
    
    logging.info("=== Запуск службы интеграции AD -> pfSense ===")
    load_config()
    await init_pfsense_state()
    
    logging.info("Настройка подписки на Windows Events...")
    sub = start_windows_subscription() 
    
    logging.info("Запуск фоновых задач...")
    asyncio.create_task(update_ad_cache_periodically())
    worker_task = asyncio.create_task(process_event_worker())
    
    logging.info("Служба успешно запущена и ожидает события.")
    await asyncio.gather(worker_task)

if __name__ == "__main__":
    asyncio.run(main())