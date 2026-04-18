import os
import httpx

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

PFSENSE_URL = os.getenv("PFSENSE_URL")
API_KEY = os.getenv("PFSENSE_RESTAPI_KEY")

if not PFSENSE_URL or not API_KEY:
    raise ValueError("Не заданы PFSENSE_URL или PFSENSE_RESTAPI_KEY в окружении!")

def fetch_pfense_aliases():
    headers = {
        "X-API-Key": API_KEY,
        "Accept": "application/json"
    }
    with httpx.Client(base_url=PFSENSE_URL, headers=headers, verify=False) as client:
        response_all = client.get("/api/v2/firewall/aliases?type=host")
        response_all.raise_for_status() 
        all_aliases = {alias["name"]: alias["address"] for alias in response_all.json().get("data", [])}
    return all_aliases
if __name__ == "__main__":
    print(fetch_pfense_aliases())