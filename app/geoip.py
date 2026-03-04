import requests
from app.config import GEOIP_API

def lookup(ip):
    try:
        response = requests.get(GEOIP_API + ip, timeout=3)
        data = response.json()

        return {
            "country": data.get("country"),
            "city": data.get("city"),
            "isp": data.get("isp")
        }
    except:
        return None
