import re
import socket
from datetime import datetime
from typing import Optional, Dict, Any, List
import aiohttp
import asyncio

from fastapi import FastAPI, Request, Query
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, JSONResponse
from ipwhois import IPWhois
from ipwhois.exceptions import IPDefinedError, ASNRegistryError, HTTPLookupError

app = FastAPI(
    title="Exploit.Net",
    description="Проверка IP, генерация Google Dorks и OSINT-инструменты",
    version="1.0",
)

app.mount("/static", StaticFiles(directory="static"), name="static")
templates = Jinja2Templates(directory="templates")

# Простая проверка формата IPv4 / IPv6
IPV4_PATTERN = re.compile(
    r"^(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d{2}|[1-9]?\d)){3}$"
)


def is_valid_ip(ip: str) -> bool:
    if IPV4_PATTERN.match(ip):
        return True
    try:
        socket.inet_pton(socket.AF_INET6, ip)
        return True
    except OSError:
        return False


def get_client_ip(request: Request) -> str:
    """Пытаемся вытащить реальный IP клиента с учётом прокси."""
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get("x-real-ip")
    if real_ip:
        return real_ip
    return request.client.host if request.client else "127.0.0.1"


def is_private_ip(ip: str) -> bool:
    private_prefixes = ("10.", "127.", "192.168.", "169.254.")
    if ip.startswith(private_prefixes):
        return True
    if ip.startswith("172."):
        try:
            second = int(ip.split(".")[1])
            if 16 <= second <= 31:
                return True
        except (IndexError, ValueError):
            pass
    return ip in ("::1", "localhost")


def get_ip_version(ip: str) -> str:
    """Определяет версию IP-адреса."""
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return "IPv4"
    except OSError:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return "IPv6"
        except OSError:
            return "Unknown"


def get_ip_type(ip: str) -> str:
    """Определяет тип IP-адреса (публичный/приватный/другой)."""
    if is_private_ip(ip):
        return "Приватный"
    if ip in ("0.0.0.0", "255.255.255.255"):
        return "Специальный"
    return "Публичный"


def format_asn_description(asn_desc: Optional[str]) -> str:
    """Форматирует описание ASN."""
    if not asn_desc:
        return "Не указано"
    # Разбиваем описание на части
    parts = asn_desc.split(", ")
    if len(parts) >= 2:
        return f"{parts[0]} - {', '.join(parts[1:])}"
    return asn_desc


def get_asn_info(asn: Optional[str]) -> Dict[str, Any]:
    """Возвращает информацию об ASN."""
    if not asn:
        return {}
    
    # Словарь с популярными ASN для примера
    asn_info = {
        "AS15169": {"name": "Google LLC", "type": "Content", "country": "US"},
        "AS16509": {"name": "Amazon.com, Inc.", "type": "Hosting", "country": "US"},
        "AS8075": {"name": "Microsoft Corporation", "type": "Hosting", "country": "US"},
        "AS13335": {"name": "Cloudflare, Inc.", "type": "CDN", "country": "US"},
        "AS32934": {"name": "Facebook, Inc.", "type": "Content", "country": "US"},
        "AS7922": {"name": "Comcast Cable", "type": "ISP", "country": "US"},
        "AS7018": {"name": "AT&T Services, Inc.", "type": "ISP", "country": "US"},
        "AS3356": {"name": "Level 3 Communications", "type": "ISP", "country": "US"},
        "AS12389": {"name": "Rostelecom", "type": "ISP", "country": "RU"},
        "AS8374": {"name": "JSC ER-Telecom Holding", "type": "ISP", "country": "RU"},
        "AS25532": {"name": "LLC VK", "type": "Content", "country": "RU"},
        "AS20485": {"name": "TransTeleCom", "type": "ISP", "country": "RU"},
        "AS8982": {"name": "MTS PJSC", "type": "ISP", "country": "RU"},
        "AS12306": {"name": "PJSC Vimpelcom", "type": "ISP", "country": "RU"},
        "AS3255": {"name": "NetAssist LLC", "type": "Hosting", "country": "UA"},
        "AS3326": {"name": "Ukrainian Telecommunication Group", "type": "ISP", "country": "UA"},
        "AS56665": {"name": "Tier 3 Data Center", "type": "Hosting", "country": "UA"},
    }
    
    return asn_info.get(asn, {})


def extract_detailed_info(result: Dict[str, Any]) -> Dict[str, Any]:
    """Извлекает детальную информацию из результата RDAP."""
    network = result.get("network") or {}
    detailed = {}
    
    # Детали сети
    detailed["network_details"] = {
        "name": network.get("name", "Не указано"),
        "handle": network.get("handle", "Не указан"),
        "cidr": network.get("cidr", "Не указан"),
        "start_address": network.get("start_address", "Не указан"),
        "end_address": network.get("end_address", "Не указан"),
        "country": network.get("country", "Не указан"),
        "type": network.get("type", "Не указан"),
        "parent_handle": network.get("parent_handle", "Не указан"),
        "registration_date": network.get("registration_date", "Не указана"),
        "last_changed": network.get("last_changed", "Не указана"),
        "remarks": network.get("remarks", ""),
    }
    
    # Контакты организаций
    contacts = []
    objects = result.get("objects") or {}
    
    for entity_key, entity_data in objects.items():
        contact = entity_data.get("contact") or {}
        roles = entity_data.get("roles", [])
        
        if contact.get("name") or contact.get("email"):
            contact_info = {
                "handle": entity_key,
                "name": contact.get("name", "Не указан"),
                "kind": contact.get("kind", "Не указан"),
                "role": ", ".join(roles) if roles else "Не указана",
                "email": [e.get("value") for e in (contact.get("email") or []) if e.get("value")],
                "phone": [p.get("value") for p in (contact.get("phone") or []) if p.get("value")],
                "address": [a.get("value") for a in (contact.get("address") or []) if a.get("value")],
            }
            contacts.append(contact_info)
    
    detailed["contacts"] = contacts
    
    # Подробности о ASN
    asn_country = result.get("asn_country_code", "Не указан")
    asn_registry = result.get("asn_registry", "Не указан")
    asn_cidr = result.get("asn_cidr", "Не указан")
    
    asn_info = get_asn_info(result.get("asn", ""))
    
    detailed["asn_details"] = {
        "number": result.get("asn", "Не указан"),
        "organization": asn_info.get("name", "Неизвестная организация"),
        "type": asn_info.get("type", "Не указан"),
        "description": format_asn_description(result.get("asn_description", "")),
        "country": asn_country,
        "registry": asn_registry,
        "cidr": asn_cidr,
        "date": result.get("asn_date", "Не указана"),
    }
    
    # Информация о стране (геолокация)
    detailed["geo_info"] = {
        "country_code": asn_country,
        "country_name": get_country_name(asn_country) if asn_country != "Не указан" else "Неизвестно",
        "registry": asn_registry,
    }
    
    return detailed


def get_country_name(code: str) -> str:
    """Возвращает название страны по коду."""
    countries = {
        "RU": "Россия",
        "US": "США",
        "UA": "Украина",
        "BY": "Беларусь",
        "KZ": "Казахстан",
        "DE": "Германия",
        "FR": "Франция",
        "GB": "Великобритания",
        "CN": "Китай",
        "JP": "Япония",
        "IN": "Индия",
        "BR": "Бразилия",
        "CA": "Канада",
        "AU": "Австралия",
        "NL": "Нидерланды",
        "SE": "Швеция",
        "CH": "Швейцария",
        "IT": "Италия",
        "ES": "Испания",
        "PL": "Польша",
        "FI": "Финляндия",
        "NO": "Норвегия",
        "DK": "Дания",
        "BE": "Бельгия",
        "AT": "Австрия",
        "CZ": "Чехия",
        "HU": "Венгрия",
        "RO": "Румыния",
        "BG": "Болгария",
        "GR": "Греция",
        "PT": "Португалия",
        "IE": "Ирландия",
        "NZ": "Новая Зеландия",
        "SG": "Сингапур",
        "HK": "Гонконг",
        "TW": "Тайвань",
        "KR": "Южная Корея",
        "IL": "Израиль",
        "AE": "ОАЭ",
        "SA": "Саудовская Аравия",
        "TR": "Турция",
        "EG": "Египет",
        "ZA": "Южная Африка",
        "AR": "Аргентина",
        "MX": "Мексика",
    }
    return countries.get(code, code)


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    client_ip = get_client_ip(request)
    return templates.TemplateResponse(
        request, "index.html", {"client_ip": client_ip}
    )


@app.get("/api/myip")
async def my_ip(request: Request):
    ip = get_client_ip(request)
    return {
        "ip": ip,
        "version": get_ip_version(ip),
        "type": get_ip_type(ip),
        "is_private": is_private_ip(ip),
        "is_valid": is_valid_ip(ip),
    }


@app.get("/api/whois")
async def whois_lookup(ip: str = Query(..., description="IP-адрес для проверки")):
    ip = ip.strip()

    if not is_valid_ip(ip):
        return JSONResponse(
            {"error": "Некорректный формат IP-адреса"}, status_code=400
        )

    if is_private_ip(ip):
        return JSONResponse(
            {"error": "Это приватный/локальный адрес — публичных WHOIS-данных по нему нет"},
            status_code=400,
        )

    try:
        obj = IPWhois(ip)
        result = obj.lookup_rdap(depth=1, rate_limit_timeout=15)

        network = result.get("network") or {}
        
        # Извлекаем детальную информацию
        detailed_info = extract_detailed_info(result)
        
        # Основная информация
        base_data = {
            "ip": ip,
            "ip_version": get_ip_version(ip),
            "ip_type": get_ip_type(ip),
            "queried_at": datetime.utcnow().isoformat() + "Z",
            "asn": result.get("asn"),
            "asn_cidr": result.get("asn_cidr"),
            "asn_country_code": result.get("asn_country_code"),
            "asn_description": result.get("asn_description"),
            "asn_date": result.get("asn_date"),
            "asn_registry": result.get("asn_registry"),
            "network": network,
            "entities": result.get("entities", []),
        }
        
        # Объединяем с детальной информацией
        response_data = {
            **base_data,
            "detailed": detailed_info,
            "summary": {
                "organization": detailed_info["asn_details"].get("organization", "Неизвестно"),
                "country": detailed_info["geo_info"].get("country_name", "Неизвестно"),
                "asn": detailed_info["asn_details"].get("number", "Не указан"),
                "network_name": detailed_info["network_details"].get("name", "Не указано"),
                "network_cidr": detailed_info["network_details"].get("cidr", "Не указан"),
                "contacts_count": len(detailed_info["contacts"]),
            }
        }
        
        return response_data

    except IPDefinedError:
        return JSONResponse(
            {"error": "Адрес зарезервирован (RFC 1918 / специального назначения)"},
            status_code=400,
        )
    except ASNRegistryError:
        return JSONResponse(
            {"error": "Не удалось определить региональный регистратор (RIR) для этого адреса"},
            status_code=502,
        )
    except HTTPLookupError:
        return JSONResponse(
            {"error": "RDAP-сервер недоступен, попробуйте позже"}, status_code=502
        )
    except Exception as e:  # noqa: BLE001
        return JSONResponse({"error": f"Ошибка при запросе: {e}"}, status_code=500)

    import aiohttp
import asyncio

async def get_geo_ip(ip: str) -> Dict[str, Any]:
    """Получает геолокацию через ip-api.com"""
    try:
        async with aiohttp.ClientSession() as session:
            url = f"http://ip-api.com/json/{ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,query"
            async with session.get(url, timeout=5) as response:
                data = await response.json()
                if data.get("status") == "success":
                    return {
                        "country": data.get("country", "Неизвестно"),
                        "country_code": data.get("countryCode", "N/A"),
                        "region": data.get("regionName", "Неизвестно"),
                        "city": data.get("city", "Неизвестно"),
                        "zip": data.get("zip", "N/A"),
                        "latitude": data.get("lat"),
                        "longitude": data.get("lon"),
                        "timezone": data.get("timezone", "N/A"),
                        "isp": data.get("isp", "Неизвестно"),
                        "org": data.get("org", "Неизвестно"),
                        "as": data.get("as", "Неизвестно"),
                    }
    except Exception:
        pass
    return {}



if __name__ == "__main__":
    import uvicorn

    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)