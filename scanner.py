"""
scanner.py — Scan réseau avec python-nmap et lookup fabricant MAC (OUI)
"""

import asyncio
import logging
from mac_vendor_lookup import AsyncMacLookup
import nmap

from config import NETWORK_RANGE
from database import upsert_device, mark_devices_offline, create_alert

logger = logging.getLogger(__name__)

_nm = nmap.PortScanner()
_mac_lookup = AsyncMacLookup()


async def _lookup_vendor(mac: str) -> str:
    """Retourne le fabricant d'une adresse MAC, ou 'Inconnu' si introuvable."""
    if not mac:
        return "Inconnu"
    try:
        vendor = await _mac_lookup.lookup(mac)
        return vendor or "Inconnu"
    except Exception:
        return "Inconnu"


def _run_nmap_scan(network_range: str) -> list:
    """Exécute nmap de façon synchrone (bloquante)."""
    logger.info("Lancement du scan nmap sur %s", network_range)
    try:
        _nm.scan(hosts=network_range, arguments="-sn --host-timeout 10s")
        return _nm.all_hosts()
    except Exception as exc:
        logger.error("Erreur nmap : %s", exc)
        return []


async def scan_network() -> list[dict]:
    """
    Scanne le réseau, met à jour la BDD, génère des alertes.
    Retourne la liste des appareils détectés.
    """
    loop = asyncio.get_event_loop()
    hosts = await loop.run_in_executor(None, _run_nmap_scan, NETWORK_RANGE)

    active_ips: list[str] = []
    results: list[dict] = []

    for host in hosts:
        ip = host
        try:
            host_data = _nm[host]
        except KeyError:
            continue

        hostname = host_data.hostname() or ip
        addresses = host_data.get("addresses", {})
        mac = addresses.get("mac", "")
        vendor = await _lookup_vendor(mac)

        upsert_result = await upsert_device(ip, mac, hostname, vendor)
        active_ips.append(ip)

        if upsert_result["is_new"]:
            await create_alert(
                level="high",
                category="new_device",
                message=f"Nouvel appareil détecté sur le réseau : {ip} ({hostname}) — Fabricant : {vendor}",
            )

        results.append({
            "ip": ip,
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "is_online": True,
            "is_new": upsert_result["is_new"],
        })

    offline_ips = await mark_devices_offline(active_ips)
    for ip in offline_ips:
        await create_alert(
            level="medium",
            category="offline_device",
            message=f"L'appareil {ip} n'est plus joignable sur le réseau.",
        )

    logger.info("Scan terminé : %d actifs, %d passés offline", len(active_ips), len(offline_ips))
    return results
