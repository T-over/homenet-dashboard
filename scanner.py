"""
scanner.py – Scan réseau avec python-nmap, lookup fabricant MAC,
scan de ports, et historique ping par appareil.
"""
import asyncio
import logging
from mac_vendor_lookup import AsyncMacLookup
import nmap

from config import NETWORK_RANGE
from database import upsert_device, set_device_offline, create_alert, save_device_ping
logger = logging.getLogger(__name__)

_nm = nmap.PortScanner()
_mac_lookup = AsyncMacLookup()


async def _lookup_vendor(mac: str) -> str:
    """Retourne le fabricant d'après l'adresse MAC."""
    if not mac:
        return "Inconnu"
    try:
        vendor = await _mac_lookup.lookup(mac)
        return vendor or "Inconnu"
    except Exception:
        return "Inconnu"


def _run_nmap_scan(network_range: str) -> list:
    """Exécute le scan nmap en mode ping (-sn) de façon synchrone."""
    logger.info("Lancement du scan nmap sur %s", network_range)
    _nm.scan(hosts=network_range, arguments="-sn --host-timeout 10s")
    return _nm.all_hosts()


async def scan_network() -> int:
    """
    Scan principal du réseau.
    - Détecte les appareils en ligne
    - Met à jour la base de données
    - Génère des alertes pour les nouveaux appareils
    - Sauvegarde l'historique ping
    Retourne le nombre d'appareils détectés.
    """
    try:
        loop = asyncio.get_event_loop()
        hosts = await loop.run_in_executor(None, _run_nmap_scan, NETWORK_RANGE)
        logger.info("%d appareil(s) détecté(s)", len(hosts))

        active_ips = []

        for host in hosts:
            try:
                host_info = _nm[host]
                mac = ""
                hostname = ""
                vendor = "Inconnu"

                # Récupération MAC et hostname
                if "mac" in host_info.get("addresses", {}):
                    mac = host_info["addresses"]["mac"]
                if host_info.hostname():
                    hostname = host_info.hostname()

                # Lookup fabricant
                if mac:
                    vendor = await _lookup_vendor(mac)

                # Upsert en base
                is_new = await upsert_device(
                    ip=host,
                    mac=mac,
                    hostname=hostname,
                    vendor=vendor,
                    is_online=True
                )

                # Alerte si nouvel appareil
                if is_new:
                    msg = f"Nouvel appareil détecté : {host} ({vendor or hostname or 'inconnu'})"
                    await add_alert("high", msg)
                    logger.warning(msg)

                # Historique ping
                await save_device_ping(host, True, None)
                active_ips.append(host)

            except Exception as e:
                logger.error("Erreur traitement host %s: %s", host, e)

        # Marquer hors ligne les absents
        await set_device_offline(active_ips)

        # Historique ping offline pour les absents
        from database import get_all_devices
        all_devices = await get_all_devices()
        for device in all_devices:
            if device["ip"] not in active_ips:
                await save_device_ping(device["ip"], False, None)

        logger.info("Scan terminé : %d actifs", len(active_ips))
        return len(active_ips)

    except Exception as e:
        logger.error("Erreur scan_network: %s", e)
        return 0


def _run_port_scan(ip: str) -> dict:
    """Exécute un scan de ports nmap (-sV) sur une IP. Synchrone."""
    logger.info("Scan de ports sur %s", ip)
    nm_ports = nmap.PortScanner()
    nm_ports.scan(
        hosts=ip,
        arguments="-sV -T4 --top-ports 1000 --host-timeout 60s"
    )
    return nm_ports


async def scan_ports(ip: str) -> list:
    """
    Scan de ports sur une IP cible.
    Retourne une liste de ports ouverts avec service et version.
    """
    try:
        loop = asyncio.get_event_loop()
        nm_result = await loop.run_in_executor(None, _run_port_scan, ip)

        ports = []
        if ip not in nm_result.all_hosts():
            logger.warning("Hôte %s non joignable pour scan de ports", ip)
            return ports

        host_data = nm_result[ip]
        for proto in host_data.all_protocols():
            port_list = host_data[proto].keys()
            for port in sorted(port_list):
                port_data = host_data[proto][port]
                if port_data["state"] == "open":
                    ports.append({
                        "port": port,
                        "protocol": proto,
                        "state": port_data["state"],
                        "service": port_data.get("name", ""),
                        "version": port_data.get("version", ""),
                        "product": port_data.get("product", ""),
                    })

        logger.info("%d port(s) ouvert(s) sur %s", len(ports), ip)
        return ports

    except Exception as e:
        logger.error("Erreur scan_ports %s: %s", ip, e)
        return []
