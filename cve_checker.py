"""
cve_checker.py — Détection des services sur une cible + recherche CVE via NIST NVD
"""

import asyncio
import logging
from database import save_cve_result
import httpx
import nmap

from config import NVD_API_BASE, NVD_API_KEY

logger = logging.getLogger(__name__)
_nm = nmap.PortScanner()


def _run_service_scan(target: str) -> dict:
    logger.info("Scan de services sur %s", target)
    try:
        _nm.scan(hosts=target, arguments="-sV -O --top-ports 1000 --host-timeout 60s --open")
        return _nm[target] if target in _nm.all_hosts() else {}
    except Exception as exc:
        logger.error("Erreur scan service sur %s : %s", target, exc)
        return {}


def _extract_cpe_keywords(host_data: dict) -> list[str]:
    keywords: list[str] = []
    for proto in ("tcp", "udp"):
        if proto not in host_data:
            continue
        for port, info in host_data[proto].items():
            product = info.get("product", "").strip()
            version = info.get("version", "").strip()
            if product:
                kw = product + (f" {version}" if version else "")
                keywords.append(kw)
    if "osmatch" in host_data:
        for osmatch in host_data["osmatch"][:2]:
            os_name = osmatch.get("name", "").strip()
            if os_name:
                keywords.append(os_name)
    return list(set(keywords))


async def _query_nvd(keyword: str, client: httpx.AsyncClient) -> list[dict]:
    params = {"keywordSearch": keyword, "resultsPerPage": 10, "startIndex": 0}
    headers = {"apiKey": NVD_API_KEY} if NVD_API_KEY else {}
    try:
        response = await client.get(NVD_API_BASE, params=params, headers=headers, timeout=15.0)
        response.raise_for_status()
        data = response.json()
    except Exception as exc:
        logger.error("Erreur requête NVD (%s) : %s", keyword, exc)
        return []

    cves: list[dict] = []
    for item in data.get("vulnerabilities", []):
        cve_data = item.get("cve", {})
        cve_id = cve_data.get("id", "N/A")
        descriptions = cve_data.get("descriptions", [])
        description = next((d["value"] for d in descriptions if d.get("lang") == "en"), "N/A")
        cvss_score, severity = None, "unknown"
        for v in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = cve_data.get("metrics", {}).get(v, [])
            if entries:
                cvss_data = entries[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                severity = cvss_data.get("baseSeverity", "unknown").lower()
                break
        if cvss_score is not None:
            if cvss_score >= 9.0: severity = "critical"
            elif cvss_score >= 7.0: severity = "high"
            elif cvss_score >= 4.0: severity = "medium"
            else: severity = "low"
        cves.append({
            "cve_id": cve_id,
            "description": description[:300] + ("..." if len(description) > 300 else ""),
            "cvss_score": cvss_score,
            "severity": severity,
            "service_keyword": keyword,
        })
    return cves


async def check_cve(hostname: str) -> dict:
    loop = asyncio.get_event_loop()
    host_data = await loop.run_in_executor(None, _run_service_scan, hostname)
    if not host_data:
        return {"target": hostname, "services_detected": [], "cves": [],
                "error": f"Hôte {hostname} inaccessible ou aucun service détecté."}

    keywords = _extract_cpe_keywords(host_data)
    all_cves: list[dict] = []
    seen_ids: set[str] = set()

    async with httpx.AsyncClient() as client:
        results = await asyncio.gather(*[_query_nvd(kw, client) for kw in keywords[:10]], return_exceptions=True)

    for result in results:
        if isinstance(result, list):
            for cve in result:
                if cve["cve_id"] not in seen_ids:
                    all_cves.append(cve)
                    seen_ids.add(cve["cve_id"])

    all_cves.sort(key=lambda c: c.get("cvss_score") or 0, reverse=True)
    return {
        "target": hostname,
        "services_detected": keywords,
        "cves": all_cves,
        "critical_count": sum(1 for c in all_cves if c["severity"] == "critical"),
        "high_count": sum(1 for c in all_cves if c["severity"] == "high"),
    }
