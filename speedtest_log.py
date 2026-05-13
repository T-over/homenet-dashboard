"""
speedtest_log.py — Mesure de débit avec speedtest-cli + sauvegarde SQLite
"""

import asyncio
import logging
import speedtest as st_lib

from config import ALERT_THRESHOLD_MBPS
from database import save_speedtest, add_alert

logger = logging.getLogger(__name__)


def _run_speedtest() -> dict:
    logger.info("Lancement du speedtest...")
    try:
        s = st_lib.Speedtest()
        s.get_best_server()
        s.download(threads=4)
        s.upload(threads=4)
        results = s.results.dict()
        return {
            "ping_ms": results.get("ping", 0.0),
            "download_mbps": results.get("download", 0) / 1_000_000,
            "upload_mbps": results.get("upload", 0) / 1_000_000,
        }
    except Exception as exc:
        logger.error("Erreur speedtest : %s", exc)
        raise


async def run_speedtest() -> dict:
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(None, _run_speedtest)

    await save_speedtest(
        ping_ms=result["ping_ms"],
        download_mbps=result["download_mbps"],
        upload_mbps=result["upload_mbps"],
    )

    logger.info(
        "Speedtest OK — Ping : %.0f ms | Down : %.1f Mbps | Up : %.1f Mbps",
        result["ping_ms"], result["download_mbps"], result["upload_mbps"],
    )

    if result["download_mbps"] < ALERT_THRESHOLD_MBPS:
        await add_alert(
            level="high",
            message=(
                f"Débit descendant critique : {result['download_mbps']:.1f} Mbps "
                f"(seuil : {ALERT_THRESHOLD_MBPS} Mbps)"
            ),
        )

    return result
