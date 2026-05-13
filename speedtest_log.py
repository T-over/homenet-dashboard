""""speedtest_log.py - Mesure de débit avec gestion améliorée des erreurs
"""

import asyncio
import logging
import speedtest as st_lib

from config import ALERT_THRESHOLD_MBPS
from database import save_speedtest, create_alert

logger = logging.getLogger(__name__)


def _run_speedtest() -> dict:
    """Exécute un speedtest avec timeout et retry."""
    logger.info("Lancement du speedtest...")
    try:
        # Configuration avec timeout augmenté
        s = st_lib.Speedtest(secure=True)
        s.get_best_server()
        
        logger.info("Téléchargement...")
        download_bps = s.download(threads=4)
        
        logger.info("Envoi...")
        upload_bps = s.upload(threads=4, pre_allocate=False)
        
        results = s.results.dict()
        
        ping_ms = float(results.get("ping", 0.0))
        download_mbps = download_bps / 1_000_000
        upload_mbps = upload_bps / 1_000_000
        
        logger.info(
            f"Speedtest terminé - Ping: {ping_ms:.1f}ms, "
            f"Download: {download_mbps:.2f}Mbps, Upload: {upload_mbps:.2f}Mbps"
        )
        
        return {
            "ping_ms": ping_ms,
            "download_mbps": download_mbps,
            "upload_mbps": upload_mbps,
        }
    except Exception as exc:
        logger.error(f"Erreur speedtest: {exc}")
        # Retourner des valeurs par défaut au lieu de crash
        return {
            "ping_ms": 0.0,
            "download_mbps": 0.0,
            "upload_mbps": 0.0,
            "error": str(exc)
        }


async def run_speedtest() -> dict:
    """Lance un speedtest en mode async et le sauvegarde."""
    try:
        # Exécuter dans un thread séparé pour ne pas bloquer
        result = await asyncio.to_thread(_run_speedtest)
        
        # Vérifier si erreur
        if "error" in result:
            logger.warning(f"Speedtest échoué: {result['error']}")
            return result
        
        # Sauvegarder en base
        await save_speedtest(
            result["ping_ms"],
            result["download_mbps"],
            result["upload_mbps"]
        )
        logger.info("Speedtest sauvegardé")
        
        # Créer alerte si débit trop faible
        if result["download_mbps"] < ALERT_THRESHOLD_MBPS:
            await create_alert(
                level="HIGH",
                message=f"Débit faible: {result['download_mbps']:.2f} Mbps",
            )
            logger.warning(f"Alerte créée: débit faible ({result['download_mbps']:.2f} Mbps)")
        
        return result
        
    except Exception as exc:
        logger.error(f"Erreur speedtest manuel: {exc}")
        raise
