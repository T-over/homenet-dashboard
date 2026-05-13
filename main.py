"""
main.py – Serveur FastAPI principal avec toutes les routes API enrichies
"""
import logging
import sys
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel
import io
import csv

from config import SPEEDTEST_INTERVAL_MIN, HOST, PORT
from database import (
    get_cve_results, get_all_cve_summary, save_cve_result,
    init_db, get_all_devices, get_speedtest_history, get_alerts,
    update_device_alias, get_device_ping_history, get_bandwidth_heatmap,
    get_port_scan_results, save_port_scan
)
from scanner import scan_network, scan_ports
from speedtest_log import run_speedtest
from cve_checker import check_cve

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("homenet.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------
scheduler = AsyncIOScheduler()

# ────────────────────────────────────────────────────────────────────────────────
# Tâche automatique : Scan CVE sur tous les appareils
# ────────────────────────────────────────────────────────────────────────────────

async def scan_all_cves():
    """Scan CVE automatique pour tous les appareils du réseau."""
    try:
        logger.info("Démarrage du scan CVE automatique pour tous les appareils...")
        devices = await get_all_devices()
        
        if not devices:
            logger.warning("Aucun appareil trouvé pour le scan CVE.")
            return
        
        cve_count = 0
        for device in devices:
            hostname = device.get("hostname", "Inconnu")
            try:
                logger.info(f"Scan CVE pour {hostname}...")
                cves = await check_cve(hostname)
                if cves:
                    cve_count += len(cves)
                    logger.info(f"  → {len(cves)} CVE(s) trouvées pour {hostname}")
            except Exception as e:
                logger.error(f"Erreur scan CVE pour {hostname}: {e}")
        
        logger.info(f"Scan CVE automatique terminé. Total: {cve_count} CVE(s) trouvées.")
    except Exception as e:
        logger.error(f"Erreur globale scan CVE automatique: {e}")

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Initialise la DB et démarre le scheduler au lancement."""
    logger.info("Démarrage de HomeNet Dashboard...")
    await init_db()
    scheduler.add_job(scan_network, "interval", minutes=5, id="scan_reseau")
    scheduler.add_job(run_speedtest, "interval", minutes=SPEEDTEST_INTERVAL_MIN, id="speedtest")
    scheduler.add_job(scan_all_cves, "interval", hours=24, id="cve_scan_auto")
    scheduler.start()
    logger.info("Scheduler démarré (scan: 5min, speedtest: %dmin)", SPEEDTEST_INTERVAL_MIN)
    yield
    scheduler.shutdown()
    logger.info("Arrêt du scheduler.")

# ---------------------------------------------------------------------------
# Application FastAPI
# ---------------------------------------------------------------------------
app = FastAPI(title="HomeNet Dashboard", version="2.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Route racine → dashboard
# ---------------------------------------------------------------------------
@app.get("/", include_in_schema=False)
async def root():
    return FileResponse("frontend/index.html")

@app.get("/api/health")
async def health():
    return {"status": "ok", "version": "2.0.0"}

# ---------------------------------------------------------------------------
# Appareils
# ---------------------------------------------------------------------------
@app.get("/api/devices")
async def get_devices():
    """Retourne tous les appareils connus avec leurs infos."""
    try:
        devices = await get_all_devices()
        online = sum(1 for d in devices if d.get("is_online"))
        return {"devices": devices, "online_count": online, "total_count": len(devices)}
    except Exception as e:
        logger.error("Erreur get_devices: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

class AliasPayload(BaseModel):
    alias: str

@app.put("/api/devices/{device_ip}/alias")
async def set_device_alias(device_ip: str, payload: AliasPayload):
    """Met à jour le nom personnalisé d'un appareil."""
    try:
        await update_device_alias(device_ip, payload.alias)
        return {"success": True, "ip": device_ip, "alias": payload.alias}
    except Exception as e:
        logger.error("Erreur alias: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/devices/export")
async def export_devices_csv():
    """Exporte la liste des appareils en CSV."""
    try:
        devices = await get_all_devices()
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["ip","alias","hostname","mac","vendor","is_online","is_new","last_seen"])
        writer.writeheader()
        for d in devices:
            writer.writerow({k: d.get(k, "") for k in ["ip","alias","hostname","mac","vendor","is_online","is_new","last_seen"]})
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=devices.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/devices/{device_ip}/history")
async def device_history(device_ip: str, limit: int = 100):
    """Historique de connexion d'un appareil (ping timeline)."""
    try:
        history = await get_device_ping_history(device_ip, limit)
        return {"ip": device_ip, "history": history}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/devices/{device_ip}/portscan")
async def port_scan(device_ip: str):
    """Lance un scan de ports sur un appareil."""
    try:
        results = await scan_ports(device_ip)
        await save_port_scan(device_ip, results)
        return {"ip": device_ip, "ports": results}
    except Exception as e:
        logger.error("Erreur port scan: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/devices/{device_ip}/ports")
async def get_ports(device_ip: str):
    """Récupère les derniers résultats de scan de ports."""
    try:
        ports = await get_port_scan_results(device_ip)
        return {"ip": device_ip, "ports": ports}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------------
# Speedtest
# ---------------------------------------------------------------------------
@app.get("/api/speedtest")
async def speedtest_history(limit: int = 24):
    """Retourne l'historique des mesures de débit."""
    try:
        history = await get_speedtest_history(limit)
        return {"history": history, "count": len(history)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/api/speedtest/run")
async def trigger_speedtest():
    """Lance manuellement un speedtest."""
    try:
        result = await run_speedtest()
        return {"success": True, "result": result}
    except Exception as e:
        logger.error("Erreur speedtest manuel: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/speedtest/export")
async def export_speedtest_csv():
    """Exporte l'historique speedtest en CSV."""
    try:
        history = await get_speedtest_history(1000)
        output = io.StringIO()
        writer = csv.DictWriter(output, fieldnames=["timestamp","download_mbps","upload_mbps","ping_ms"])
        writer.writeheader()
        for h in history:
            writer.writerow({k: h.get(k, "") for k in ["timestamp","download_mbps","upload_mbps","ping_ms"]})
        output.seek(0)
        return StreamingResponse(
            iter([output.getvalue()]),
            media_type="text/csv",
            headers={"Content-Disposition": "attachment; filename=speedtest_history.csv"}
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/api/speedtest/heatmap")
async def bandwidth_heatmap():
    """Retourne la heatmap débit moyen par heure/jour."""
    try:
        data = await get_bandwidth_heatmap()
        return {"heatmap": data}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------------
# CVE
# ---------------------------------------------------------------------------
@app.get("/api/cve/{hostname}")
async def cve_scan(hostname: str):
    """Lance un scan CVE sur un hostname ou IP."""
    try:
        result = await check_cve(hostname)
        return result
    except Exception as e:
        logger.error("Erreur CVE scan: %s", e)
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------------
# Alertes
# ---------------------------------------------------------------------------
@app.get("/api/alerts")
async def alerts(limit: int = 50):
    """Retourne les alertes actives."""
    try:
        data = await get_alerts(limit)
        return {"alerts": data, "count": len(data)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------------
# Scan manuel
# ---------------------------------------------------------------------------
@app.post("/api/scan/run")
async def trigger_scan():
    """Lance manuellement un scan réseau."""
    try:
        result = await scan_network()
        return {"success": True, "scanned": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

# ---------------------------------------------------------------------------
# Lancement
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False)
