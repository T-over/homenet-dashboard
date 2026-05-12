"""
main.py — Serveur FastAPI principal avec routes API et scheduler APScheduler
"""

import logging
import sys
from contextlib import asynccontextmanager

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from config import SPEEDTEST_INTERVAL_MIN
from database import init_db, get_all_devices, get_speedtest_history, get_alerts
from scanner import scan_network
from speedtest_log import run_speedtest
from cve_checker import check_cve

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("homenet.log", encoding="utf-8"),
    ],
)
logger = logging.getLogger(__name__)

scheduler = AsyncIOScheduler(timezone="Europe/Paris")


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Démarrage de HomeNet Dashboard...")
    await init_db()
    try:
        await scan_network()
    except Exception as exc:
        logger.error("Erreur lors du scan initial : %s", exc)
    scheduler.add_job(scan_network, "interval", minutes=5, id="network_scan")
    scheduler.add_job(run_speedtest, "interval", minutes=SPEEDTEST_INTERVAL_MIN, id="speedtest")
    scheduler.start()
    logger.info("Scheduler démarré (scan réseau: 5 min, speedtest: %d min)", SPEEDTEST_INTERVAL_MIN)
    yield
    scheduler.shutdown()
    logger.info("HomeNet Dashboard arrêté.")


app = FastAPI(
    title="HomeNet Dashboard API",
    version="1.0.0",
    description="API locale de supervision réseau domestique",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory="frontend"), name="static")


@app.get("/")
async def serve_frontend():
    return FileResponse("frontend/index.html")


@app.get("/api/devices")
async def api_devices():
    try:
        devices = await get_all_devices()
        return {"devices": devices, "online_count": sum(1 for d in devices if d["is_online"]), "total_count": len(devices)}
    except Exception as exc:
        logger.error("Erreur /api/devices : %s", exc)
        raise HTTPException(status_code=500, detail="Erreur lors de la récupération des appareils.")


@app.get("/api/speedtest")
async def api_speedtest_history(limit: int = 24):
    try:
        history = await get_speedtest_history(limit=limit)
        return {"history": history, "count": len(history)}
    except Exception as exc:
        logger.error("Erreur /api/speedtest : %s", exc)
        raise HTTPException(status_code=500, detail="Erreur historique speedtest.")


@app.post("/api/speedtest/run")
async def api_speedtest_run():
    try:
        result = await run_speedtest()
        return {"status": "success", "result": result}
    except Exception as exc:
        logger.error("Erreur /api/speedtest/run : %s", exc)
        raise HTTPException(status_code=500, detail=f"Erreur speedtest : {exc}")


@app.get("/api/cve/{hostname}")
async def api_cve_scan(hostname: str):
    if not hostname or len(hostname) > 255:
        raise HTTPException(status_code=400, detail="Hostname invalide.")
    try:
        return await check_cve(hostname)
    except Exception as exc:
        logger.error("Erreur /api/cve/%s : %s", hostname, exc)
        raise HTTPException(status_code=500, detail=f"Erreur scan CVE : {exc}")


@app.get("/api/alerts")
async def api_alerts(limit: int = 50):
    try:
        alerts = await get_alerts(limit=limit)
        return {"alerts": alerts, "count": len(alerts)}
    except Exception as exc:
        logger.error("Erreur /api/alerts : %s", exc)
        raise HTTPException(status_code=500, detail="Erreur alertes.")


@app.get("/api/health")
async def api_health():
    return {"status": "ok", "version": "1.0.0"}


if __name__ == "__main__":
    import uvicorn
    from config import HOST, PORT
    uvicorn.run("main:app", host=HOST, port=PORT, reload=False, log_level="info")
