"""
config.py — Chargement de la configuration depuis le fichier .env
"""

import os
import logging
from dotenv import load_dotenv

# Chargement du fichier .env
load_dotenv()

logger = logging.getLogger(__name__)

# --- Réseau ---
NETWORK_RANGE: str = os.getenv("NETWORK_RANGE", "192.168.1.0/24")

# --- Speedtest ---
SPEEDTEST_INTERVAL_MIN: int = int(os.getenv("SPEEDTEST_INTERVAL_MIN", "60"))
ALERT_THRESHOLD_MBPS: float = float(os.getenv("ALERT_THRESHOLD_MBPS", "50.0"))

# --- Base de données ---
DATABASE_PATH: str = os.getenv("DATABASE_PATH", "homenet.db")

# --- API NVD NIST ---
NVD_API_BASE: str = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY: str = os.getenv("NVD_API_KEY", "")  # Optionnel, améliore le rate-limit

# --- Serveur ---
HOST: str = os.getenv("HOST", "0.0.0.0")
PORT: int = int(os.getenv("PORT", "8000"))

logger.info(
    "Configuration chargée — réseau : %s, seuil alerte : %s Mbps",
    NETWORK_RANGE,
    ALERT_THRESHOLD_MBPS,
)
