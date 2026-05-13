"""
database.py - Gestion de la base de données SQLite
Tables : devices, speedtest_history, alerts, cve_results, device_ping_history, port_scans
"""

import logging
import json
import aiosqlite
from datetime import datetime
from config import DATABASE_PATH

logger = logging.getLogger(__name__)


async def init_db() -> None:
    """Crée les tables si elles n'existent pas encore."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        # Table appareils
        await db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip              TEXT NOT NULL UNIQUE,
                alias           TEXT,
                mac             TEXT,
                hostname        TEXT,
                vendor          TEXT,
                is_online       INTEGER NOT NULL DEFAULT 1,
                is_new          INTEGER NOT NULL DEFAULT 1,
                first_seen      TEXT NOT NULL,
                last_seen       TEXT NOT NULL
            )
        """)
        
        # Ajout colonne alias si elle n'existe pas encore
        try:
            await db.execute("ALTER TABLE devices ADD COLUMN alias TEXT")
        except Exception:
            pass
        
        # Table historique speedtest
        await db.execute("""
            CREATE TABLE IF NOT EXISTS speedtest_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                download_mbps   REAL,
                upload_mbps     REAL,
                ping_ms         REAL
            )
        """)
        
        # Table alertes
        await db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       TEXT NOT NULL,
                level           TEXT NOT NULL,
                message         TEXT NOT NULL,
                resolved        INTEGER NOT NULL DEFAULT 0
            )
        """)
        
        # Table CVE
        await db.execute("""
            CREATE TABLE IF NOT EXISTS cve_results (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                device_ip       TEXT NOT NULL,
                hostname        TEXT NOT NULL,
                cve_id          TEXT NOT NULL,
                description     TEXT,
                severity        TEXT,
                cvss_score      REAL,
                scan_timestamp  TEXT NOT NULL,
                resolved        INTEGER NOT NULL DEFAULT 0
            )
        """)
        
        # Table historique ping par appareil
        await db.execute("""
            CREATE TABLE IF NOT EXISTS device_ping_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip              TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                is_online       INTEGER NOT NULL,
                ping_ms         REAL
            )
        """)
        
        # Table scan de ports
        await db.execute("""
            CREATE TABLE IF NOT EXISTS port_scans (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                ip              TEXT NOT NULL,
                timestamp       TEXT NOT NULL,
                port            INTEGER NOT NULL,
                state           TEXT NOT NULL,
                service         TEXT
            )
        """)
        
        await db.commit()
        logger.info("Base de données initialisée.")


# ────────────────────────────────────────────────────────────────────────────────
# Devices
# ────────────────────────────────────────────────────────────────────────────────

async def get_all_devices() -> list:
    """Retourne tous les appareils."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("SELECT * FROM devices ORDER BY ip")
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def upsert_device(ip: str, mac: str = "", hostname: str = "", 
                       vendor: str = "", is_online: bool = True) -> None:
    """Insère ou met à jour un appareil."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        existing = await db.execute("SELECT id, is_new FROM devices WHERE ip = ?", (ip,))
        row = await existing.fetchone()
        
        if row:
            await db.execute("""
                UPDATE devices
                SET mac = ?, hostname = ?, vendor = ?, is_online = ?, last_seen = ?, is_new = 0
                WHERE ip = ?
            """, (mac, hostname, vendor, int(is_online), now, ip))
        else:
            await db.execute("""
                INSERT INTO devices (ip, mac, hostname, vendor, is_online, is_new, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """, (ip, mac, hostname, vendor, int(is_online), now, now))
        
        await db.commit()


async def set_device_offline(ip: str) -> None:
    """Marque un appareil comme hors ligne."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("UPDATE devices SET is_online = 0 WHERE ip = ?", (ip,))
        await db.commit()


async def update_device_alias(ip: str, alias: str) -> None:
    """Met à jour l'alias d'un appareil."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("UPDATE devices SET alias = ? WHERE ip = ?", (alias, ip))
        await db.commit()


# ────────────────────────────────────────────────────────────────────────────────
# Speedtest
# ────────────────────────────────────────────────────────────────────────────────

async def save_speedtest(ping_ms: float, download_mbps: float, upload_mbps: float) -> None:
    """Sauvegarde un résultat de speedtest."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO speedtest_history (timestamp, ping_ms, download_mbps, upload_mbps)
            VALUES (?, ?, ?, ?)
        """, (now, ping_ms, download_mbps, upload_mbps))
        await db.commit()


async def get_speedtest_history(limit: int = 50) -> list:
    """Retourne l'historique des speedtests."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM speedtest_history
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_speedtest_heatmap(days: int = 7) -> list:
    """Retourne données pour heatmap (par jour et heure)."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT 
                strftime('%w', timestamp) as day,
                strftime('%H', timestamp) as hour,
                AVG(download_mbps) as avg_download
            FROM speedtest_history
            WHERE timestamp >= datetime('now', '-' || ? || ' days')
            GROUP BY day, hour
            ORDER BY day, hour
        """, (days,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ────────────────────────────────────────────────────────────────────────────────
# Alertes
# ────────────────────────────────────────────────────────────────────────────────

async def create_alert(level: str, message: str) -> None:
    """Ajoute une alerte en base."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO alerts (timestamp, level, message, resolved)
            VALUES (?, ?, ?, 0)
        """, (now, level, message))
        await db.commit()


async def get_alerts(limit: int = 50) -> list:
    """Retourne les dernières alertes non résolues."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT timestamp, level, message, id
            FROM alerts
            WHERE resolved = 0
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ────────────────────────────────────────────────────────────────────────────────
# CVE Results
# ────────────────────────────────────────────────────────────────────────────────

async def save_cve_result(device_ip: str, hostname: str, cve_id: str, 
                          description: str = "", severity: str = "", 
                          cvss_score: float = 0.0) -> None:
    """Sauvegarde un résultat de scan CVE."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO cve_results (device_ip, hostname, cve_id, description, 
                                     severity, cvss_score, scan_timestamp, resolved)
            VALUES (?, ?, ?, ?, ?, ?, ?, 0)
        """, (device_ip, hostname, cve_id, description, severity, cvss_score, now))
        await db.commit()
        logger.info(f"CVE sauvegardée: {cve_id} pour {hostname}")


async def get_cve_results(device_ip: str = None, resolved: bool = False) -> list:
    """Récupère les résultats CVE."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        if device_ip:
            query = """SELECT * FROM cve_results 
                       WHERE device_ip = ? AND resolved = ? 
                       ORDER BY scan_timestamp DESC"""
            cursor = await db.execute(query, (device_ip, int(resolved)))
        else:
            query = """SELECT * FROM cve_results 
                       WHERE resolved = ? 
                       ORDER BY scan_timestamp DESC"""
            cursor = await db.execute(query, (int(resolved),))
        
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def get_all_cve_summary() -> dict:
    """Récupère un résumé de toutes les CVE par appareil."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        
        query = """SELECT device_ip, hostname, COUNT(*) as cve_count
                   FROM cve_results
                   WHERE resolved = 0
                   GROUP BY device_ip, hostname
                   ORDER BY cve_count DESC"""
        
        cursor = await db.execute(query)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def mark_cve_resolved(cve_id: str, device_ip: str) -> None:
    """Marque une CVE comme résolue."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            UPDATE cve_results 
            SET resolved = 1 
            WHERE cve_id = ? AND device_ip = ?
        """, (cve_id, device_ip))
        await db.commit()
        logger.info(f"CVE {cve_id} marquée comme résolue pour {device_ip}")


# ────────────────────────────────────────────────────────────────────────────────
# Device Ping History
# ────────────────────────────────────────────────────────────────────────────────

async def get_device_ping_history(ip: str, limit: int = 100) -> list:
    """Retourne l'historique de ping pour un appareil."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM device_ping_history
            WHERE ip = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (ip, limit))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def save_device_ping(ip: str, is_online: bool, ping_ms: float = 0.0) -> None:
    """Sauvegarde un résultat de ping pour un appareil."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO device_ping_history (ip, timestamp, is_online, ping_ms)
            VALUES (?, ?, ?, ?)
        """, (ip, now, int(is_online), ping_ms))
        await db.commit()


# ────────────────────────────────────────────────────────────────────────────────
# Port Scans
# ────────────────────────────────────────────────────────────────────────────────

async def get_port_scans(ip: str) -> list:
    """Retourne les scans de ports pour un appareil."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT * FROM port_scans
            WHERE ip = ?
            ORDER BY timestamp DESC, port
        """, (ip,))
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


async def save_port_scan(ip: str, port: int, state: str, service: str = "") -> None:
    """Sauvegarde un résultat de scan de port."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO port_scans (ip, timestamp, port, state, service)
            VALUES (?, ?, ?, ?, ?)
        """, (ip, now, port, state, service))
        await db.commit()
