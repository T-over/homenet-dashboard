"""
database.py – Gestion de la base de données SQLite via aiosqlite
Tables : devices, speedtest_history, alerts, device_ping_history, port_scans
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
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                ip         TEXT NOT NULL UNIQUE,
                alias      TEXT,
                mac        TEXT,
                hostname   TEXT,
                vendor     TEXT,
                is_online  INTEGER NOT NULL DEFAULT 1,
                is_new     INTEGER NOT NULL DEFAULT 1,
                first_seen TEXT NOT NULL,
                last_seen  TEXT NOT NULL
            )
        """)
        # Ajout colonne alias si elle n'existe pas (migration)
        try:
            await db.execute("ALTER TABLE devices ADD COLUMN alias TEXT")
        except Exception:
            pass

        # Table historique speedtest
        await db.execute("""
            CREATE TABLE IF NOT EXISTS speedtest_history (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                download_mbps REAL,
                upload_mbps   REAL,
                ping_ms       REAL
            )
        """)

        # Table alertes
        await db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level     TEXT NOT NULL,
                message   TEXT NOT NULL,
                resolved  INTEGER NOT NULL DEFAULT 0
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
        """)

        # Table historique ping par appareil
        await db.execute("""
            CREATE TABLE IF NOT EXISTS device_ping_history (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ip        TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                is_online INTEGER NOT NULL DEFAULT 1,
                ping_ms   REAL
            )
        """)

        # Table scan de ports
        await db.execute("""
            CREATE TABLE IF NOT EXISTS port_scans (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                ip        TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ports_json TEXT NOT NULL
            )
        """)

        await db.commit()
        logger.info("Base de données initialisée : %s", DATABASE_PATH)


# ---------------------------------------------------------------------------
# Appareils
# ---------------------------------------------------------------------------
async def get_all_devices() -> list:
    """Retourne tous les appareils triés : en ligne d'abord, puis par IP."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT ip, alias, mac, hostname, vendor, is_online, is_new, first_seen, last_seen
            FROM devices
            ORDER BY is_online DESC, ip ASC
        """)
        rows = await cursor.fetchall()
        return [
            {
                "ip": r["ip"],
                "alias": r["alias"] or "",
                "mac": r["mac"] or "",
                "hostname": r["hostname"] or "",
                "vendor": r["vendor"] or "Inconnu",
                "is_online": bool(r["is_online"]),
                "is_new": bool(r["is_new"]),
                "first_seen": r["first_seen"],
                "last_seen": r["last_seen"],
            }
            for r in rows
        ]


async def upsert_device(ip: str, mac: str, hostname: str, vendor: str, is_online: bool) -> bool:
    """Insère ou met à jour un appareil. Retourne True si c'est un nouvel appareil."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        cursor = await db.execute("SELECT id, is_new FROM devices WHERE ip = ?", (ip,))
        row = await cursor.fetchone()
        if row is None:
            await db.execute("""
                INSERT INTO devices (ip, mac, hostname, vendor, is_online, is_new, first_seen, last_seen)
                VALUES (?, ?, ?, ?, ?, 1, ?, ?)
            """, (ip, mac, hostname, vendor, int(is_online), now, now))
            await db.commit()
            return True
        else:
            await db.execute("""
                UPDATE devices
                SET mac=?, hostname=?, vendor=?, is_online=?, last_seen=?
                WHERE ip=?
            """, (mac, hostname, vendor, int(is_online), now, ip))
            await db.commit()
            return False


async def mark_devices_offline(active_ips: list) -> None:
    """Marque hors ligne les appareils absents du dernier scan."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        if active_ips:
            placeholders = ",".join(["?"] * len(active_ips))
            await db.execute(
                f"UPDATE devices SET is_online=0 WHERE ip NOT IN ({placeholders})",
                active_ips
            )
        else:
            await db.execute("UPDATE devices SET is_online=0")
        await db.commit()


async def update_device_alias(ip: str, alias: str) -> None:
    """Met à jour le nom personnalisé d'un appareil."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("UPDATE devices SET alias=? WHERE ip=?", (alias, ip))
        await db.commit()


async def get_device_ping_history(ip: str, limit: int = 100) -> list:
    """Retourne l'historique ping/état d'un appareil."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT timestamp, is_online, ping_ms
            FROM device_ping_history
            WHERE ip = ?
            ORDER BY timestamp DESC
            LIMIT ?
        """, (ip, limit))
        rows = await cursor.fetchall()
        return [{"timestamp": r["timestamp"], "is_online": bool(r["is_online"]), "ping_ms": r["ping_ms"]} for r in rows]


async def save_device_ping(ip: str, is_online: bool, ping_ms: float = None) -> None:
    """Sauvegarde un événement ping pour un appareil."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO device_ping_history (ip, timestamp, is_online, ping_ms)
            VALUES (?, ?, ?, ?)
        """, (ip, now, int(is_online), ping_ms))
        await db.commit()


# ---------------------------------------------------------------------------
# Scan de ports
# ---------------------------------------------------------------------------
async def save_port_scan(ip: str, ports: list) -> None:
    """Sauvegarde les résultats d'un scan de ports."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO port_scans (ip, timestamp, ports_json)
            VALUES (?, ?, ?)
        """, (ip, now, json.dumps(ports)))
        await db.commit()


async def get_port_scan_results(ip: str) -> list:
    """Retourne les derniers résultats de scan de ports pour une IP."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT ports_json, timestamp
            FROM port_scans
            WHERE ip = ?
            ORDER BY timestamp DESC
            LIMIT 1
        """, (ip,))
        row = await cursor.fetchone()
        if row:
            return {"ports": json.loads(row["ports_json"]), "timestamp": row["timestamp"]}
        return {"ports": [], "timestamp": None}


# ---------------------------------------------------------------------------
# Speedtest
# ---------------------------------------------------------------------------
async def save_speedtest(download: float, upload: float, ping: float) -> None:
    """Sauvegarde un résultat de speedtest."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO speedtest_history (timestamp, download_mbps, upload_mbps, ping_ms)
            VALUES (?, ?, ?, ?)
        """, (now, download, upload, ping))
        await db.commit()


async def get_speedtest_history(limit: int = 24) -> list:
    """Retourne l'historique des mesures de débit."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT timestamp, download_mbps, upload_mbps, ping_ms
            FROM speedtest_history
            ORDER BY timestamp DESC
            LIMIT ?
        """, (limit,))
        rows = await cursor.fetchall()
        result = [dict(r) for r in rows]
        result.reverse()
        return result


async def get_bandwidth_heatmap() -> list:
    """
    Retourne la moyenne de débit par heure et par jour de la semaine.
    Format: [{day: 0-6, hour: 0-23, download_mbps: float, upload_mbps: float}]
    """
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT
                CAST(strftime('%w', timestamp) AS INTEGER) as day,
                CAST(strftime('%H', timestamp) AS INTEGER) as hour,
                AVG(download_mbps) as download_mbps,
                AVG(upload_mbps) as upload_mbps,
                COUNT(*) as count
            FROM speedtest_history
            GROUP BY day, hour
            ORDER BY day, hour
        """)
        rows = await cursor.fetchall()
        return [dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Alertes
# ---------------------------------------------------------------------------
async def add_alert(level: str, message: str) -> None:
    """Ajoute une alerte en base."""
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO alerts (timestamp, level, message)
            VALUES (?, ?, ?)
        """, (now, level, message))
        await db.commit()


async def get_alerts(limit: int = 50) -> list:
    """Retourne les dernières alertes non résolues."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        cursor = await db.execute("""
            SELECT timestamp, level, message
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
