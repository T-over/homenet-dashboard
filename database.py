"""
database.py — Gestion de la base de données SQLite via aiosqlite
Tables : devices, speedtest_history, alerts
"""

import logging
import aiosqlite
from datetime import datetime
from config import DATABASE_PATH

logger = logging.getLogger(__name__)


async def init_db() -> None:
    """Crée les tables si elles n'existent pas encore."""
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                ip          TEXT NOT NULL UNIQUE,
                mac         TEXT,
                hostname    TEXT,
                vendor      TEXT,
                is_online   INTEGER NOT NULL DEFAULT 1,
                is_new      INTEGER NOT NULL DEFAULT 1,
                first_seen  TEXT NOT NULL,
                last_seen   TEXT NOT NULL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS speedtest_history (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp     TEXT NOT NULL,
                ping_ms       REAL,
                download_mbps REAL,
                upload_mbps   REAL
            )
        """)
        await db.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id        INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                level     TEXT NOT NULL,
                category  TEXT NOT NULL,
                message   TEXT NOT NULL,
                resolved  INTEGER NOT NULL DEFAULT 0
            )
        """)
        await db.commit()
    logger.info("Base de données initialisée : %s", DATABASE_PATH)


async def upsert_device(ip: str, mac: str, hostname: str, vendor: str) -> dict:
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM devices WHERE ip = ?", (ip,)) as cur:
            existing = await cur.fetchone()
        if existing is None:
            await db.execute("""
                INSERT INTO devices (ip, mac, hostname, vendor, is_online, is_new, first_seen, last_seen)
                VALUES (?, ?, ?, ?, 1, 1, ?, ?)
            """, (ip, mac, hostname, vendor, now, now))
            is_new = True
        else:
            await db.execute("""
                UPDATE devices SET mac=?, hostname=?, vendor=?, is_online=1, last_seen=? WHERE ip=?
            """, (mac, hostname, vendor, now, ip))
            is_new = bool(existing["is_new"])
        await db.commit()
    return {"ip": ip, "is_new": is_new}


async def mark_devices_offline(active_ips: list[str]) -> list[str]:
    now = datetime.utcnow().isoformat()
    offline_ips: list[str] = []
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT ip FROM devices WHERE is_online = 1") as cur:
            online = await cur.fetchall()
        for row in online:
            if row["ip"] not in active_ips:
                await db.execute("UPDATE devices SET is_online=0, last_seen=? WHERE ip=?", (now, row["ip"]))
                offline_ips.append(row["ip"])
        await db.commit()
    return offline_ips


async def get_all_devices() -> list[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("SELECT * FROM devices ORDER BY is_online DESC, last_seen DESC") as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]


async def save_speedtest(ping_ms: float, download_mbps: float, upload_mbps: float) -> None:
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO speedtest_history (timestamp, ping_ms, download_mbps, upload_mbps)
            VALUES (?, ?, ?, ?)
        """, (now, ping_ms, download_mbps, upload_mbps))
        await db.commit()


async def get_speedtest_history(limit: int = 24) -> list[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM speedtest_history ORDER BY timestamp DESC LIMIT ?
        """, (limit,)) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in reversed(rows)]


async def create_alert(level: str, category: str, message: str) -> None:
    now = datetime.utcnow().isoformat()
    async with aiosqlite.connect(DATABASE_PATH) as db:
        await db.execute("""
            INSERT INTO alerts (timestamp, level, category, message) VALUES (?, ?, ?, ?)
        """, (now, level, category, message))
        await db.commit()
    logger.warning("[ALERTE %s] %s : %s", level.upper(), category, message)


async def get_alerts(limit: int = 50) -> list[dict]:
    async with aiosqlite.connect(DATABASE_PATH) as db:
        db.row_factory = aiosqlite.Row
        async with db.execute("""
            SELECT * FROM alerts WHERE resolved = 0 ORDER BY timestamp DESC LIMIT ?
        """, (limit,)) as cur:
            rows = await cur.fetchall()
    return [dict(r) for r in rows]
