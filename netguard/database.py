"""Penyimpanan riwayat perangkat & kejadian menggunakan SQLite."""
from __future__ import annotations

import sqlite3
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path


def connect(db_path: Path) -> sqlite3.Connection:
    """Buka koneksi SQLite dengan row factory."""
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def init_db(conn: sqlite3.Connection) -> None:
    """Buat tabel bila belum ada."""
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ip          TEXT NOT NULL,
            mac         TEXT NOT NULL,
            hostname    TEXT,
            vendor      TEXT,
            status      TEXT DEFAULT 'online',
            first_seen  TEXT NOT NULL,
            last_seen   TEXT NOT NULL,
            gateway     INTEGER DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_devices_mac ON devices(mac);
        CREATE INDEX IF NOT EXISTS idx_devices_ip  ON devices(ip);

        CREATE TABLE IF NOT EXISTS history (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            ts          TEXT NOT NULL,
            event       TEXT NOT NULL,
            severity    TEXT NOT NULL,       -- info | warning | critical
            detail      TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_history_ts ON history(ts);
        """
    )
    conn.commit()


def upsert_device(
    conn: sqlite3.Connection,
    ip: str,
    mac: str,
    hostname: Optional[str] = None,
    vendor: Optional[str] = None,
    status: str = "online",
    gateway: bool = False,
) -> None:
    """Simpan/update satu perangkat. Unik berdasarkan MAC."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    cur = conn.execute("SELECT id FROM devices WHERE mac = ?", (mac,))
    row = cur.fetchone()
    if row is None:
        conn.execute(
            """INSERT INTO devices (ip, mac, hostname, vendor, status, first_seen, last_seen, gateway)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (ip, mac, hostname, vendor, status, now, now, int(gateway)),
        )
    else:
        conn.execute(
            """UPDATE devices
               SET ip = ?, hostname = COALESCE(?, hostname), vendor = COALESCE(?, vendor),
                   status = ?, last_seen = ?, gateway = MAX(gateway, ?)
               WHERE mac = ?""",
            (ip, hostname, vendor, status, now, int(gateway), mac),
        )


def mark_offline(conn: sqlite3.Connection, online_macs: set) -> None:
    """Tandai perangkat yang tidak terlihat di scan terakhir sebagai offline."""
    rows = conn.execute("SELECT mac FROM devices WHERE status != 'offline'").fetchall()
    for row in rows:
        if row["mac"] not in online_macs:
            conn.execute(
                "UPDATE devices SET status = 'offline' WHERE mac = ?",
                (row["mac"],),
            )


def add_history(
    conn: sqlite3.Connection,
    event: str,
    severity: str,
    detail: str = "",
    ts: Optional[str] = None,
) -> None:
    """Catat satu kejadian ke log riwayat."""
    conn.execute(
        "INSERT INTO history (ts, event, severity, detail) VALUES (?, ?, ?, ?)",
        (ts or datetime.now().strftime("%Y-%m-%d %H:%M:%S"), event, severity, detail),
    )


def get_devices(conn: sqlite3.Connection) -> List[Dict[str, Any]]:
    """Semua perangkat, terurut: gateway, lalu IP numerik."""
    rows = [dict(r) for r in conn.execute("SELECT * FROM devices").fetchall()]
    def key(d):
        try:
            return tuple(int(x) for x in d["ip"].split("."))
        except Exception:
            return (999, 999, 999, 999)
    rows.sort(key=lambda d: (not d.get("gateway"), key(d)))
    return rows


def get_gateway_mac(conn: sqlite3.Connection) -> Optional[str]:
    """MAC gateway yang tersimpan (dari scan sebelumnya)."""
    row = conn.execute(
        "SELECT mac FROM devices WHERE gateway = 1 ORDER BY id DESC LIMIT 1"
    ).fetchone()
    return row["mac"] if row else None


def find_mac_for_ip(conn: sqlite3.Connection, ip: str) -> Optional[str]:
    row = conn.execute("SELECT mac FROM devices WHERE ip = ? LIMIT 1", (ip,)).fetchone()
    return row["mac"] if row else None


def set_gateway(conn: sqlite3.Connection, mac: str) -> None:
    """Tandai satu MAC sebagai gateway, hapus penanda gateway lain."""
    conn.execute("UPDATE devices SET gateway = 0")
    conn.execute("UPDATE devices SET gateway = 1 WHERE mac = ?", (mac,))
