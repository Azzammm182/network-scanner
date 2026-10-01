"""Utilitas umum NetGuard."""
from __future__ import annotations

import importlib.util
import ipaddress
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any, Dict

IS_WINDOWS = os.name == "nt"

# Deteksi dependensi tanpa import berat (import scapy bisa lambat 2-4 detik).
PSUTIL = importlib.util.find_spec("psutil") is not None
MANUF = importlib.util.find_spec("manuf") is not None
REQUESTS = importlib.util.find_spec("requests") is not None
SCAPY = importlib.util.find_spec("scapy") is not None


def now_str() -> str:
    """Timestamp standar untuk log."""
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def normalize_mac(mac: str) -> str:
    """Normalisasi MAC menjadi format aa:bb:cc:dd:ee:ff (huruf kecil)."""
    if not mac:
        return ""
    cleaned = re.sub(r"[^0-9a-fA-F]", "", mac.strip())
    if len(cleaned) != 12:
        return mac.strip().lower()
    return ":".join(cleaned[i:i + 2] for i in range(0, 12, 2))


def ip_sort_key(ip: str) -> int:
    """Kunci urut numerik untuk alamat IPv4."""
    try:
        return int(ipaddress.ip_address(ip))
    except ValueError:
        return 0


def load_json(path: Any, default: Any) -> Any:
    """Muat JSON; kembalikan `default` bila gagal/tidak ada."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path: Any, data: Any) -> None:
    """Simpan JSON (best-effort)."""
    try:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception:
        pass


def truncate(text: str, width: int) -> str:
    """Potong teks agar pas di kolom tabel."""
    text = text or ""
    return text if len(text) <= width else text[: width - 1] + "…"
