"""Konfigurasi NetGuard (default + config.yaml)."""
from __future__ import annotations

import copy
from pathlib import Path
from typing import Any, Dict

try:
    import yaml

    YAML = True
except ImportError:  # pragma: no cover - fallback ke default saja
    yaml = None
    YAML = False

BASE_DIR = Path(__file__).resolve().parent.parent

DEFAULTS: Dict[str, Any] = {
    "monitor": {
        "interval": 10,            # detik antar pemindaian saat `watch`
        "ping_timeout_ms": 500,    # timeout ping (ms) saat sweeping
        "ping_workers": 64,        # jumlah thread ping paralel
    },
    "scan": {
        "ping_sweep": True,
        "vendor_lookup": True,
        "resolve_hostname": True,
    },
    "alerts": {
        "new_device": True,
        "gateway_mac_change": True,
        "duplicate_mac": True,
        "duplicate_ip": True,
        "ip_reassigned": True,
    },
    "packet": {
        "syn_port_threshold": 25,
        "arp_flood_threshold": 20,
        "deauth_threshold": 5,
    },
    "paths": {
        "data_dir": "data",
    },
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    """Gabungkan dict bertingkat (override menimpa base)."""
    out = copy.deepcopy(base)
    for key, value in (override or {}).items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_config(path: Path = None) -> Dict[str, Any]:
    """Muat konfigurasi; file config.yaml bersifat opsional."""
    cfg = copy.deepcopy(DEFAULTS)
    config_path = path or (BASE_DIR / "config.yaml")
    if YAML and config_path.exists():
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                data = yaml.safe_load(f) or {}
            cfg = _deep_merge(cfg, data)
        except Exception:
            pass  # file rusak -> pakai default
    return cfg


def get_paths(cfg: Dict[str, Any]) -> Dict[str, Path]:
    """Path database, state, dan cache (folder otomatis dibuat)."""
    data_dir = BASE_DIR / cfg.get("paths", {}).get("data_dir", "data")
    data_dir.mkdir(parents=True, exist_ok=True)
    return {
        "data_dir": data_dir,
        "db": data_dir / "netguard.db",
        "state": data_dir / "state.json",
        "oui_cache": data_dir / "oui_cache.json",
    }
