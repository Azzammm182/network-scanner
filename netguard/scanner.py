"""Pemindai perangkat di jaringan lokal.

Alur (khas toolkit ARP scanner):
  1. Sweep ping seluruh subnet (paralel) -> ARP cache terisi.
  2. Baca ARP cache via perintah OS -> dapat pasangan IP<->MAC.
  3. (Opsional) resolve hostname dan cari vendor MAC.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import Any, Dict, List, Optional

from .config import get_paths
from .network import get_gateway, get_network, ping
from .utils import IS_WINDOWS, MANUF, load_json, normalize_mac, save_json


def _arp_entries() -> List[Dict[str, str]]:
    """Baca ARP cache OS. Return [{ip, mac}]."""
    if IS_WINDOWS:
        return _arp_entries_windows()
    return _arp_entries_linux()


def _arp_entries_windows() -> List[Dict[str, str]]:
    try:
        out = subprocess.run(
            ["arp", "-a"],
            capture_output=True,
            text=True,
            timeout=5,
            errors="replace",
        ).stdout
    except Exception:
        return []

    # Contoh baris: "  192.168.1.1          aa-bb-cc-dd-ee-ff     dynamic"
    entries: List[Dict[str, str]] = []
    for line in out.splitlines():
        m = re.search(r"(\d{1,3}(?:\.\d{1,3}){3})\s+((?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2})", line)
        if m:
            entries.append({"ip": m.group(1), "mac": normalize_mac(m.group(2))})
    return entries


def _arp_entries_linux() -> List[Dict[str, str]]:
    try:
        with open("/proc/net/arp") as f:
            lines = f.read().splitlines()[1:]
    except Exception:
        return []

    entries: List[Dict[str, str]] = []
    for line in lines:
        parts = line.split()
        if len(parts) >= 4 and parts[3] not in ("00:00:00:00:00:00",):
            entries.append({"ip": parts[0], "mac": normalize_mac(parts[3])})
    return entries


def sweep_ping(network: ipaddress.IPv4Network, timeout_ms: int = 500, workers: int = 64) -> List[str]:
    """Ping semua host dalam subnet secara paralel."""
    hosts = [str(h) for h in network.hosts()]
    if not hosts:
        return []
    alive: List[str] = []
    with ThreadPoolExecutor(max_workers=min(workers, len(hosts))) as pool:
        for ip, ok in zip(hosts, pool.map(lambda ip: ping(ip, timeout_ms), hosts)):
            if ok:
                alive.append(ip)
    return alive


class VendorLookup:
    """Cache vendor berdasarkan prefix OUI dari MAC (offline via db `manuf`)."""

    def __init__(self, cache_path):
        self.cache_path = cache_path
        self.cache = load_json(cache_path, {})
        self._parser = None
        if MANUF:
            try:
                from manuf import manuf

                self._parser = manuf.MacParser()
            except Exception:
                self._parser = None

    def lookup(self, mac: str) -> str:
        mac = normalize_mac(mac)
        if mac in self.cache:
            return self.cache[mac]
        vendor = ""
        if self._parser is not None:
            try:
                vendor = self._parser.get_manuf_long(mac) or ""
            except Exception:
                vendor = ""
        self.cache[mac] = vendor
        save_json(self.cache_path, self.cache)
        return vendor


def _resolve_hostname(ip: str, timeout: float = 0.4) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def scan_network(cfg: Dict[str, Any], verbose: bool = True) -> Dict[str, Any]:
    """Jalankan satu pemindaian penuh.

    Return: {network, local_ip, gateway_ip, gateway_mac, devices, ts}
    """
    net = get_network()
    if net is None:
        raise RuntimeError("Tidak bisa menentukan subnet. Pastikan terhubung ke WiFi.")

    from .network import get_local_ip

    local_ip = get_local_ip()
    gateway_ip = get_gateway(net)
    interval = cfg.get("monitor", {}).get("interval", 10)

    if verbose:
        print(f"[*] Subnet     : {net}")
        print(f"[*] IP lokal   : {local_ip}")
        print(f"[*] Gateway    : {gateway_ip}")

    if cfg.get("scan", {}).get("ping_sweep", True):
        timeout_ms = cfg.get("monitor", {}).get("ping_timeout_ms", 500)
        workers = cfg.get("monitor", {}).get("ping_workers", 64)
        if verbose:
            print(f"[*] Sweep ping : {net.num_addresses - 2} host, {workers} thread ...")
        alive = sweep_ping(net, timeout_ms, workers)
        if verbose:
            print(f"[*] Host aktif : {len(alive)}")

    entries = _arp_entries()

    # Pastikan gateway selalu masuk (mungkin tak ter-cache bila baru).
    seen_ips = {e["ip"] for e in entries}
    if gateway_ip and gateway_ip not in seen_ips:
        entries.append({"ip": gateway_ip, "mac": ""})

    vendor_lookup = None
    paths = get_paths(cfg)
    if cfg.get("scan", {}).get("vendor_lookup", True):
        vendor_lookup = VendorLookup(paths["oui_cache"])

    devices: List[Dict[str, Any]] = []
    for entry in entries:
        try:
            ip_addr = ipaddress.ip_address(entry["ip"])
        except ValueError:
            continue
        if ip_addr.version != 4 or not ip_addr in net:
            continue
        if entry["ip"] == local_ip:
            continue  # perangkat ini tidak perlu masuk daftar

        mac = normalize_mac(entry["mac"])
        vendor = vendor_lookup.lookup(mac) if (mac and vendor_lookup) else ""
        hostname = ""
        if cfg.get("scan", {}).get("resolve_hostname", True):
            hostname = _resolve_hostname(entry["ip"])

        devices.append({
            "ip": entry["ip"],
            "mac": mac,
            "hostname": hostname,
            "vendor": vendor,
            "status": "online",
            "gateway": bool(mac and entry["ip"] == gateway_ip),
        })

    # Dedup: 1 MAC di banyak IP -> pertahankan IP pertama (paling kecil).
    by_mac: Dict[str, Dict[str, Any]] = {}
    for dev in devices:
        if not dev["mac"]:
            continue
        key = dev["mac"]
        if key not in by_mac:
            by_mac[key] = dev
    devices = list(by_mac.values())
    devices.sort(key=lambda d: tuple(int(x) for x in d["ip"].split(".")))

    gateway_mac = next(
        (d["mac"] for d in devices if d["gateway"] and d["mac"]),
        next((d["mac"] for d in devices if d["ip"] == gateway_ip and d["mac"]), ""),
    )

    return {
        "network": str(net),
        "local_ip": local_ip,
        "gateway_ip": gateway_ip,
        "gateway_mac": gateway_mac,
        "devices": devices,
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    }
