"""Deteksi antarmuka jaringan, subnet, dan gateway."""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from typing import List, Optional

from .utils import IS_WINDOWS


def _psutil():
    try:
        import psutil

        return psutil
    except Exception:
        return None


def get_local_ip() -> str:
    """IP lokal perangkat ini (trik UDP connect, tidak mengirim paket)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        return s.getsockname()[0]
    except OSError:
        return "127.0.0.1"
    finally:
        s.close()


def get_interface_for_ip(ip: str) -> Optional[str]:
    psutil = _psutil()
    if psutil is None:
        return None
    for name, addrs in psutil.net_if_addrs().items():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == ip:
                return name
    return None


def get_netmask(ip: str) -> Optional[str]:
    psutil = _psutil()
    if psutil is None:
        return None
    for addrs in psutil.net_if_addrs().values():
        for addr in addrs:
            if addr.family == socket.AF_INET and addr.address == ip:
                return addr.netmask
    return None


def get_network() -> Optional[ipaddress.IPv4Network]:
    """Subnet IPv4 tempat perangkat ini berada."""
    ip = get_local_ip()
    if ip == "127.0.0.1":
        return None
    netmask = get_netmask(ip) or "255.255.255.0"
    try:
        return ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
    except ValueError:
        try:
            return ipaddress.ip_network(f"{ip}/24", strict=False)
        except ValueError:
            return None


def ping(ip: str, timeout_ms: int = 500) -> bool:
    """Ping satu host. Return True bila host menjawab."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(max(1, timeout_ms // 1000)), ip]
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
        )
        return proc.returncode == 0
    except Exception:
        return False


def get_gateway(network: ipaddress.IPv4Network) -> str:
    """IP gateway: baca tabel route, fallback ping .1 / .254."""
    parsed = _parse_gateways()
    for gw in parsed:
        try:
            if ipaddress.ip_address(gw) in network:
                return gw
        except ValueError:
            continue

    hosts = list(network.hosts())
    if not hosts:
        return str(network.network_address)
    for candidate in (hosts[0], hosts[-1]):
        if ping(str(candidate), 400):
            return str(candidate)
    if parsed:
        return parsed[0]
    return str(hosts[0])


def _parse_gateways() -> List[str]:
    """Ambil kandidat gateway dari tabel route OS."""
    if IS_WINDOWS:
        try:
            out = subprocess.run(
                ["route", "print", "-4"],
                capture_output=True,
                text=True,
                timeout=5,
            ).stdout
        except Exception:
            return []
        results: List[str] = []
        for line in out.splitlines():
            parts = line.split()
            if len(parts) >= 3 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                candidate = parts[2]
                if re.match(r"\d+\.\d+\.\d+\.\d+", candidate) and candidate != "0.0.0.0":
                    results.append(candidate)
        return results

    # Linux: /proc/net/route, gateway tersimpan hex little-endian.
    try:
        with open("/proc/net/route") as f:
            for line in f:
                parts = line.split()
                if len(parts) >= 3 and parts[1] == "00000000":
                    try:
                        gw = socket.inet_ntoa(bytes.fromhex(parts[2])[::-1])
                    except Exception:
                        continue
                    if gw != "0.0.0.0":
                        return [gw]
    except Exception:
        return []
    return []
