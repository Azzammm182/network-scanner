"""Deteksi anomali / indikasi serangan dari data hasil scan.

Yang dideteksi (heuristik):
  - new_device        : perangkat asing muncul pertama kali
  - gateway_mac_change: MAC gateway berubah -> indikasi ARP spoofing
  - duplicate_mac     : satu MAC mengklaim banyak IP
  - duplicate_ip      : dua MAC mengklaim IP yang sama
  - ip_reassigned     : IP berpindah ke MAC lain (kadang wajar, DHCP)
  - flood / port scan : dari analyzer paket (di class PacketAnalyzer)
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .database import add_history, get_devices, get_gateway_mac
from .utils import normalize_mac


def detect(
    conn,
    cfg: Dict[str, Any],
    scan: Dict[str, Any],
    on_alert: Optional[Callable[[str, str, str], None]] = None,
) -> List[Dict[str, str]]:
    """Bandingkan hasil scan dengan riwayat DB; catat temuan.

    Return list temuan {level, event, detail}.
    """
    alerts_cfg = cfg.get("alerts", {})
    devices = scan["devices"]
    gateway_ip = scan["gateway_ip"]
    gateway_mac = normalize_mac(scan["gateway_mac"])
    ts = scan.get("ts") or datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    known: Dict[str, Dict[str, Any]] = {d["mac"]: d for d in get_devices(conn) if d["mac"]}
    online_macs = {normalize_mac(d["mac"]) for d in devices if d["mac"]}

    findings: List[Dict[str, str]] = []
    emit = on_alert or (lambda level, event, detail: None)

    # --- 1. Perangkat baru ------------------------------------------------
    if alerts_cfg.get("new_device", True):
        for dev in devices:
            mac = normalize_mac(dev["mac"])
            if mac and mac not in known:
                findings.append({
                    "level": "warning",
                    "event": "PERANGKAT_BARU",
                    "detail": f"{dev['ip']} ({mac}) vendor={dev.get('vendor') or '-'}",
                })

    # --- 2. MAC gateway berubah (ARP spoofing) ----------------------------
    if alerts_cfg.get("gateway_mac_change", True) and gateway_mac:
        prev = get_gateway_mac(conn)
        if prev and normalize_mac(prev) != gateway_mac:
            findings.append({
                "level": "critical",
                "event": "GANTI_MAC_GATEWAY",
                "detail": f"Gateway {gateway_ip}: MAC {prev} -> {gateway_mac} "
                          f"(kemungkinan ARP spoofing!)",
            })

    # --- 3. Satu MAC mengklaim banyak IP -----------------------------------
    if alerts_cfg.get("duplicate_mac", True):
        ip_by_mac: Dict[str, List[str]] = {}
        for dev in devices:
            mac = normalize_mac(dev["mac"])
            if mac:
                ip_by_mac.setdefault(mac, []).append(dev["ip"])
        for mac, ips in ip_by_mac.items():
            if len(ips) > 1:
                findings.append({
                    "level": "warning",
                    "event": "MAC_GANDA",
                    "detail": f"MAC {mac} muncul di IP: {', '.join(sorted(ips))}",
                })

    # --- 4. Dua MAC mengklaim IP yang sama ---------------------------------
    if alerts_cfg.get("duplicate_ip", True):
        mac_by_ip: Dict[str, List[str]] = {}
        for dev in devices:
            mac = normalize_mac(dev["mac"])
            if mac:
                mac_by_ip.setdefault(dev["ip"], []).append(mac)
        for ip, macs in mac_by_ip.items():
            if len(macs) > 1:
                findings.append({
                    "level": "warning",
                    "event": "IP_GANDA",
                    "detail": f"IP {ip} dipakai oleh MAC: {', '.join(sorted(macs))}",
                })

    # --- 5. IP berpindah perangkat ----------------------------------------
    if alerts_cfg.get("ip_reassigned", True):
        ip_by_mac_now: Dict[str, str] = {
            normalize_mac(d["mac"]): d["ip"] for d in devices if d["mac"]
        }
        for mac, old in known.items():
            new = ip_by_mac_now.get(mac)
            if mac in online_macs and new and new != old["ip"]:
                findings.append({
                    "level": "info",
                    "event": "IP_BERPINDAH",
                    "detail": f"MAC {mac} berpindah IP: {old['ip']} -> {new}",
                })

    # Tulis semua temuan ke DB dan callback.
    for f in findings:
        add_history(conn, f["event"], f["level"], f["detail"], ts)
        emit(f["level"], f["event"], f["detail"])

    return findings


class PacketAnalyzer:
    """Analisis statistik koneksi -> deteksi port scan (satu sumber ke satu
    tujuan dengan banyak port berbeda).

    Ambang batas dapat dikonfigurasi di config.yaml (packet.syn_port_threshold).
    """

    def __init__(self, syn_port_threshold: int = 25):
        self.syn_port_threshold = syn_port_threshold
        self._counters: Dict[str, Dict[str, Any]] = {}
        self._last_ts = datetime.now()

    def feed(self, src_ip: str, dst_ip: str, dst_port: int) -> Optional[Dict[str, str]]:
        """Masukkan satu koneksi, return finding bila ada indikasi serangan."""
        now = datetime.now()
        elapsed = max(1.0, (now - self._last_ts).total_seconds())
        key = f"{src_ip}->{dst_ip}"
        st = self._counters.setdefault(key, {"ports": set(), "count": 0, "window": now})
        st["ports"].add(dst_port)
        st["count"] += 1

        finding = None
        if len(st["ports"]) >= self.syn_port_threshold:
            finding = {
                "level": "warning",
                "event": "PORT_SCAN",
                "detail": f"{src_ip} menyentuh {len(st['ports'])} port di {dst_ip}",
            }
            st["ports"] = set()  # reset agar tidak spam
        if elapsed >= 10.0:
            self._counters.clear()
            self._last_ts = now
        return finding
