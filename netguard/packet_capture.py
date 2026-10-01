"""Inspeksi paket WiFi dengan scapy.

Dua mode:
  passive : menganalisis koneksi TCP/UDP lewat psutil (tanpa admin,
            tanpa Npcap) -> deteksi port scan & flood.
  monitor : menangkap frame WiFi dengan scapy (WAJIB Npcap + adapter
            yang mendukung monitor mode) -> deteksi deauth attack,
            ARP flood, dan menampilkan statistik ringan.
"""
from __future__ import annotations

import time
from collections import Counter, defaultdict, deque
from datetime import datetime
from typing import Any, Dict, List, Optional

from .utils import SCAPY, IS_WINDOWS, normalize_mac


# ---------------------------------------------------------------------------
# Mode passive (psutil) — jalan tanpa hak admin & tanpa Npcap
# ---------------------------------------------------------------------------
def passive_analyze(
    seconds: int,
    top_n: int = 20,
    syn_port_threshold: int = 25,
) -> List[Dict[str, Any]]:
    """Analisis koneksi sistem secara pasif selama `seconds` detik.

    `syn_port_threshold`: jumlah port berbeda (satu sumber -> satu tujuan)
    yang dianggap sebagai indikasi port scan.
    """
    try:
        import psutil
    except ImportError:
        raise RuntimeError("psutil belum terinstall. Jalankan: py -m pip install -r requirements.txt")

    start = time.time()
    findings: List[Dict[str, Any]] = []
    last_print = 0.0
    while time.time() - start < seconds:
        rows: List[Dict[str, Any]] = []
        for conn in psutil.net_connections(kind="inet"):
            if not (conn.laddr and conn.raddr):
                continue
            try:
                src_ip, _src_port = conn.laddr.ip, conn.laddr.port
                dst_ip, dst_port = conn.raddr.ip, conn.raddr.port
            except Exception:
                continue
            rows.append({
                "src": f"{src_ip}",
                "dst_ip": f"{dst_ip}",
                "dst_port": dst_port,
                "status": conn.status,
                "pid": conn.pid,
            })

        # Sinyal mencurigakan: SATU sumber -> SATU tujuan, BANYAK port berbeda.
        # (koneksi browsing normal umumnya hanya 1-2 port, mis. 443)
        groups: Dict[tuple, set] = defaultdict(set)
        for r in rows:
            src = r["src"]
            if src.startswith(("127.", "0.", "169.254.")):
                continue
            dst_ip = r["dst_ip"]
            if dst_ip.startswith(("127.", "0.", "169.254.")):
                continue
            groups[(src, dst_ip)].add(r["dst_port"])

        for (src, dst_ip), ports in groups.items():
            if len(ports) >= syn_port_threshold:
                findings.append({
                    "level": "warning",
                    "event": "PORT_SCAN_AKTIF",
                    "detail": f"{src} menyentuh {len(ports)} port berbeda di {dst_ip} "
                              f"(port: {', '.join(map(str, sorted(ports)[:12]))} ...)",
                })

        if findings:
            return findings

        # Cetak progress sekali saja agar tidak banjir output.
        if time.time() - last_print >= 5:
            print(f"  ... memantau koneksi (aktif: {len(rows)}) ...")
            last_print = time.time()
        time.sleep(1.0)

    return []


# ---------------------------------------------------------------------------
# Mode monitor (scapy) — perlu Npcap, idealnya adapter monitor-mode
# ---------------------------------------------------------------------------
def check_scapy() -> List[str]:
    """Return daftar masalah yang membuat mode monitor tidak bisa jalan."""
    problems = []
    if not SCAPY:
        problems.append(
            "scapy belum terinstall. Jalankan: py -m pip install -r requirements.txt"
        )
    if IS_WINDOWS:
        problems.append(
            "Windows: pastikan Npcap sudah terinstall (https://npcap.com) "
            "dan pilih 'Support raw 802.11 traffic' saat instalasi."
        )
    return problems


def monitor_capture(
    iface: Optional[str] = None,
    duration: int = 60,
    deauth_threshold: int = 5,
    arp_flood_threshold: int = 20,
) -> List[Dict[str, Any]]:
    """Tangkap frame selama `duration` detik; deteksi deauth & ARP flood.

    Return list temuan. Memerlukan scapy + Npcap + izin yang cukup.
    """
    if not SCAPY:
        raise RuntimeError("scapy belum terinstall.")
    try:
        from scapy.all import Dot11, Dot11Deauth, ARP, sniff
    except ImportError as e:  # praktis - scapy import gagal tanpa Npcap
        raise RuntimeError(f"Gagal import scapy: {e}")

    deauths: deque = deque()
    arp_requests: deque = deque()
    findings: List[Dict[str, Any]] = []

    def _handle(pkt):
        # --- Deauth / disassociation frame ---
        if pkt.haslayer(Dot11Deauth):
            try:
                target = normalize_mac(pkt[Dot11].addr1)
                source = normalize_mac(pkt[Dot11].addr2)
            except Exception:
                target, source = "", ""
            deauths.append((time.time(), source, target))

        # --- ARP flood sederhana ---
        if pkt.haslayer(ARP):
            arp_requests.append(time.time())

    sniff(iface=iface, prn=_handle, timeout=duration, store=False)

    now = time.time()
    recent_deauth = [d for d in deauths if now - d[0] <= 5]
    recent_arp = [a for a in arp_requests if now - a <= 10]

    if len(recent_deauth) >= deauth_threshold:
        senders = Counter(s for _, s, _ in recent_deauth)
        top_src, count = senders.most_common(1)[0]
        findings.append({
            "level": "critical",
            "event": "DEAUTH_ATTACK",
            "detail": f"{count} frame deauth/5 detik dari {top_src} (target diserang)",
        })

    if len(recent_arp) >= arp_flood_threshold:
        findings.append({
            "level": "warning",
            "event": "ARP_FLOOD",
            "detail": f"{len(recent_arp)} paket ARP/10 detik (kemungkinan ARP flooding)",
        })

    if not findings:
        findings.append({
            "level": "info",
            "event": "PACKET_OK",
            "detail": f"{len(deauths)} frame deauth, {len(arp_requests)} ARP dalam {duration}s — tidak ada indikasi serangan",
        })

    return findings
