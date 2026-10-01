"""Command-line interface NetGuard."""
from __future__ import annotations

import argparse
import csv
import json
import os
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

# Pastikan folder project ada di sys.path bila dijalankan sebagai script.
BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from netguard import __version__
from netguard.analyzer import detect
from netguard.config import BASE_DIR as _CFG_BASE, get_paths, load_config
from netguard.database import (
    add_history,
    connect,
    get_devices,
    get_gateway_mac,
    init_db,
    mark_offline,
    set_gateway,
    upsert_device,
)
from netguard.scanner import scan_network
from netguard.utils import IS_WINDOWS, MANUF, PSUTIL, SCAPY, ip_sort_key, normalize_mac, now_str, truncate

try:
    from rich.console import Console
    from rich.table import Table
    from rich.text import Text

    RICH = True
except Exception:
    RICH = False


LEVEL_COLOR = {"info": "cyan", "warning": "yellow", "critical": "red"}


def _console():
    if RICH:
        return Console()
    return None


def _print_banner() -> None:
    print("=" * 62)
    print("  NetGuard v" + __version__ + "  —  Monitor & Proteksi Jaringan WiFi Pribadi")
    print("  Hanya untuk jaringan milik sendiri / yang Anda berwenang mengujinya.")
    print("=" * 62)


def _print_finding(f: Dict[str, str]) -> None:
    level = f.get("level", "info")
    event = f.get("event", "?")
    detail = f.get("detail", "")
    if RICH:
        c = Console()
        color = LEVEL_COLOR.get(level, "white")
        c.print(Text(f"  [!] {event}", style=f"bold {color}"), end=" ")
        c.print(detail)
    else:
        print(f"  [!] {event} ({level}) {detail}")


def _print_findings(findings: List[Dict[str, str]]) -> None:
    if not findings:
        print("  [✓] Tidak ada indikasi serangan terdeteksi.")
        return
    for f in findings:
        _print_finding(f)


def _devices_table(devices: List[Dict[str, Any]], gateway_ip: str = "") -> None:
    if not devices:
        print("  (tidak ada perangkat tersimpan)")
        return

    if RICH:
        c = Console(width=160)
        table = Table(title=f"Perangkat Terhubung ({len(devices)})", show_lines=False, expand=False)
        table.add_column("IP", style="bold", no_wrap=True, min_width=15)
        table.add_column("MAC", no_wrap=True, min_width=17)
        table.add_column("Hostname", no_wrap=True, max_width=28)
        table.add_column("Vendor", no_wrap=True, max_width=30)
        table.add_column("Status", no_wrap=True)
        table.add_column("Peran", no_wrap=True)
        table.add_column("Terakhir", no_wrap=True)
        for d in devices:
            role = "Gateway" if d.get("gateway") else ("Anda" if d.get("ip") == gateway_ip else "")
            status = d.get("status", "online")
            status_style = "green" if status == "online" else "dim"
            table.add_row(
                str(d.get("ip", "-")),
                d.get("mac") or "-",
                truncate(d.get("hostname") or "-", 24),
                truncate(d.get("vendor") or "-", 28),
                f"[{status_style}]{status}[/]",
                role or "-",
                d.get("last_seen", "-"),
            )
        c.print(table)
        return

    # Fallback tanpa rich.
    headers = ("IP", "MAC", "Hostname", "Vendor", "Status", "Peran", "Terakhir")
    rows = []
    for d in devices:
        role = "Gateway" if d.get("gateway") else ("Anda" if d.get("ip") == gateway_ip else "")
        rows.append((
            d.get("ip", "-"),
            d.get("mac") or "-",
            truncate(d.get("hostname") or "-", 24),
            truncate(d.get("vendor") or "-", 28),
            d.get("status", "online"),
            role or "-",
            d.get("last_seen", "-"),
        ))
    widths = [max(len(str(r[i])) for r in rows + [headers]) for i in range(len(headers))]
    fmt = "  " + "  ".join(f"{{:<{w}}}" for w in widths)
    print(fmt.format(*headers))
    print("  " + "  ".join("-" * w for w in widths))
    for r in rows:
        print(fmt.format(*r))


def _load_deps_status() -> Dict[str, Any]:
    return {
        "psutil": PSUTIL,
        "manuf": MANUF,
        "scapy": SCAPY,
        "rich": RICH,
        "windows": IS_WINDOWS,
    }


def _update_db(conn, scan: Dict[str, Any]) -> None:
    """Simpan hasil scan ke database."""
    for dev in scan["devices"]:
        upsert_device(
            conn,
            ip=dev["ip"],
            mac=dev["mac"],
            hostname=dev.get("hostname"),
            vendor=dev.get("vendor"),
            status="online",
            gateway=bool(dev.get("gateway")),
        )
    gateway_mac = normalize_mac(scan.get("gateway_mac") or "")
    if gateway_mac:
        set_gateway(conn, gateway_mac)
    online_macs = {normalize_mac(d["mac"]) for d in scan["devices"] if d.get("mac")}
    mark_offline(conn, online_macs)
    conn.commit()


def cmd_scan(args) -> int:
    cfg = load_config(args.config)
    conn = connect(get_paths(cfg)["db"])
    init_db(conn)

    try:
        scan = scan_network(cfg)
    except RuntimeError as e:
        print(f"[x] {e}")
        return 1

    existing = get_devices(conn)
    baseline = bool(existing)
    findings: List[Dict[str, str]] = []

    if baseline:
        findings = detect(conn, cfg, scan)
    else:
        print(f"[*] Scan pertama — menyimpan {len(scan['devices'])} perangkat sebagai baseline.\n")

    _update_db(conn, scan)

    print()
    _devices_table(get_devices(conn), gateway_ip=scan["gateway_ip"])
    print()
    if findings:
        print("[!] Temuan deteksi:")
        _print_findings(findings)
    else:
        _print_findings([])
    print()
    print(f"[*] Tersimpan di database: {get_paths(cfg)['db']}")
    conn.close()
    return 0


def cmd_list(args) -> int:
    cfg = load_config(args.config)
    paths = get_paths(cfg)
    if not paths["db"].exists():
        print("[x] Belum ada data. Jalankan dulu: python netguard.py scan")
        return 1
    conn = connect(paths["db"])
    init_db(conn)
    devices = get_devices(conn)
    conn.close()

    _devices_table(devices)
    online = sum(1 for d in devices if d.get("status") == "online")
    print(f"\n  Total: {len(devices)} perangkat (online: {online})")
    return 0


def cmd_watch(args) -> int:
    cfg = load_config(args.config)
    paths = get_paths(cfg)
    conn = connect(paths["db"])
    init_db(conn)

    print(f"[*] Mode pantau berkelanjutan — interval {cfg['monitor']['interval']} detik.")
    print("[*] Tekan Ctrl+C untuk berhenti.\n")

    try:
        while True:
            try:
                scan = scan_network(cfg, verbose=False)
            except RuntimeError as e:
                print(f"[x] {e}")
                time.sleep(cfg["monitor"]["interval"])
                continue

            baseline = bool(get_devices(conn))
            findings = detect(conn, cfg, scan) if baseline else []

            _update_db(conn, scan)

            print(f"\n--- {now_str()} | {len(scan['devices'])} perangkat aktif ---")
            _devices_table(get_devices(conn), gateway_ip=scan["gateway_ip"])
            if findings:
                print("[!] Temuan:")
                _print_findings(findings)
            time.sleep(cfg["monitor"]["interval"])
    except KeyboardInterrupt:
        print("\n[*] Pemantauan dihentikan.")
    finally:
        conn.close()
    return 0


def cmd_history(args) -> int:
    cfg = load_config(args.config)
    paths = get_paths(cfg)
    if not paths["db"].exists():
        print("[x] Belum ada data. Jalankan dulu: python netguard.py scan")
        return 1
    conn = connect(paths["db"])
    init_db(conn)
    limit = args.limit
    rows = conn.execute(
        "SELECT ts, event, severity, detail FROM history ORDER BY id DESC LIMIT ?",
        (limit,),
    ).fetchall()
    conn.close()

    if not rows:
        print("  (belum ada kejadian tercatat)")
        return 0

    if RICH:
        c = Console(width=160)
        table = Table(title=f"Riwayat Kejadian ({len(rows)} terakhir)", expand=False)
        table.add_column("Waktu", no_wrap=True)
        table.add_column("Kejadian", style="bold", no_wrap=True)
        table.add_column("Level", no_wrap=True)
        table.add_column("Detail")
        for r in rows:
            color = LEVEL_COLOR.get(r["severity"], "white")
            table.add_row(r["ts"], f"[{color}]{r['event']}[/]", f"[{color}]{r['severity']}[/]", r["detail"] or "-")
        c.print(table)
        return 0

    for r in rows:
        print(f"  {r['ts']}  [{r['severity']}] {r['event']}  {r['detail'] or '-'}")
    return 0


def cmd_packets(args) -> int:
    deps = _load_deps_status()
    if not deps["psutil"]:
        print("[x] psutil belum terinstall. Jalankan: py -m pip install -r requirements.txt")
        return 1

    if args.mode == "passive":
        seconds = args.seconds
        print(f"[*] Analisis koneksi pasif selama {seconds} detik (Ctrl+C untuk berhenti)...")
        from netguard.packet_capture import passive_analyze

        syn_threshold = load_config(args.config).get("packet", {}).get("syn_port_threshold", 25)
        try:
            findings = passive_analyze(seconds, syn_port_threshold=syn_threshold)
        except KeyboardInterrupt:
            findings = []
        _print_findings(findings if findings else [{
            "level": "info",
            "event": "PACKET_OK",
            "detail": "tidak ada indikasi port scan pada koneksi aktif",
        }])
        return 0

    if args.mode == "monitor":
        from netguard.packet_capture import check_scapy, monitor_capture

        problems = check_scapy()
        if problems:
            print("[x] Mode monitor tidak bisa dijalankan:")
            for p in problems:
                print(f"    - {p}")
            return 1
        pkt_cfg = load_config(args.config).get("packet", {})
        print(f"[*] Menangkap frame selama {args.duration} detik...")
        findings = monitor_capture(
            iface=args.iface,
            duration=args.duration,
            deauth_threshold=pkt_cfg.get("deauth_threshold", 5),
            arp_flood_threshold=pkt_cfg.get("arp_flood_threshold", 20),
        )
        _print_findings(findings)
        return 0

    print("[x] Mode tidak dikenal.")
    return 1


def cmd_export(args) -> int:
    cfg = load_config(args.config)
    paths = get_paths(cfg)
    if not paths["db"].exists():
        print("[x] Belum ada data. Jalankan dulu: python netguard.py scan")
        return 1
    conn = connect(paths["db"])
    init_db(conn)
    devices = get_devices(conn)
    conn.close()

    fmt = args.format.lower()
    if fmt == "json":
        out = paths["data_dir"] / "devices.json"
        out.write_text(json.dumps(devices, indent=2, ensure_ascii=False), encoding="utf-8")
    else:
        out = paths["data_dir"] / "devices.csv"
        with open(out, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["ip", "mac", "hostname", "vendor", "status", "first_seen", "last_seen", "gateway"])
            writer.writeheader()
            for d in devices:
                writer.writerow({k: d.get(k, "") for k in writer.fieldnames})
    print(f"[*] {len(devices)} perangkat diekspor ke: {out}")
    return 0


def cmd_clear(args) -> int:
    cfg = load_config(args.config)
    paths = get_paths(cfg)
    for key in ("db", "state", "oui_cache"):
        p = paths[key]
        if p.exists():
            p.unlink()
            print(f"  [-] {p} dihapus")
    print("[*] Database & cache dibersihkan. Jalankan `scan` untuk membuat baseline baru.")
    return 0


def cmd_deps(args) -> int:
    deps = _load_deps_status()
    rows = [
        ("psutil", deps["psutil"], "wajib — info interface & pemindaian"),
        ("manuf", deps["manuf"], "opsional — vendor MAC (offline)"),
        ("rich", deps["rich"], "opsional — tampilan tabel berwarna"),
        ("scapy", deps["scapy"], "opsional — inspeksi paket WiFi (perlu Npcap)"),
    ]
    for name, ok, desc in rows:
        mark = "OK" if ok else "BELUM"
        print(f"  [{'✓' if ok else ' '}] {name:<8} {mark:<6} {desc}")
    if IS_WINDOWS and not SCAPY:
        print("\n  Catatan Windows: untuk mode monitor install Npcap dari")
        print("  https://npcap.com (centang 'Support raw 802.11 traffic').")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="netguard",
        description="NetGuard — monitor & proteksi WiFi pribadi (ARP scanner, deteksi anomali, inspeksi paket).",
    )
    p.add_argument("--config", type=Path, default=None, help="path config.yaml (default: config.yaml di folder project)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    sub = p.add_subparsers(dest="command", required=True)

    p_scan = sub.add_parser("scan", help="pindai perangkat terhubung sekali, lalu deteksi anomali")
    p_scan.set_defaults(func=cmd_scan)

    p_list = sub.add_parser("list", help="tampilkan daftar perangkat tersimpan")
    p_list.set_defaults(func=cmd_list)

    p_watch = sub.add_parser("watch", help="pantau terus-menerus + deteksi serangan real-time")
    p_watch.set_defaults(func=cmd_watch)

    p_hist = sub.add_parser("history", help="lihat riwayat kejadian/insiden")
    p_hist.add_argument("--limit", type=int, default=50, help="jumlah kejadian terakhir (default 50)")
    p_hist.set_defaults(func=cmd_history)

    p_pkt = sub.add_parser("packets", help="analisis paket: passive (psutil) atau monitor (scapy)")
    p_pkt.add_argument("mode", choices=["passive", "monitor"], help="mode analisis")
    p_pkt.add_argument("--seconds", type=int, default=15, help="[passive] durasi analisis (default 15)")
    p_pkt.add_argument("--duration", type=int, default=60, help="[monitor] durasi tangkap frame (default 60)")
    p_pkt.add_argument("--iface", type=str, default=None, help="[monitor] nama interface WiFi")
    p_pkt.set_defaults(func=cmd_packets)

    p_exp = sub.add_parser("export", help="ekspor perangkat ke CSV/JSON")
    p_exp.add_argument("--format", choices=["csv", "json"], default="csv")
    p_exp.set_defaults(func=cmd_export)

    p_clear = sub.add_parser("clear", help="hapus database & cache (buat baseline baru)")
    p_clear.set_defaults(func=cmd_clear)

    p_deps = sub.add_parser("deps", help="cek status dependensi")
    p_deps.set_defaults(func=cmd_deps)

    return p


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    _print_banner()
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
