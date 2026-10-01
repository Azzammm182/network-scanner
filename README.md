# NetGuard — Monitor & Proteksi WiFi Pribadi

Toolkit Python untuk memantau jaringan WiFi milik sendiri:

- **Daftar perangkat terhubung** — IP, MAC, hostname, vendor, status, waktu terakhir terlihat.
- **Deteksi serangan / anomali** — perangkat asing, ARP spoofing (MAC gateway berubah),
  MAC/IP ganda, IP berpindah, port scan aktif, ARP flood, dan deauth attack.
- **Riwayat kejadian** — semua insiden tercatat di database (SQLite).
- **Inspeksi paket** — mode pasif (tanpa admin) dan mode monitor (scapy + Npcap).

> **PENTING — legal:** gunakan hanya pada jaringan WiFi milik sendiri atau yang Anda
> berwenang mengujinya. Memindai/menyerang jaringan orang lain adalah ilegal.

---

## 1. Struktur Project

```
D:\project\Network\
├── netguard.py            # launcher CLI utama
├── run.bat                # shortcut Windows
├── requirements.txt
├── config.yaml            # semua pengaturan
├── README.md
├── netguard\
│   ├── __init__.py
│   ├── __main__.py
│   ├── cli.py             # semua perintah CLI
│   ├── config.py          # load config + default
│   ├── database.py        # SQLite (perangkat & riwayat)
│   ├── network.py         # info interface, subnet, gateway
│   ├── scanner.py         # ping sweep + ARP + vendor MAC
│   ├── analyzer.py        # deteksi anomali (heuristik)
│   ├── packet_capture.py  # passive (psutil) & monitor (scapy)
│   └── utils.py
└── data\                  # dibuat otomatis: netguard.db, devices.csv/json, log
```

## 2. Instalasi

```bat
cd /d D:\project\Network
py -m pip install -r requirements.txt
```

Untuk mode **monitor paket WiFi** (deauth/ARP flood) di Windows, install juga:
[Npcap](https://npcap.com) — saat instalasi **centang `Support raw 802.11 traffic`**.

> Catatan: deauth detection sempurna butuh adapter WiFi yang mendukung *monitor mode*.
> Sebagian besar deteksi (perangkat asing, ARP spoofing, port scan, IP ganda) tetap
> berjalan **tanpa** Npcap.

## 3. Penggunaan

Jalankan dari `D:\project\Network`:

**CMD (Windows) — cukup ketik nama file:**
```bat
run.bat scan
run.bat list
run.bat watch
run.bat history
run.bat packets passive
run.bat export --format csv
rem atau langsung tanpa argumen untuk menu interaktif:
run.bat
```

**PowerShell (Windows) — wajib pakai awalan `.\`:**
```powershell
.\run.bat scan
# atau pakai launcher PowerShell:
.\run.ps1 scan
```

### Daftar perintah

| Perintah                         | Fungsi                                                        |
| -------------------------------- | ------------------------------------------------------------- |
| `run.bat scan`                   | Pindai sekali + simpan + deteksi anomali                      |
| `run.bat list`                   | Tampilkan daftar perangkat tersimpan                          |
| `run.bat watch`                  | Pantau terus-menerus (realtime) + deteksi serangan            |
| `run.bat history --limit 100`    | Riwayat insiden / kejadian                                    |
| `run.bat packets passive`        | Analisis koneksi (tanpa admin) — deteksi port scan            |
| `run.bat packets monitor`        | Tangkap frame WiFi (scapy + Npcap) — deteksi deauth/ARP flood |
| `run.bat export --format csv`    | Ekspor perangkat ke `data\devices.csv` (atau `json`)          |
| `run.bat clear`                  | Hapus database & cache (baseline baru)                        |
| `run.bat deps`                   | Cek status dependensi                                         |

### Contoh alur pertama kali

```bat
cd /d D:\project\Network
run.bat scan            rem scan pertama -> jadi baseline
run.bat list            rem lihat perangkat
run.bat watch           rem pantau + deteksi realtime
```

## 4. Apa Saja yang Dideteksi?

| Deteksi              | Level     | Arti / respons yang disarankan                                              |
| -------------------- | --------- | --------------------------------------------------------------------------- |
| `PERANGKAT_BARU`     | warning   | Ada MAC baru di jaringan — cek apakah perangkat Anda; ganti password WiFi bila asing. |
| `GANTI_MAC_GATEWAY`  | critical  | MAC gateway berubah — indikasi kuat **ARP spoofing / MITM**. Segera cek.    |
| `MAC_GANDA`          | warning   | Satu MAC mengklaim banyak IP — bisa perangkat normal, bisa spoofing.        |
| `IP_GANDA`           | warning   | Dua MAC mengklaim IP sama — konflik DHCP atau upaya hijack.                 |
| `IP_BERPINDAH`       | info      | MAC pindah IP — umumnya DHCP wajar, perhatikan bila sering terjadi.         |
| `PORT_SCAN` / `PORT_SCAN_AKTIF` | warning | Satu host membuka banyak port/koneksi — ciri scanning.        |
| `ARP_FLOOD`          | warning   | Lonjakan ARP besar-besaran — ciri ARP flooding/scanning agresif.            |
| `DEAUTH_ATTACK`      | critical  | Banyak frame deauth — penyerang berusaha memutus perangkat dari WiFi.       |

Deteksi memakai **baseline**: `scan` pertama menyimpan perangkat yang dikenal.
Perangkat yang muncul setelahnya dianggap `PERANGKAT_BARU`.

## 5. Konfigurasi (`config.yaml`)

Semua nilai bisa diubah:

```yaml
monitor:
  interval: 10            # detik antar scan saat `watch`
  ping_timeout_ms: 500
  ping_workers: 64
scan:
  ping_sweep: true
  vendor_lookup: true
  resolve_hostname: true
alerts:                   # matikan jenis deteksi dengan false
  new_device: true
  gateway_mac_change: true
  duplicate_mac: true
  duplicate_ip: true
  ip_reassigned: true
packet:
  syn_port_threshold: 25
  arp_flood_threshold: 20
  deauth_threshold: 5
```

## 6. Cara Kerja Teknis

1. **Subnet & gateway** — didapat dari tabel routing & info interface OS.
2. **Ping sweep paralel** — semua host di subnet di-ping agar ARP cache terisi.
3. **Baca ARP cache** — `arp -a` (Windows) atau `/proc/net/arp` (Linux) memberi pasangan IP↔MAC.
4. **Vendor MAC** — lookup OUI via database offline `manuf`.
5. **Baseline & deteksi** — hasil dibandingkan dengan riwayat di SQLite; anomali dicatat.
6. **Inspeksi paket** — mode pasif membaca koneksi `psutil`; mode monitor menangkap frame via scapy.

## 7. Troubleshooting

| Gejala                                  | Solusi                                                                 |
| --------------------------------------- | ---------------------------------------------------------------------- |
| `Tidak bisa menentukan subnet`          | Pastikan WiFi tersambung dan perangkat punya IP valid.                  |
| Hasil scan sedikit / tidak ada          | Coba jalankan terminal sebagai **Administrator**; pastikan firewall tidak memblokir ping. |
| `scapy` error / monitor tidak jalan     | Install Npcap (centang raw 802.11) dan/atau adapter tidak support monitor mode. |
| Perangkat sendiri muncul sebagai asing  | Wajar setelah reset router/ganti perangkat. `run.bat clear` lalu `scan` untuk baseline baru. |
| `rich` tidak terinstall                 | `py -m pip install rich` (tanpa rich tetap jalan, tampilan polos).      |

## 8. Fitur Lanjutan (Tugas Project)

Ide pengembangan berikutnya:

- Auto-block MAC asing via router (perlu integrasi API router).
- Kirim notifikasi Telegram/email saat `critical` terdeteksi.
- Web dashboard (Flask/FastAPI) untuk pantau dari HP.
- Ekspor laporan PDF.
- MAC spoofing aktif (ARP reply injeksi) sebagai countermeasure riset.
- Whitelist perangkat resmi di `config.yaml`.

---

*Dibuat sebagai project edukasi keamanan jaringan. Gunakan secara bertanggung jawab.*
