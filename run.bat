@echo off
setlocal
cd /d "%~dp0"

rem Cek Python (py launcher) tersedia
py --version >nul 2>&1
if errorlevel 1 (
    echo [x] Python tidak ditemukan. Install Python 3 dari https://python.org
    pause
    exit /b 1
)

rem Bila ada argumen, jalankan langsung:  run.bat scan / list / watch / history / dst.
if not "%~1"=="" (
    py netguard.py %*
    exit /b %errorlevel%
)

:menu
cls
echo ================================================================
echo   NetGuard - Monitor & Proteksi WiFi Pribadi
echo ================================================================
echo   1. scan            Pindai perangkat terhubung + deteksi serangan
echo   2. list            Lihat daftar perangkat tersimpan
echo   3. watch           Pantau realtime + deteksi anomali
echo   4. history         Riwayat insiden / kejadian
echo   5. packets passive Deteksi port scan (tanpa admin)
echo   6. packets monitor Deteksi deauth / ARP flood (perlu Npcap)
echo   7. export          Ekspor perangkat ke CSV / JSON
echo   8. deps            Cek status dependensi
echo   9. clear           Reset database / baseline
echo   0. Keluar
echo ================================================================
set /p choice="Pilih nomor [1-9, 0=keluar]: "

if "%choice%"=="1"  py netguard.py scan
if "%choice%"=="2"  py netguard.py list
if "%choice%"=="3"  py netguard.py watch
if "%choice%"=="4"  py netguard.py history
if "%choice%"=="5"  py netguard.py packets passive
if "%choice%"=="6"  py netguard.py packets monitor
if "%choice%"=="7"  py netguard.py export
if "%choice%"=="8"  py netguard.py deps
if "%choice%"=="9"  py netguard.py clear
if "%choice%"=="0"  exit /b 0

echo.
pause
goto menu
