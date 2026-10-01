# Jalankan NetGuard di Windows PowerShell
# Penggunaan: .\run.ps1 scan   |   .\run.ps1 watch   |   .\run.ps1 deps
Set-Location -Path $PSScriptRoot
py netguard.py @args
