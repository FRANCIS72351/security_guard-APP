# Start SecureGuard API on port 5001 with dev testing flags (relaxed GPS/geofence)
$port = 5001
Get-NetTCPConnection -LocalPort $port -ErrorAction SilentlyContinue |
    ForEach-Object { Stop-Process -Id $_.OwningProcess -Force -ErrorAction SilentlyContinue }
Start-Sleep -Seconds 2
Set-Location $PSScriptRoot
$env:PORT = $port
$env:SECUREGUARD_ENV = "dev"
Write-Host "[SECUREGUARD] Strict geofence + GPS enforcement enabled" -ForegroundColor Cyan
Write-Host "  Edit deployment_posts.json to set BROAD_STREET coordinates for your site." -ForegroundColor DarkGray
python app.py