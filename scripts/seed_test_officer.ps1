# Seeds TEST001 face template from Flutter simulator asset (for local dev check-in).
$root = Split-Path $PSScriptRoot -Parent
$src = Join-Path $root "..\police_mobile_core\assets\simulator_face.jpg"
$dest = Join-Path $root "known_faces\TEST001.jpg"

if (-not (Test-Path $src)) {
    Write-Error "Missing source image: $src"
    exit 1
}

Copy-Item -Path $src -Destination $dest -Force
Write-Host "Seeded TEST001 face template at $dest"
Write-Host "Restart the backend to reload face templates."
