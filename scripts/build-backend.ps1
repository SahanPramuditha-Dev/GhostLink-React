# Build Backend Script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$ProjectRoot = Split-Path -Parent $ScriptDir
$BackendDir = Join-Path $ProjectRoot "backend"

Set-Location $BackendDir

Write-Host "Cleaning previous builds..."
Remove-Item -Path build -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path dist -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path main.spec -Force -ErrorAction SilentlyContinue

Write-Host "Building backend EXE..."
pyinstaller --name=main --onefile --noconsole --add-data "..\ghostlink;ghostlink" ..\ghostlink\api\server.py
Write-Host "Backend build complete!"
