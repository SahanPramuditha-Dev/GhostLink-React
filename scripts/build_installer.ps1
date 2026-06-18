param(
    [switch]$SkipFrontend
)

function Check-Command($name) {
    $cmd = Get-Command $name -ErrorAction SilentlyContinue
    return $null -ne $cmd
}

Write-Host "Starting build_installer.ps1: will produce a Windows installer for GHOSTLINK"

# 1. Ensure Python venv
if (-not (Test-Path ".venv")) {
    Write-Host "Creating virtual environment .venv..."
    python -m venv .venv
}

Write-Host "Activating virtual environment"
. .venv\Scripts\Activate.ps1

Write-Host "Upgrading pip and installing backend requirements"
python -m pip install --upgrade pip
python -m pip install -r backend\requirements.txt

# 2. Freeze backend with PyInstaller
if (-not (Check-Command pyinstaller)) {
    Write-Host "PyInstaller not found; installing into venv..."
    python -m pip install pyinstaller
}

Write-Host "Building backend executable with PyInstaller"
Push-Location backend
pyinstaller --noconfirm --onefile --add-data "..\ghostlink;ghostlink" --name main main.py
Pop-Location

# 3. Build frontend (web-radar or frontend)
if (-not $SkipFrontend) {
    if (Test-Path "web-radar") {
        Push-Location web-radar
        if (-not (Test-Path "node_modules")) {
            if (Test-Path "package-lock.json") { npm ci } else { npm install }
        }
        npm run build
        Pop-Location
    } elseif (Test-Path "frontend") {
        Push-Location frontend
        if (-not (Test-Path "node_modules")) {
            if (Test-Path "package-lock.json") { npm ci } else { npm install }
        }
        npm run build
        Pop-Location
    } else {
        Write-Host "No frontend folder found (web-radar or frontend). Skipping frontend build."
    }
}

# 4. Root npm deps and electron-builder
if (-not (Check-Command npm)) {
    Write-Error "npm not found. Install Node.js and npm from https://nodejs.org/ and re-run this script."
    exit 1
}

Write-Host "Installing root node modules (electron/electron-builder)..."
if (-not (Test-Path "node_modules")) {
    if (Test-Path "package-lock.json") { npm ci } else { npm install }
}

Write-Host "Running electron-builder to produce installer (NSIS)"

# Clean up electron-builder cache to avoid stale code-sign downloads
$cacheDir = "$env:LOCALAPPDATA\electron-builder\Cache"
if (Test-Path $cacheDir) {
    Write-Host "Cleaning electron-builder cache..."
    Remove-Item $cacheDir -Recurse -Force -ErrorAction SilentlyContinue
}

# Set environment variables to disable code signing
$env:CSC_IDENTITY_AUTO_DISCOVERY = "false"
$env:CSC_LINK = ""
$env:CSC_KEY_PASSWORD = ""
$env:WIN_CSC_LINK = ""

# Run electron-builder with environment variables set (must use & not Invoke-Expression)
Write-Host "Building installer..."
& npx --yes electron-builder --win --x64 --publish never

Write-Host "Build finished. Look in the 'dist' folder for installer artifacts."
Write-Host "If you want to include a Startup shortcut option, ensure scripts/installer.iss or NSIS config is present in your electron-builder config."

Write-Host "Done."
