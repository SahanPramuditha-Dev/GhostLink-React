Param(
    [string]$venvPath = ".venv",
    [string]$exeName = "ghostlink"
)

Set-StrictMode -Version Latest

# Create venv if missing
if (!(Test-Path $venvPath)) {
    Write-Host "Creating virtual environment at $venvPath..."
    python -m venv $venvPath
}

# Ensure PyInstaller is installed
& "$venvPath\Scripts\python" -m pip install --upgrade pip setuptools wheel pyinstaller
& "$venvPath\Scripts\python" -m pip install pystray pillow

# Build frontend
Write-Host "Building frontend (web-radar)..."
Push-Location "web-radar"
if (!(Test-Path "node_modules")) {
    npm ci
}
npm run build
Pop-Location

# Build standalone backend executable with embedded static files
Write-Host "Running PyInstaller to build standalone executable..."
$distPath = Join-Path (Resolve-Path .).Path "web-radar\dist"
$addData = "$distPath;web-radar/dist"
# Use icon if available
$iconPath = "scripts\ghostlink.ico"
$iconArg = ""
if (Test-Path $iconPath) {
    $iconArg = "--icon $iconPath"
    Write-Host "Using icon: $iconPath"
} else {
    # If a source PNG exists, generate ICO using Pillow
    $pngPath = "scripts\icon.png"
    if (Test-Path $pngPath) {
        Write-Host "Found placeholder PNG at $pngPath. Generating ICO..."
        & "$venvPath\Scripts\python" "scripts\create_icon.py"
        if (Test-Path $iconPath) {
            $iconArg = "--icon $iconPath"
            Write-Host "Generated ICO at $iconPath"
        }
    } else {
        Write-Host "No icon found at $iconPath or $pngPath. Building without icon."
    }
}

# Build server exe
& "$venvPath\Scripts\pyinstaller.exe" --noconfirm --onefile --add-data $addData --name $exeName $iconArg ghostlink\api\server.py

# Build launcher exe (system tray)
$launcherName = "ghostlink-launcher"
& "$venvPath\Scripts\pyinstaller.exe" --noconfirm --onefile --add-data $addData --name $launcherName $iconArg ghostlink\launcher.py

Write-Host "Build complete. Executable located at dist\$exeName.exe"
Write-Host "Launcher executable located at dist\$launcherName.exe"

# Optionally compile Inno Setup if ISCC.exe is available
$isccPath = "C:\\Program Files (x86)\\Inno Setup 6\\ISCC.exe"
if (Test-Path $isccPath) {
    Write-Host "Found Inno Setup compiler at $isccPath. Compiling installer..."
    & $isccPath "scripts\installer.iss"
    Write-Host "Installer build complete."
} else {
    Write-Host "Inno Setup compiler not found at $isccPath. Skipping automatic installer compilation."
}
