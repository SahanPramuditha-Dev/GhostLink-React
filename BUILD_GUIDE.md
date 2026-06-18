# GHOSTLINK Build Guide

This guide will walk you through building the GHOSTLINK installable software from scratch.

## Prerequisites

Make sure you have these installed:
- **Node.js** (v18 or later)
- **Python** (3.10 or later)
- **npm** (comes with Node.js)

---

## Quick Start (One-Step Commands)

For a faster build process, use these convenient npm scripts:

### 1. Install all dependencies (once)
```powershell
npm run install-all
```
**What it does**: Installs all root, frontend, and backend dependencies in one command.

### 2. Build everything (full installer)
```powershell
# First activate your venv if not already active
.\.venv\Scripts\Activate.ps1
# Disable code signing
$env:CSC_IDENTITY_AUTO_DISCOVERY="false"
# Then run the full build
npm run build
```
**What it does**:
- Builds the frontend
- Cleans and builds the backend EXE
- Creates the Electron installer

---

## Step 1: Initial Setup

### 1.1 Navigate to the project directory
```powershell
cd "c:\D\Projects\Python\Wifi Hacker\GhostLink React Version"
```

### 1.2 Install root Node.js dependencies
```powershell
npm install
```
**What it does**: Installs Electron, electron-builder, and other main Electron dependencies.

---

## Step 2: Frontend Setup (Web-Radar)

### 2.1 Navigate to the web-radar directory
```powershell
cd web-radar
```

### 2.2 Install web-radar dependencies
```powershell
npm install
```
**What it does**: Installs React, Vite, Material-UI, and other frontend dependencies.

### 2.3 Build the frontend
```powershell
npm run build
```
**What it does**: Compiles the React/Vite app into static HTML/CSS/JS files in the `web-radar/dist/` directory.

---

## Step 3: Backend Setup

### 3.1 Navigate back to the project root
```powershell
cd ..
```

### 3.2 Create a Python virtual environment
```powershell
python -m venv .venv
```
**What it does**: Creates an isolated Python environment to manage dependencies without conflicting with system-wide packages.

### 3.3 Activate the virtual environment
```powershell
.\.venv\Scripts\Activate.ps1
```
**What it does**: Activates the virtual environment, so all subsequent Python commands use this environment.

### 3.4 Install backend dependencies
```powershell
pip install -r backend\requirements.txt
```
**What it does**: Installs FastAPI, Uvicorn, psutil, reportlab, PyInstaller, and other Python dependencies.

---

## Step 4: Build the Backend EXE

### Option 1: Use the npm script (recommended)
```powershell
# Navigate to project root if not already there
cd "c:\D\Projects\Python\Wifi Hacker\GhostLink React Version"
npm run build-backend
```
**What it does**: Cleans previous builds and builds the backend EXE in one command.

### Option 2: Manual build
### 4.1 Navigate to the backend directory
```powershell
cd backend
```

### 4.2 Clean any previous builds (optional but recommended)
```powershell
Remove-Item -Path build -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path dist -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path main.spec -Force -ErrorAction SilentlyContinue
```

### 4.3 Build the backend EXE
```powershell
pyinstaller --name=main --onefile --add-data "..\ghostlink;ghostlink" ..\ghostlink\api\server.py
```
**What it does**:
- `--name=main`: Names the output file `main.exe`
- `--onefile`: Packages everything into a single executable
- `--add-data "..\ghostlink;ghostlink"`: Includes the ghostlink module (the actual backend logic)
- `..\ghostlink\api\server.py`: The entry point for the backend server

The built EXE will be in `backend/dist/main.exe`.

---

## Step 5: Prepare the Icon (Optional but recommended)

### 5.1 Generate the ICO file from the logo
If you've already installed backend requirements, Pillow is already installed!
```powershell
cd "c:\D\Projects\Python\Wifi Hacker\GhostLink React Version"
python scripts\create_icon.py
```
**What it does**: Converts `scripts/icon.png` into `scripts/ghostlink.ico` with multiple sizes (256x256, 128x128, etc.) for Windows.

---

## Step 6: Build the Electron Installer

### Option 1: Use the full npm script (recommended, builds everything)
See the Quick Start section above for `npm run build`.

### Option 2: Manual build
### 6.1 Disable code signing (optional, for development builds)
```powershell
$env:CSC_IDENTITY_AUTO_DISCOVERY="false"
```
**What it does**: Prevents Electron from trying to sign the installer (which requires a certificate).

### 6.2 Build the installer
```powershell
npx electron-builder --win --x64 --publish never
```
**What it does**:
- Uses electron-builder to package the app
- Targets Windows x64
- Creates an NSIS installer
- Does not publish to any distribution platform

The final installer will be in `release-final/GHOSTLINK Setup 1.0.0.exe`.

---

## Project Structure Recap

Here's what each directory does:
- **web-radar/**: The React/Vite frontend
  - `src/`: Source files
  - `dist/`: Build output (static files)
- **ghostlink/**: The Python backend source code
  - `api/`: FastAPI routes and server
  - `storage/`: Data storage for logs/vault/reports
- **backend/**: Contains the build script for the backend EXE
  - `dist/`: Where the main.exe is built
- **electron/**: Electron main process code
  - `main.js`: Entry point for the Electron app
- **scripts/**: Helper scripts (like creating the icon)
- **package.json**: Project configuration
- **release-final/**: Where the final installers are saved

---

## Troubleshooting

### Issue: "ModuleNotFoundError" when running main.exe
**Fix**: Make sure you have the correct virtual environment activated, and you've installed all requirements.

### Issue: "resource busy or locked" when running electron-builder
**Fix**: Kill any running GHOSTLINK processes:
```powershell
Get-Process -Name "GHOSTLINK", "main" -ErrorAction SilentlyContinue | Stop-Process -Force
```

### Issue: Can't clear the logs
**Fix**: We've already removed the mock logs in Logs.tsx, so the clear button should now work properly!

---

## Final Installer

After completing all steps, you can find your final installable app at:
`release-final/GHOSTLINK Setup 1.0.0.exe`
