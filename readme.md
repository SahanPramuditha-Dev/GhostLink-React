# GHOSTLINK

Wi-Fi security testing framework for authorized lab and internal security assessment environments.

## Important Notice
Use this project only on networks you own or have explicit permission to test.

## Interfaces
GHOSTLINK currently provides both CLI and GUI workflows.

> Run commands from the project root (the folder that contains `run.py`, `run_gui.py`, `requirements.txt`, and `ghostlink/`).

### GUI
- (Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned) ; (& "c:\D\Projects\Python\Wifi Hacker\GhostLink\.venv\Scripts\Activate.ps1")
- Entry point: `run_gui.py`
- Main window module: `ghostlink/gui/main_window.py`
- UI tabs include scan, attack configuration, progress, and recon views.

Run GUI from source:

```bash
python run_gui.py
```

If you packaged the app, use the executable from `dist/GHOSTLINK/`.

### CLI
- Entry point: `run.py`
- Main logic: `ghostlink/main.py`

Get CLI help (all supported flags):

```bash
python run.py --help
```

Interactive mode (prompts you for configuration):

```bash
python run.py
```

Non-interactive example (target + attack settings):

```bash
python run.py --ssid "MyWiFi" --profile 1 --minlen 4 --maxlen 8 --threads 2
```

Admin requirement:
- The CLI checks for Administrator privileges.
- Run as Administrator **or** pass `--force` (use with caution).


## Installation

### Option 1: Run from source
1. Install Python 3.9+.
2. Clone the repository.
3. Install dependencies.
4. Start with `python run_gui.py` (GUI) or `python run.py` (CLI).

```bash
git clone <your-repo-url>
cd GhostLink
pip install -r requirements.txt
```

Note: `requirements.txt` includes the current runtime dependencies. Some entries are optional (for extra dashboard and speed-test features), so you can trim them for minimal installs.

### Option 2: Portable packaged app (no installer)
- Build output folder: `dist/GHOSTLINK/`
- Launch executable directly:

```text
dist/GHOSTLINK/GHOSTLINK.exe
```

### Option 3: Windows installer
- Installer file: `GHOSTLINK_Setup.exe`
- Installs app to `Program Files\GHOSTLINK`
- Creates desktop and Start Menu shortcuts
- Registers uninstall entry in Windows

## Setup and Build Files
These files control packaging and installation:

- `GHOSTLINK.spec`: PyInstaller definition used to package the GUI app (`run_gui.py`) into `dist/GHOSTLINK`.
- `installer.nsi`: NSIS installer script used to generate `GHOSTLINK_Setup.exe` from `dist/GHOSTLINK`.
- `ghostlink.ico`: App icon used in packaged builds.
- `build/`: PyInstaller intermediate artifacts.
- `dist/`: Final distributable output.

Build and docs helpers:

- `scripts/build.ps1`: builds `dist/GHOSTLINK` from `GHOSTLINK.spec` (supports `-Clean`, `-InstallDeps`).
- `scripts/installer.ps1`: builds `GHOSTLINK_Setup.exe` via NSIS (supports `-SkipBuild`).
- `docs/build-guide.md`: full packaging and installer guide.
- `docs/commands.md`: runtime and build command reference.

## Manual Build Steps
If you want to regenerate installer files:

1. Package app with PyInstaller:

```bash
pyinstaller GHOSTLINK.spec
```

2. Build installer with NSIS:

```bash
makensis installer.nsi
```

Output expected:
- `dist/GHOSTLINK/GHOSTLINK.exe`
- `GHOSTLINK_Setup.exe`

## Repository Layout (key parts)

```text
ghostlink/
  core/
  engine/
  network/
  storage/
  cli/
  gui/
  dashboard/

run.py
run_gui.py
GHOSTLINK.spec
installer.nsi
GHOSTLINK_Setup.exe
dist/
build/
```

## Security and Ethics
Allowed:
- personal lab testing
- internal authorized assessments
- educational security research

Not allowed:
- unauthorized network access
- testing public or third-party networks without permission

## Author
Sahan Pramuditha
