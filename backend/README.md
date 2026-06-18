Backend build and run

Run the FastAPI backend for development:

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
python backend\main.py
```

Freeze backend into single exe with PyInstaller (packaging step):

```powershell
cd backend
pyinstaller --name=main --onefile --add-data="ghostlink;ghostlink" main.py
```

Notes:
- The `--add-data` flag includes the `ghostlink` package data for runtime.
- The produced executable will be at `backend\dist\main.exe`.
- The Electron build uses `backend/dist/main.exe` as an extra resource and places it under `resources/backend/main.exe` in the packaged app.
