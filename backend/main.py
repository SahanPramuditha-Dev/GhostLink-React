import sys
from pathlib import Path

# Handle both development and PyInstaller bundled environments
if getattr(sys, 'frozen', False):
    # PyInstaller bundle
    ROOT = Path(sys._MEIPASS)
else:
    # Development: go up one from backend directory
    ROOT = Path(__file__).resolve().parent.parent

if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

# Import routers - use relative imports if possible for better bundling, but let's use absolute
try:
    from backend.api import scan, attack, recon, vault, admin, settings, logs, status, performance
except ImportError:
    # Try importing from the ghostlink module
    from ghostlink.api import scan, attack, recon, vault, admin, settings, logs, status, performance

app = FastAPI(title="GHOSTLINK Backend")

# CORS - allow all origins for Electron
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"]
)

# Mount routers
app.include_router(scan.router)
app.include_router(attack.router)
app.include_router(recon.router)
app.include_router(vault.router)
app.include_router(admin.router)
app.include_router(settings.router)
app.include_router(logs.router)
app.include_router(status.router)
app.include_router(performance.router)

if __name__ == '__main__':
    uvicorn.run(app, host="127.0.0.1", port=5966)
