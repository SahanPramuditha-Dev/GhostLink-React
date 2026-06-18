from fastapi import APIRouter, HTTPException
from pathlib import Path
import json

router = APIRouter()

CONFIG_PATH = Path(__file__).parent.parent.parent / 'ghostlink_config.json'
DEFAULTS = {
    'threads': 2,
    'timeout': 5,
    'theme': 'dark'
}

@router.get('/api/settings')
async def get_settings():
    try:
        if not CONFIG_PATH.exists():
            return DEFAULTS
        with open(CONFIG_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.put('/api/settings')
async def put_settings(payload: dict):
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(payload, f, indent=2)
        return {'success': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/api/settings/reset')
async def reset_settings():
    try:
        with open(CONFIG_PATH, 'w', encoding='utf-8') as f:
            json.dump(DEFAULTS, f, indent=2)
        return {'success': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
