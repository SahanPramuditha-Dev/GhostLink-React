from fastapi import APIRouter, HTTPException
from fastapi.responses import PlainTextResponse
from pathlib import Path
import json

router = APIRouter()
LOG_FILE = Path(__file__).parent.parent.parent / 'logs' / 'ghostlink.jsonl'

@router.get('/api/logs/tail')
async def tail_logs(lines: int = 100):
    try:
        if not LOG_FILE.exists():
            return []
        with open(LOG_FILE, 'r', encoding='utf-8') as f:
            all_lines = f.readlines()
        last = all_lines[-lines:]
        items = [json.loads(l) for l in last if l.strip()]
        return items
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/api/logs/export')
async def export_logs(filter: dict = None):
    try:
        dest = Path('logs') / f'export-{int(time.time())}.jsonl'
        # Very simple export: copy file
        if LOG_FILE.exists():
            with open(LOG_FILE, 'r', encoding='utf-8') as src, open(dest, 'w', encoding='utf-8') as dst:
                for l in src:
                    dst.write(l)
            return {'path': str(dest)}
        return {'path': None}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
