from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter()

class ScanResult(BaseModel):
    ssid: str
    signal: int
    security: str

@router.post('/api/scan')
async def do_scan():
    try:
        from ghostlink.network.scanner import WiFiScanner
        scanner = WiFiScanner()
        results = scanner.scan()
        out = []
        for r in results:
            out.append({ 'ssid': r.ssid, 'signal': r.signal, 'security': r.security })
        return { 'networks': out }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
