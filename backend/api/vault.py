from fastapi import APIRouter, HTTPException, UploadFile, File
from fastapi.responses import PlainTextResponse
import csv
import io

router = APIRouter()

@router.get('/api/vault')
async def list_vault():
    try:
        from ghostlink.core.constants import VAULT_PATH
        from ghostlink.storage.vault import PasswordVault
        v = PasswordVault(VAULT_PATH)
        v.load()
        return v.list_entries()
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete('/api/vault/{ssid}')
async def delete_entry(ssid: str):
    try:
        from ghostlink.core.constants import VAULT_PATH
        from ghostlink.storage.vault import PasswordVault
        v = PasswordVault(VAULT_PATH)
        v.load()
        v.remove(ssid)
        return {'success': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/api/vault/clear')
async def clear_vault():
    try:
        from ghostlink.core.constants import VAULT_PATH
        from ghostlink.storage.vault import PasswordVault
        v = PasswordVault(VAULT_PATH)
        v.clear()
        return {'success': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get('/api/vault/export')
async def export_vault():
    try:
        from ghostlink.core.constants import VAULT_PATH
        from ghostlink.storage.vault import PasswordVault
        v = PasswordVault(VAULT_PATH)
        v.load()
        entries = v.list_entries()
        si = io.StringIO()
        writer = csv.writer(si)
        writer.writerow(['ssid','password','timestamp'])
        for e in entries:
            writer.writerow([e.get('ssid'), e.get('password'), e.get('timestamp')])
        return PlainTextResponse(si.getvalue(), media_type='text/csv')
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/api/vault/import')
async def import_vault(file: UploadFile = File(...)):
    try:
        content = await file.read()
        s = content.decode('utf-8')
        reader = csv.DictReader(io.StringIO(s))
        from ghostlink.core.constants import VAULT_PATH
        from ghostlink.storage.vault import PasswordVault
        v = PasswordVault(VAULT_PATH)
        v.load()
        for row in reader:
            ssid = row.get('ssid')
            pwd = row.get('password')
            if ssid and pwd:
                v.set(ssid, pwd)
        return {'success': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
