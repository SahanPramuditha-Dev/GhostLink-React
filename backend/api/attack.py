from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from threading import Thread, Event
import time
import json

router = APIRouter()

# Simple attack manager using existing BruteForceEngine
_attack_thread = None
_attack_stop = Event()
_attack_state = {
    'current_password': None,
    'attempts': 0,
    'speed': 0,
    'status': 'idle',
    'found_password': None
}

@router.post('/api/attack/start')
async def start_attack(config: dict):
    global _attack_thread, _attack_stop, _attack_state
    if _attack_thread and _attack_thread.is_alive():
        raise HTTPException(status_code=400, detail='Attack already running')
    try:
        from ghostlink.engine.attack import BruteForceEngine, shared_state
        from ghostlink.core.constants import VAULT_PATH
        from ghostlink.storage.vault import PasswordVault
        vault = PasswordVault(VAULT_PATH)
        vault.load()
        engine = BruteForceEngine(config, vault)
        _attack_stop.clear()
        _attack_state.update({'status': 'running', 'attempts': 0, 'found_password': None, 'current_password': None})
        def run_engine():
            try:
                password, attempts, elapsed, verified = engine.execute()
                _attack_state['found_password'] = password if verified else None
                _attack_state['status'] = 'finished'
            except Exception as e:
                _attack_state['status'] = 'error'
                _attack_state['error'] = str(e)
        _attack_thread = Thread(target=run_engine, daemon=True)
        _attack_thread.start()
        return {'success': True}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post('/api/attack/stop')
async def stop_attack():
    global _attack_thread
    try:
        from ghostlink.engine.attack import shared_state
        if _attack_thread and _attack_thread.is_alive():
            if hasattr(shared_state, 'request_stop'):
                shared_state.request_stop()
            return {'success': True}
        return {'success': False, 'detail': 'No attack running'}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.get('/api/attack/status')
async def get_status():
    # Try to read from shared_state if available
    try:
        from ghostlink.engine.attack import shared_state
        status = {
            'current_password': getattr(shared_state, 'current_password', None),
            'attempts': getattr(shared_state, 'attempts', 0),
            'speed': int(getattr(shared_state, 'speed', 0)),
            'status': getattr(shared_state, 'status', 'idle'),
            'found_password': getattr(shared_state, 'found_password', None)
        }
        return status
    except Exception:
        return _attack_state

# WebSocket endpoint for real-time updates
@router.websocket('/ws/attack')
async def ws_attack(ws: WebSocket):
    await ws.accept()
    try:
        while True:
            try:
                from ghostlink.engine.attack import shared_state
                data = {
                    'current_password': getattr(shared_state, 'current_password', None),
                    'attempts': getattr(shared_state, 'attempts', 0),
                    'speed': int(getattr(shared_state, 'speed', 0)),
                    'status': getattr(shared_state, 'status', 'idle'),
                    'found_password': getattr(shared_state, 'found_password', None)
                }
            except Exception:
                data = _attack_state
            await ws.send_text(json.dumps(data))
            time.sleep(0.5)
    except WebSocketDisconnect:
        return
    except Exception:
        return
