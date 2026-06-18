from fastapi import APIRouter

router = APIRouter()

@router.get('/api/status')
async def get_status():
    # Aggregator for dashboard
    try:
        from ghostlink.core.constants import VAULT_PATH
        from ghostlink.storage.vault import PasswordVault
        v = PasswordVault(VAULT_PATH)
        v.load()
        cached = v.get_count() if hasattr(v, 'get_count') else len(v.list_entries())
    except Exception:
        cached = 0
    # attack status
    try:
        from ghostlink.engine.attack import shared_state
        attack_status = getattr(shared_state, 'status', 'idle')
        total_attempts = getattr(shared_state, 'attempts', 0)
    except Exception:
        attack_status = 'idle'
        total_attempts = 0
    return {
        'target': None,
        'attackStatus': attack_status,
        'totalAttempts': total_attempts,
        'cachedPasswords': cached
    }
