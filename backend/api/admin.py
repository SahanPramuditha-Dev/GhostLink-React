from fastapi import APIRouter
from ghostlink.core.utils import is_admin

router = APIRouter()

@router.get('/api/admin')
async def get_admin():
    return { 'isAdmin': is_admin() }
