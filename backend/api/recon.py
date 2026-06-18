from fastapi import APIRouter, HTTPException
import sys, io

router = APIRouter()

MODULE_MAP = {
    'full': 'full_network_recon',
    'my_device': 'scan_my_device',
    'infrastructure': 'scan_infrastructure',
    'wireless': 'scan_wireless',
    'internet': 'scan_internet_identity',
    'performance': 'scan_performance',
    'resources': 'scan_resources',
    'security': 'scan_security',
    'traffic': 'scan_traffic'
}

@router.post('/api/recon/{module_id}')
async def run_module(module_id: str):
    try:
        if module_id not in MODULE_MAP:
            raise HTTPException(status_code=400, detail='Unknown module id')
        func_name = MODULE_MAP[module_id]
        import ghostlink.network.recon as recon
        if not hasattr(recon, func_name):
            raise HTTPException(status_code=500, detail='Recon module missing')
        func = getattr(recon, func_name)
        # Capture stdout
        old_stdout = sys.stdout
        sys.stdout = io.StringIO()
        try:
            result = func()
        except TypeError:
            # some functions may expect args
            result = func()
        output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        return { 'output': output }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
