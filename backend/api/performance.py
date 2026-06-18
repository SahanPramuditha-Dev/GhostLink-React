from fastapi import APIRouter
from datetime import datetime
import psutil

router = APIRouter()
_prev_net = None

@router.get('/api/performance')
async def get_performance():
    global _prev_net
    try:
        cpu_percent = psutil.cpu_percent(interval=0.1)
        memory = psutil.virtual_memory()
        memory_percent = memory.percent
        net_io = psutil.net_io_counters()
        if _prev_net is None:
            _prev_net = net_io
            network_percent = 0
        else:
            delta_sent = net_io.bytes_sent - _prev_net.bytes_sent
            delta_recv = net_io.bytes_recv - _prev_net.bytes_recv
            # very rough normalization
            network_percent = min(100, (delta_sent + delta_recv) / 100000)
            _prev_net = net_io
        return {
            'cpu': round(cpu_percent, 1),
            'memory': round(memory_percent, 1),
            'network': round(network_percent, 1),
            'timestamp': datetime.now().isoformat()
        }
    except Exception as e:
        return { 'cpu': 0, 'memory': 0, 'network': 0, 'error': str(e) }
