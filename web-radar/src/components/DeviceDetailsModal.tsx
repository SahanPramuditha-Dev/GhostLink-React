import {
  Dialog,
  DialogTitle,
  DialogContent,
  IconButton,
  Typography,
  Box,
  Chip,
  Divider,
  Tooltip
} from '@mui/material'
import { X, Wifi, Server, Cpu, Smartphone, Home, Printer } from 'lucide-react'

interface Device {
  ip: string
  mac: string
  hostname: string
  manufacturer: string
  open_ports: number[]
  services: Record<number, string>
  os_guess: string
  device_type: string
  scan_time: string
}

interface DeviceDetailsModalProps {
  open: boolean
  onClose: () => void
  device: Device | null
}

export const DeviceDetailsModal = ({ open, onClose, device }: DeviceDetailsModalProps) => {
  if (!device) return null

  const getDeviceIcon = () => {
    const type = device.device_type.toLowerCase()
    if (type.includes('mobile') || type.includes('phone') || type.includes('tablet')) {
      return Smartphone
    } else if (type.includes('server') || type.includes('nas')) {
      return Server
    } else if (type.includes('printer')) {
      return Printer
    } else if (type.includes('iot') || type.includes('smart') || type.includes('embedded')) {
      return Home
    } else if (type.includes('network') || type.includes('router') || type.includes('switch')) {
      return Wifi
    }
    return Cpu
  }

  const DeviceIcon = getDeviceIcon()

  return (
    <Dialog 
      open={open} 
      onClose={onClose}
      maxWidth="md"
      fullWidth
      slotProps={{
        paper: {
          sx: {
            backgroundColor: 'rgba(15,23,42,0.98)',
            border: '1px solid rgba(0,245,255,0.2)',
            borderRadius: 3
          }
        }
      }}
    >
      <DialogTitle sx={{ 
        display: 'flex', 
        alignItems: 'center', 
        justifyContent: 'space-between',
        color: '#FFFFFF',
        pb: 2
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <DeviceIcon size={28} color="#00F5FF" />
          <Typography variant="h5" sx={{ fontWeight: 800 }}>
            {device.hostname || device.ip}
          </Typography>
        </Box>
        <IconButton onClick={onClose} sx={{ color: '#94A3B8' }}>
          <X size={20} />
        </IconButton>
      </DialogTitle>

      <Divider sx={{ backgroundColor: 'rgba(255,255,255,0.1)' }} />

      <DialogContent sx={{ pt: 3 }}>
        <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: '1fr 1fr' }, gap: 3 }}>
          {/* Basic Info */}
          <Box sx={{ p: 2, backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 2 }}>
            <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#00F5FF', mb: 2 }}>
              Basic Information
            </Typography>
            
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="#94A3B8">
                  IP Address
                </Typography>
                <Typography variant="body2" sx={{ color: '#E0E7FF', fontWeight: 600 }}>
                  {device.ip}
                </Typography>
              </Box>

              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="#94A3B8">
                  MAC Address
                </Typography>
                <Typography variant="body2" sx={{ color: '#E0E7FF', fontWeight: 600 }}>
                  {device.mac}
                </Typography>
              </Box>

              {device.hostname && (
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="body2" color="#94A3B8">
                    Hostname
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#E0E7FF', fontWeight: 600 }}>
                    {device.hostname}
                  </Typography>
                </Box>
              )}

              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="#94A3B8">
                  Device Type
                </Typography>
                <Chip 
                  label={device.device_type} 
                  size="small"
                  sx={{ 
                    backgroundColor: 'rgba(0,245,255,0.1)', 
                    color: '#00F5FF', 
                    fontWeight: 700,
                    border: '1px solid rgba(0,245,255,0.3)'
                  }}
                />
              </Box>

              {device.manufacturer !== 'Unknown' && (
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="body2" color="#94A3B8">
                    Manufacturer
                  </Typography>
                  <Typography variant="body2" sx={{ color: '#E0E7FF', fontWeight: 600 }}>
                    {device.manufacturer}
                  </Typography>
                </Box>
              )}

              {device.os_guess && (
                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                  <Typography variant="body2" color="#94A3B8">
                    OS Guess
                  </Typography>
                  <Chip 
                    label={device.os_guess} 
                    size="small"
                    sx={{ 
                      backgroundColor: 'rgba(34,197,94,0.1)', 
                      color: '#22C55E', 
                      fontWeight: 700,
                      border: '1px solid rgba(34,197,94,0.3)'
                    }}
                  />
                </Box>
              )}

              <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <Typography variant="body2" color="#94A3B8">
                  Scan Time
                </Typography>
                <Typography variant="body2" sx={{ color: '#E0E7FF' }}>
                  {new Date(device.scan_time).toLocaleString()}
                </Typography>
              </Box>
            </Box>
          </Box>

          {/* Open Ports */}
          <Box sx={{ p: 2, backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 2 }}>
            <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 2 }}>
              <Typography variant="subtitle2" sx={{ fontWeight: 700, color: '#EF4444' }}>
                Open Ports & Services
              </Typography>
              <Chip 
                label={`${device.open_ports.length} open`} 
                size="small"
                sx={{ 
                  backgroundColor: 'rgba(245,158,11,0.1)', 
                  color: '#F59E0B', 
                  fontWeight: 700,
                  border: '1px solid rgba(245,158,11,0.3)'
                }}
              />
            </Box>

            {device.open_ports.length === 0 ? (
              <Typography variant="body2" color="#64748B" sx={{ textAlign: 'center', py: 4 }}>
                No open ports detected
              </Typography>
            ) : (
              <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                {device.open_ports.map((port) => (
                  <Tooltip 
                    key={port} 
                    title={device.services[port] || `Port ${port}`} 
                    placement="top"
                  >
                    <Chip 
                      key={port}
                      label={port}
                      size="medium"
                      sx={{ 
                        backgroundColor: 'rgba(239,68,68,0.1)', 
                        color: '#EF4444', 
                        fontWeight: 700,
                        border: '1px solid rgba(239,68,68,0.3)',
                        cursor: 'pointer',
                        '&:hover': {
                          backgroundColor: 'rgba(239,68,68,0.2)'
                        }
                      }}
                    />
                  </Tooltip>
                ))}
              </Box>
            )}
          </Box>
        </Box>
      </DialogContent>
    </Dialog>
  )
}


