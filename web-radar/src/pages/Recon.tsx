import { useState, useMemo } from 'react'
import {
  Play,
  Eye,
  Wifi,
  Activity,
  Lock,
  Shield,
  Terminal,
  CheckCircle2,
  AlertCircle,
  XCircle,
  Info,
  Globe,
  Zap,
  Cpu,
  Download,
  Search,
  FileJson,
  FileSpreadsheet,
  FileText
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { useApi } from '../hooks/useApi'
import {
  Container,
  Typography,
  Paper,
  Button as MuiButton,
  Box,
  Alert,
  LinearProgress,
  CircularProgress,
  Tabs,
  Tab,
  Chip,
  TextField,
  InputAdornment,
  Menu,
  MenuItem
} from '@mui/material'
import { runReconModule } from '../api'
import { DeviceDetailsModal } from '../components'
import { AnsiUp } from 'ansi_up'

// --- Types ---
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
interface NetworkInfo {
  local_ip: string
  gateway: string
  subnet_mask: string
  cidr_prefix: number
  network_cidr: string | null
}
interface InterfaceInfo {
  name: string
  ipv4: string
  ipv4_prefix: number
  ipv6: string
  mac: string
  state: string
  type: string
  dhcp: boolean
  dhcp_server: string
  dhcp_lease_obtained: string
  dhcp_lease_expires: string
  dns_servers: string[]
  dns_suffix: string
  profile: string
  speed: string
  mtu: number
}
interface ConnectionInfo {
  protocol: string
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  state: string
  pid: number
  process: string
}
interface WirelessNetwork {
  ssid: string
  bssid: string
  channel: number
  band: string
  signal: number
  security: string
  authentication: string
  encryption: string
  connected: boolean
  signal_dbm: number
  frequency: number
}
interface DnsTestResult {
  domain: string
  ip: string
  latency_ms: number
  success: boolean
}
interface PingTestResult {
  label: string
  host: string
  latency_ms: number
  error: boolean
}
interface RiskyPort {
  port: number
  description: string
}
interface RiskyDevice {
  ip: string
  hostname: string
  manufacturer: string
  risky_ports: RiskyPort[]
}
interface UnknownDevice {
  ip: string
  mac: string
  hostname: string
}
interface ConnectionBreakdown {
  external_ips: string[]
  local_ips: string[]
}
interface ModuleResult {
  output: string
  structured?: {
    // Full recon
    network?: NetworkInfo
    devices?: Device[]
    scan_duration?: number
    errors?: string[]
    
    // My device
    hostname?: string
    fqdn?: string
    platform?: string
    python_version?: string
    interfaces?: InterfaceInfo[]
    connections?: ConnectionInfo[]
    
    // Infrastructure
    gateway_alive?: boolean
    dhcp_range?: { start: string; end: string }
    traceroute?: string[]
    nat_info?: string
    
    // Wireless
    connected?: WirelessNetwork
    visible?: WirelessNetwork[]
    channel_counts?: Record<number | string, number>
    
    // Internet
    public_ip?: any
    dns_tests?: DnsTestResult[]
    
    // Performance
    ping_tests?: PingTestResult[]
    path_mtu?: number
    
    // Security
    wireless_security?: { ssid: string; authentication: string; encryption: string }
    risky_ports?: RiskyDevice[]
    unknown_devices?: UnknownDevice[]
    
    // Traffic
    connection_breakdown?: ConnectionBreakdown
    interface_stats?: any
  } | null
}

// --- Main Component ---
function Recon() {
  const { setSnackbar } = useAppContext()
  const { loading, execute } = useApi<ModuleResult>()
  const [output, setOutput] = useState<string>('')
  const [structured, setStructured] = useState<ModuleResult['structured']>(null)
  const [currentModule, setCurrentModule] = useState<string>('')
  const [activeTab, setActiveTab] = useState<number>(0)
  const [searchQuery, setSearchQuery] = useState<string>('')
  const [selectedDevice, setSelectedDevice] = useState<Device | null>(null)
  const [exportMenuAnchor, setExportMenuAnchor] = useState<null | HTMLElement>(null)

  const ansiUp = useMemo(() => new AnsiUp(), []);

  // Filter devices based on search query
  const filteredDevices = useMemo(() => {
    if (!structured?.devices) return []
    if (!searchQuery.trim()) return structured.devices
    const query = searchQuery.toLowerCase()
    return structured.devices.filter(device => 
      device.ip.toLowerCase().includes(query) ||
      (device.hostname && device.hostname.toLowerCase().includes(query)) ||
      (device.mac && device.mac.toLowerCase().includes(query)) ||
      (device.manufacturer && device.manufacturer.toLowerCase().includes(query)) ||
      (device.device_type && device.device_type.toLowerCase().includes(query)) ||
      device.open_ports.some(port => port.toString().includes(query))
    )
  }, [structured?.devices, searchQuery])
  
  const modules = [
    { id: 'full', name: 'Full Recon', icon: Eye },
    { id: 'my_device', name: 'My Device', icon: Activity },
    { id: 'infrastructure', name: 'Infrastructure', icon: Lock },
    { id: 'wireless', name: 'Wireless', icon: Wifi },
    { id: 'internet', name: 'Internet', icon: Globe },
    { id: 'performance', name: 'Performance', icon: Zap },
    { id: 'resources', name: 'Resources', icon: Cpu },
    { id: 'security', name: 'Security', icon: Shield },
    { id: 'traffic', name: 'Traffic', icon: Activity }
  ]

  const handleRunModule = async (moduleId: string) => {
    setCurrentModule(moduleId)
    try {
      const moduleData = await execute(() => runReconModule(moduleId))
      if (moduleData) {
        setOutput(moduleData.output)
        setStructured(moduleData.structured || null)
        setSnackbar({
          open: true,
          message: `${modules.find(m => m.id === moduleId)?.name} completed!`,
          severity: 'success'
        })
      }
    } catch (err) {
      console.error(`[Recon] Error running ${moduleId}:`, err)
    }
  }

  const handleRunAll = async () => {
    setOutput('')
    for (let i = 0; i < modules.length; i++) {
      const mod = modules[i]
      setCurrentModule(mod.id)
      try {
        const moduleData = await execute(() => runReconModule(mod.id))
        if (moduleData) {
          setOutput(prev => `${prev}\n\n===== ${mod.name} =====\n${moduleData.output}`)
        }
      } catch (err) {
        console.error(`[Recon] Error running ${mod.id}:`, err)
      }
      await new Promise(r => setTimeout(r, 300))
    }
    setSnackbar({
      open: true,
      message: 'All modules completed!',
      severity: 'success'
    })
  }

  const exportToJSON = () => {
    const data = structured || { raw: output }
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ghostlink-recon-${currentModule || 'all'}-${new Date().toISOString().replace(/[:.]/g, '-')}.json`
    a.click()
    URL.revokeObjectURL(url)
    setSnackbar({ open: true, message: 'JSON export successful!', severity: 'success' })
  }

  const exportToCSV = () => {
    let csv = ''
    // If we have devices (from full recon or security), export those
    if (structured?.devices && structured.devices.length > 0) {
      const headers = Object.keys(structured.devices[0])
      csv = headers.join(',') + '\n'
      structured.devices.forEach((device: any) => {
        const values = headers.map(key => {
          let val = device[key]
          if (Array.isArray(val)) val = val.join(';')
          if (typeof val === 'object') val = JSON.stringify(val)
          if (typeof val === 'string' && (val.includes(',') || val.includes('"'))) {
            val = `"${val.replace(/"/g, '""')}"`
          }
          return val ?? ''
        })
        csv += values.join(',') + '\n'
      })
    } else {
      // Otherwise, export structured data as flattened CSV
      const flatten = (obj: any, prefix: string = ''): any => {
        let result: any = {}
        for (const [key, value] of Object.entries(obj)) {
          const newKey = prefix ? `${prefix}_${key}` : key
          if (value && typeof value === 'object' && !Array.isArray(value)) {
            result = { ...result, ...flatten(value, newKey) }
          } else if (Array.isArray(value)) {
            result[newKey] = value.join(';')
          } else {
            result[newKey] = value
          }
        }
        return result
      }
      const flat = flatten(structured || { raw: output })
      const headers = Object.keys(flat)
      csv = headers.join(',') + '\n'
      csv += headers.map(h => {
        let val = flat[h]
        if (typeof val === 'string' && (val.includes(',') || val.includes('"'))) {
          val = `"${val.replace(/"/g, '""')}"`
        }
        return val ?? ''
      }).join(',')
    }
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ghostlink-recon-${currentModule || 'all'}-${new Date().toISOString().replace(/[:.]/g, '-')}.csv`
    a.click()
    URL.revokeObjectURL(url)
    setSnackbar({ open: true, message: 'CSV export successful!', severity: 'success' })
  }

  const exportToTXT = () => {
    const blob = new Blob([output], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ghostlink-recon-${currentModule || 'all'}-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`
    a.click()
    URL.revokeObjectURL(url)
    setSnackbar({ open: true, message: 'TXT export successful!', severity: 'success' })
  }

  return (
    <Container maxWidth="xl" disableGutters sx={{ p: 3 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h3" component="h1" sx={{ fontWeight: 800, color: '#FFFFFF', mb: 1 }}>
          Reconnaissance
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Run network intelligence modules
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', gap: 3, flexWrap: 'wrap' }}>
        {/* Left Sidebar - Modules */}
        <Box sx={{ width: { xs: '100%', lg: '280px' }, flexShrink: 0 }}>
          <Paper
            sx={{
              backgroundColor: 'rgba(15,23,42,0.9)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 3,
              p: 2.5
            }}
          >
            <Typography variant="h6" sx={{ color: '#F8FAFC', fontWeight: 600, mb: 2 }}>
              Modules
            </Typography>
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.25 }}>
              {modules.map((mod) => {
                const Icon = mod.icon
                const isActive = currentModule === mod.id
                return (
                  <MuiButton
                    key={mod.id}
                    variant={isActive ? 'contained' : 'outlined'}
                    fullWidth
                    onClick={() => handleRunModule(mod.id)}
                    disabled={loading}
                    startIcon={<Icon size={18} />}
                    sx={{
                      justifyContent: 'flex-start',
                      textTransform: 'none',
                      fontWeight: isActive ? 700 : 500,
                      py: 1.25,
                      borderRadius: 1.5,
                      borderColor: isActive ? 'rgba(0,245,255,0.8)' : 'rgba(0,245,255,0.3)',
                      backgroundColor: isActive ? '#00F5FF20' : 'transparent',
                      color: isActive ? '#00F5FF' : '#94A3B8',
                      boxShadow: isActive ? '0 0 20px rgba(0,245,255,0.3)' : 'none',
                      '&:hover': {
                        backgroundColor: isActive ? '#00F5FF30' : 'rgba(0,245,255,0.08)',
                        borderColor: 'rgba(0,245,255,0.5)'
                      },
                      '&.Mui-disabled': {
                        backgroundColor: 'rgba(255,255,255,0.03)',
                        color: 'rgba(255,255,255,0.2)'
                      }
                    }}
                  >
                    {isActive && loading ? (
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        <CircularProgress size={16} sx={{ color: '#00F5FF' }} />
                        Running...
                      </Box>
                    ) : (
                      mod.name
                    )}
                  </MuiButton>
                )
              })}
            </Box>

            <Box sx={{ mt: 2.5, display: 'flex', flexDirection: 'column', gap: 1.5 }}>
              <MuiButton
                variant="contained"
                color="primary"
                fullWidth
                size="large"
                startIcon={<Play size={20} />}
                onClick={handleRunAll}
                disabled={loading}
                sx={{
                  py: 1.5,
                  fontWeight: 600,
                  borderRadius: 1.5,
                  textTransform: 'none',
                  background: 'linear-gradient(135deg, #06B6D4 0%, #00F5FF 100%)',
                  '&:hover': {
                    background: 'linear-gradient(135deg, #0891B2 0%, #06B6D4 100%)'
                  }
                }}
              >
                Run All Modules
              </MuiButton>
              {output && (
                <>
                  <MuiButton
                    variant="outlined"
                    fullWidth
                    size="large"
                    startIcon={<Download size={20} />}
                    onClick={(e) => setExportMenuAnchor(e.currentTarget)}
                    disabled={loading}
                    sx={{
                      py: 1.5,
                      fontWeight: 600,
                      borderRadius: 1.5,
                      textTransform: 'none',
                      borderColor: 'rgba(168,85,247,0.5)',
                      color: '#A855F7',
                      '&:hover': {
                        backgroundColor: 'rgba(168,85,247,0.1)',
                        borderColor: '#A855F7'
                      }
                    }}
                  >
                    Export Report
                  </MuiButton>
                  <Menu
                    anchorEl={exportMenuAnchor}
                    open={Boolean(exportMenuAnchor)}
                    onClose={() => setExportMenuAnchor(null)}
                    slotProps={{
                      paper: {
                        sx: {
                          backgroundColor: 'rgba(15,23,42,0.95)',
                          border: '1px solid rgba(0,245,255,0.2)',
                          borderRadius: 2
                        }
                      }
                    }}
                  >
                    <MenuItem
                      onClick={() => {
                        exportToJSON()
                        setExportMenuAnchor(null)
                      }}
                      sx={{ color: '#E2E8F0' }}
                    >
                      <Box sx={{ mr: 1.5, color: '#06B6D4' }}>
                        <FileJson size={18} />
                      </Box>
                      Export as JSON
                    </MenuItem>
                    <MenuItem
                      onClick={() => {
                        exportToCSV()
                        setExportMenuAnchor(null)
                      }}
                      sx={{ color: '#E2E8F0' }}
                    >
                      <Box sx={{ mr: 1.5, color: '#22C55E' }}>
                        <FileSpreadsheet size={18} />
                      </Box>
                      Export as CSV
                    </MenuItem>
                    <MenuItem
                      onClick={() => {
                        exportToTXT()
                        setExportMenuAnchor(null)
                      }}
                      sx={{ color: '#E2E8F0' }}
                    >
                      <Box sx={{ mr: 1.5, color: '#94A3B8' }}>
                        <FileText size={18} />
                      </Box>
                      Export as TXT
                    </MenuItem>
                  </Menu>
                </>
              )}
            </Box>
          </Paper>
        </Box>

        {/* Main Content - Output */}
        <Box sx={{ flex: 1, minWidth: 0 }}>
          {loading && (
            <Box sx={{ mb: 2 }}>
              <LinearProgress
                sx={{
                  height: 6,
                  borderRadius: 3,
                  backgroundColor: 'rgba(0,0,0,0.3)',
                  '& .MuiLinearProgress-bar': {
                    background: 'linear-gradient(90deg, #06B6D4, #00F5FF)'
                  }
                }}
              />
            </Box>
          )}

          <Paper
            sx={{
              backgroundColor: 'rgba(15,23,42,0.95)',
              border: '1px solid rgba(255,255,255,0.08)',
              borderRadius: 3,
              height: 'calc(100vh - 200px)',
              display: 'flex',
              flexDirection: 'column'
            }}
          >
            {/* Tabs */}
            {output && (
              <Box sx={{ borderBottom: '1px solid rgba(255,255,255,0.08)' }}>
                <Tabs
                  value={activeTab}
                  onChange={(_, newValue) => setActiveTab(newValue)}
                  sx={{
                    '& .MuiTabs-indicator': {
                      backgroundColor: '#00F5FF'
                    },
                    '& .MuiTab-root': {
                      textTransform: 'none',
                      fontWeight: 600,
                      color: '#94A3B8',
                      '&.Mui-selected': {
                        color: '#00F5FF'
                      }
                    }
                  }}
                >
                  <Tab
                    label="Structured View"
                    icon={<Terminal size={16} />}
                    iconPosition="start"
                  />
                  <Tab
                    label="Raw View"
                    icon={<Info size={16} />}
                    iconPosition="start"
                  />
                </Tabs>
              </Box>
            )}

            {/* Content Area */}
            <Box sx={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
              {!output && (
                <Box sx={{ p: 4, textAlign: 'center' }}>
                  <Alert
                    severity="info"
                    sx={{
                      backgroundColor: 'rgba(6, 182, 212, 0.05)',
                      border: '1px dashed rgba(0, 245, 255, 0.3)',
                      borderRadius: '8px',
                      color: '#5EEAD4'
                    }}
                  >
                    Run a module to see output here!
                  </Alert>
                </Box>
              )}

              {output && activeTab === 0 && (
                <Box
                  sx={{
                    flex: 1,
                    overflowY: 'auto',
                    p: 3,
                    background: 'linear-gradient(180deg, #020617 0%, #0f172a 100%)',
                    lineHeight: 1.6,
                    position: 'relative',
                    '&::before': {
                      content: '""',
                      position: 'absolute',
                      top: 0,
                      left: 0,
                      right: 0,
                      height: '2px',
                      background: 'linear-gradient(90deg, transparent, #00F5FF, transparent)'
                    },
                    '&::-webkit-scrollbar': {
                      width: '8px'
                    },
                    '&::-webkit-scrollbar-track': {
                      background: 'rgba(0, 0, 0, 0.2)',
                      borderRadius: '4px'
                    },
                    '&::-webkit-scrollbar-thumb': {
                      background: 'linear-gradient(180deg, #00F5FF, #06B6D4)',
                      borderRadius: '4px'
                    }
                  }}
                >
                  {/* Display structured data if available, else ANSI */}
                  {structured ? (
                    <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
                      {/* Full Recon - Network Info */}
                      {structured.network && (
                        <Paper
                          sx={{
                            p: 3,
                            borderRadius: 2,
                            backgroundColor: 'rgba(0,245,255,0.05)',
                            border: '1px solid rgba(0,245,255,0.2)'
                          }}
                        >
                          <Typography variant="h6" sx={{ color: '#00F5FF', fontWeight: 700, mb: 2 }}>
                            Network Info
                          </Typography>
                          <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' }, gap: 2 }}>
                            <Box>
                              <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                Local IP
                              </Typography>
                              <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                {structured.network.local_ip || 'N/A'}
                              </Typography>
                            </Box>
                            <Box>
                              <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                Gateway
                              </Typography>
                              <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                {structured.network.gateway || 'N/A'}
                              </Typography>
                            </Box>
                            <Box>
                              <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                Subnet Mask
                              </Typography>
                              <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                {structured.network.subnet_mask || 'N/A'}
                              </Typography>
                            </Box>
                            <Box>
                              <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                CIDR Block
                              </Typography>
                              <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                {structured.network.network_cidr || 'N/A'}
                              </Typography>
                            </Box>
                          </Box>
                        </Paper>
                      )}

                      {/* Full Recon - Devices */}
                      {structured.devices && structured.devices.length > 0 && (
                        <Box>
                          <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, justifyContent: 'space-between', alignItems: { xs: 'stretch', sm: 'center' }, gap: 2, mb: 2 }}>
                            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                              <Typography variant="h6" sx={{ color: '#00F5FF', fontWeight: 700 }}>
                                Discovered Devices ({filteredDevices.length}{filteredDevices.length !== structured.devices.length ? ` of ${structured.devices.length}` : ''})
                              </Typography>
                              {structured.scan_duration && (
                                <Chip
                                  label={`Scan took ${structured.scan_duration.toFixed(2)}s`}
                                  sx={{ backgroundColor: 'rgba(139, 92, 246, 0.1)', color: '#8B5CF6', fontWeight: 600 }}
                                />
                              )}
                            </Box>
                            <TextField
                              size="small"
                              placeholder="Search devices..."
                              value={searchQuery}
                              onChange={(e) => setSearchQuery(e.target.value)}
                              slotProps={{
                                input: {
                                  startAdornment: (
                                    <InputAdornment position="start">
                                      <Search size={16} color="#94A3B8" />
                                    </InputAdornment>
                                  )
                                }
                              }}
                              sx={{
                                minWidth: '250px',
                                '& .MuiOutlinedInput-root': {
                                  backgroundColor: 'rgba(0,0,0,0.3)',
                                  borderRadius: 1.5,
                                  '& fieldset': {
                                    borderColor: 'rgba(0,245,255,0.2)'
                                  },
                                  '&:hover fieldset': {
                                    borderColor: 'rgba(0,245,255,0.4)'
                                  },
                                  '&.Mui-focused fieldset': {
                                    borderColor: '#00F5FF'
                                  }
                                },
                                '& .MuiInputBase-input': {
                                  color: '#E2E8F0'
                                }
                              }}
                            />
                          </Box>
                          {filteredDevices.length > 0 ? (
                            <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(2, 1fr)' }, gap: 2 }}>
                              {filteredDevices.map((device, idx) => (
                              <Paper
                                key={idx}
                                onClick={() => setSelectedDevice(device)}
                                sx={{
                                  p: 2.5,
                                  borderRadius: 2,
                                  backgroundColor: 'rgba(15,23,42,0.8)',
                                  border: '1px solid rgba(0,245,255,0.15)',
                                  transition: 'all 0.2s ease',
                                  cursor: 'pointer',
                                  '&:hover': {
                                    borderColor: 'rgba(0,245,255,0.4)',
                                    boxShadow: '0 0 20px rgba(0,245,255,0.1)',
                                    transform: 'translateY(-2px)'
                                  }
                                }}
                              >
                                <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 2 }}>
                                  <Box>
                                    <Typography variant="h5" sx={{ color: '#FFFFFF', fontWeight: 800 }}>
                                      {device.ip}
                                    </Typography>
                                    {device.hostname && (
                                      <Typography variant="body2" sx={{ color: '#94A3B8', mt: 0.5 }}>
                                        {device.hostname}
                                      </Typography>
                                    )}
                                  </Box>
                                  <Chip
                                    label={device.device_type || 'Unknown'}
                                    size="small"
                                    sx={{ backgroundColor: 'rgba(0,245,255,0.1)', color: '#00F5FF', fontWeight: 600 }}
                                  />
                                </Box>
                                {device.mac && (
                                  <Box sx={{ mb: 1.5 }}>
                                    <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                      MAC Address
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace' }}>
                                      {device.mac}
                                    </Typography>
                                  </Box>
                                )}
                                {device.manufacturer && device.manufacturer !== 'Unknown' && (
                                  <Box sx={{ mb: 1.5 }}>
                                    <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                      Manufacturer
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: '#CBD5E1' }}>
                                      {device.manufacturer}
                                    </Typography>
                                  </Box>
                                )}
                                {device.open_ports && device.open_ports.length > 0 && (
                                  <Box>
                                    <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600, mb: 0.75, display: 'block' }}>
                                      Open Ports ({device.open_ports.length})
                                    </Typography>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 0.75 }}>
                                      {device.open_ports.map((port) => (
                                        <Chip
                                          key={port}
                                          label={`${port}${device.services[port] ? ` - ${device.services[port]}` : ''}`}
                                          size="small"
                                          sx={{
                                            backgroundColor: 'rgba(34,197,94,0.1)',
                                            color: '#22C55E',
                                            fontWeight: 700,
                                            border: '1px solid rgba(34,197,94,0.3)'
                                          }}
                                        />
                                      ))}
                                    </Box>
                                  </Box>
                                )}
                                {device.os_guess && (
                                  <Box sx={{ mt: 1.5 }}>
                                    <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                      OS Guess
                                    </Typography>
                                    <Typography variant="body2" sx={{ color: '#CBD5E1' }}>
                                      {device.os_guess}
                                    </Typography>
                                  </Box>
                                )}
                              </Paper>
                            ))}
                            </Box>
                          ) : (
                            <Box sx={{ textAlign: 'center', py: 6, backgroundColor: 'rgba(0,0,0,0.2)', borderRadius: 2 }}>
                              <Box sx={{ opacity: 0.5, mb: 2 }}>
                                <Search size={48} color="#64748B" />
                              </Box>
                              <Typography variant="h6" sx={{ color: '#94A3B8', mb: 1 }}>
                                No devices match your search
                              </Typography>
                              <Typography variant="body2" sx={{ color: '#64748B' }}>
                                Try adjusting your search query
                              </Typography>
                            </Box>
                          )}
                        </Box>
                      )}

                      {/* My Device View */}
                      {(structured.hostname || structured.platform) && (
                        <>
                          <Paper
                            sx={{
                              p: 3,
                              borderRadius: 2,
                              backgroundColor: 'rgba(168,85,247,0.05)',
                              border: '1px solid rgba(168,85,247,0.2)'
                            }}
                          >
                            <Typography variant="h6" sx={{ color: '#A855F7', fontWeight: 700, mb: 2 }}>
                              System Info
                            </Typography>
                            <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' }, gap: 2 }}>
                              {structured.hostname && (
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Hostname
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.hostname}
                                  </Typography>
                                </Box>
                              )}
                              {structured.fqdn && (
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    FQDN
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.fqdn}
                                  </Typography>
                                </Box>
                              )}
                              {structured.platform && (
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Platform
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.platform}
                                  </Typography>
                                </Box>
                              )}
                              {structured.python_version && (
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Python Version
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.python_version}
                                  </Typography>
                                </Box>
                              )}
                            </Box>
                          </Paper>

                          {structured.interfaces && structured.interfaces.length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(6,182,212,0.05)',
                                border: '1px solid rgba(6,182,212,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#06B6D4', fontWeight: 700, mb: 2 }}>
                                Network Interfaces
                              </Typography>
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                {structured.interfaces.map((iface, idx) => (
                                  <Box
                                    key={idx}
                                    sx={{
                                      p: 2,
                                      backgroundColor: 'rgba(0,0,0,0.2)',
                                      borderRadius: 1.5,
                                      border: '1px solid rgba(255,255,255,0.05)'
                                    }}
                                  >
                                    <Typography variant="h6" sx={{ color: '#FFFFFF', fontWeight: 700, mb: 1.5 }}>
                                      {iface.name}
                                    </Typography>
                                    <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)' }, gap: 2 }}>
                                      <Box>
                                        <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                          IPv4
                                        </Typography>
                                        <Typography variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace' }}>
                                          {iface.ipv4}/{iface.ipv4_prefix}
                                        </Typography>
                                      </Box>
                                      <Box>
                                        <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                          MAC
                                        </Typography>
                                        <Typography variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace' }}>
                                          {iface.mac}
                                        </Typography>
                                      </Box>
                                      <Box>
                                        <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                          Status
                                        </Typography>
                                        <Chip
                                          label={iface.state}
                                          size="small"
                                          sx={{
                                            backgroundColor: iface.state === 'Up' ? 'rgba(34,197,94,0.1)' : 'rgba(248,113,113,0.1)',
                                            color: iface.state === 'Up' ? '#22C55E' : '#EF4444',
                                            fontWeight: 600
                                          }}
                                        />
                                      </Box>
                                      {iface.dhcp_server && (
                                        <Box>
                                          <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                            DHCP Server
                                          </Typography>
                                          <Typography variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace' }}>
                                            {iface.dhcp_server}
                                          </Typography>
                                        </Box>
                                      )}
                                      {iface.dns_servers && iface.dns_servers.length > 0 && (
                                        <Box>
                                          <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                            DNS Servers
                                          </Typography>
                                          {iface.dns_servers.map((dns, i) => (
                                            <Typography key={i} variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace' }}>
                                              {dns}
                                            </Typography>
                                          ))}
                                        </Box>
                                      )}
                                      {iface.speed && (
                                        <Box>
                                          <Typography variant="caption" sx={{ color: '#64748B', textTransform: 'uppercase', fontWeight: 600 }}>
                                            Speed
                                          </Typography>
                                          <Typography variant="body2" sx={{ color: '#CBD5E1' }}>
                                            {iface.speed}
                                          </Typography>
                                        </Box>
                                      )}
                                    </Box>
                                  </Box>
                                ))}
                              </Box>
                            </Paper>
                          )}

                          {structured.connections && structured.connections.length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(34,197,94,0.05)',
                                border: '1px solid rgba(34,197,94,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#22C55E', fontWeight: 700, mb: 2 }}>
                                Active Connections
                              </Typography>
                              <Box sx={{ maxHeight: '300px', overflowY: 'auto' }}>
                                {structured.connections.map((conn, idx) => (
                                  <Box
                                    key={idx}
                                    sx={{
                                      p: 1.5,
                                      mb: 1,
                                      backgroundColor: 'rgba(0,0,0,0.2)',
                                      borderRadius: 1,
                                      border: '1px solid rgba(255,255,255,0.05)'
                                    }}
                                  >
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                                      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                                        <Chip
                                          label={conn.protocol}
                                          size="small"
                                          sx={{ backgroundColor: 'rgba(168,85,247,0.1)', color: '#A855F7', fontWeight: 700 }}
                                        />
                                        <Typography variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace' }}>
                                          {conn.local_addr}:{conn.local_port} → {conn.remote_addr}:{conn.remote_port}
                                        </Typography>
                                      </Box>
                                      <Box sx={{ display: 'flex', gap: 1, alignItems: 'center' }}>
                                        <Chip
                                          label={conn.state}
                                          size="small"
                                          sx={{
                                            backgroundColor: conn.state === 'ESTABLISHED' ? 'rgba(34,197,94,0.1)' : 'rgba(248,113,113,0.1)',
                                            color: conn.state === 'ESTABLISHED' ? '#22C55E' : '#EF4444',
                                            fontWeight: 600
                                          }}
                                        />
                                        {conn.process && (
                                          <Typography variant="body2" sx={{ color: '#94A3B8' }}>
                                            {conn.process}
                                          </Typography>
                                        )}
                                      </Box>
                                    </Box>
                                  </Box>
                                ))}
                              </Box>
                            </Paper>
                          )}
                        </>
                      )}

                      {/* Infrastructure View */}
                      {(structured.gateway_alive !== undefined || structured.dhcp_range) && (
                        <>
                          <Paper
                            sx={{
                              p: 3,
                              borderRadius: 2,
                              backgroundColor: 'rgba(168,85,247,0.05)',
                              border: '1px solid rgba(168,85,247,0.2)'
                            }}
                          >
                            <Typography variant="h6" sx={{ color: '#A855F7', fontWeight: 700, mb: 2 }}>
                              Infrastructure Status
                            </Typography>
                            <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)' }, gap: 2 }}>
                              <Box>
                                <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                  Gateway Alive
                                </Typography>
                                <Chip
                                  label={structured.gateway_alive ? 'Yes' : 'No'}
                                  sx={{
                                    backgroundColor: structured.gateway_alive ? 'rgba(34,197,94,0.1)' : 'rgba(248,113,113,0.1)',
                                    color: structured.gateway_alive ? '#22C55E' : '#EF4444',
                                    fontWeight: 700
                                  }}
                                />
                              </Box>
                              {structured.dhcp_range && (
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    DHCP Range
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600, fontFamily: 'monospace' }}>
                                    {structured.dhcp_range.start} - {structured.dhcp_range.end}
                                  </Typography>
                                </Box>
                              )}
                              {structured.nat_info && (
                                <Box sx={{ gridColumn: '1 / -1' }}>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    NAT Info
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.nat_info}
                                  </Typography>
                                </Box>
                              )}
                            </Box>
                          </Paper>

                          {structured.traceroute && structured.traceroute.length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(6,182,212,0.05)',
                                border: '1px solid rgba(6,182,212,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#06B6D4', fontWeight: 700, mb: 2 }}>
                                Traceroute (to 8.8.8.8)
                              </Typography>
                              <Box sx={{ maxHeight: '200px', overflowY: 'auto' }}>
                                {structured.traceroute.map((line, idx) => (
                                  <Typography key={idx} variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace', mb: 0.5 }}>
                                    {line}
                                  </Typography>
                                ))}
                              </Box>
                            </Paper>
                          )}
                        </>
                      )}

                      {/* Wireless View */}
                      {(structured.connected || structured.visible) && (
                        <>
                          {structured.connected && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(34,197,94,0.05)',
                                border: '1px solid rgba(34,197,94,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#22C55E', fontWeight: 700, mb: 2 }}>
                                Connected Network
                              </Typography>
                              <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(3, 1fr)' }, gap: 2 }}>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    SSID
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.connected.ssid}
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Signal Strength
                                  </Typography>
                                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                                    <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                      {structured.connected.signal}% ({structured.connected.signal_dbm} dBm)
                                    </Typography>
                                  </Box>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Channel
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.connected.channel} ({structured.connected.frequency} GHz)
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Security
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.connected.authentication} / {structured.connected.encryption}
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    BSSID
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600, fontFamily: 'monospace' }}>
                                    {structured.connected.bssid}
                                  </Typography>
                                </Box>
                              </Box>
                            </Paper>
                          )}

                          {structured.visible && structured.visible.length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(6,182,212,0.05)',
                                border: '1px solid rgba(6,182,212,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#06B6D4', fontWeight: 700, mb: 2 }}>
                                Nearby Networks ({structured.visible.length})
                              </Typography>
                              <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(2, 1fr)' }, gap: 2 }}>
                                {structured.visible.map((net, idx) => (
                                  <Box
                                    key={idx}
                                    sx={{
                                      p: 2,
                                      backgroundColor: 'rgba(0,0,0,0.2)',
                                      borderRadius: 1.5,
                                      border: net.connected ? '2px solid rgba(34,197,94,0.5)' : '1px solid rgba(255,255,255,0.05)'
                                    }}
                                  >
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5 }}>
                                      <Box>
                                        <Typography variant="h6" sx={{ color: '#FFFFFF', fontWeight: 700 }}>
                                          {net.ssid || '<Hidden>'}
                                        </Typography>
                                        {net.bssid && (
                                          <Typography variant="body2" sx={{ color: '#94A3B8', fontFamily: 'monospace' }}>
                                            {net.bssid}
                                          </Typography>
                                        )}
                                      </Box>
                                      <Box sx={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 0.5 }}>
                                        <Chip
                                          label={`${net.signal}%`}
                                          size="small"
                                          sx={{
                                            backgroundColor: net.signal > 70 ? 'rgba(34,197,94,0.1)' : net.signal > 40 ? 'rgba(234,179,8,0.1)' : 'rgba(248,113,113,0.1)',
                                            color: net.signal > 70 ? '#22C55E' : net.signal > 40 ? '#EAB308' : '#EF4444',
                                            fontWeight: 700
                                          }}
                                        />
                                        {net.connected && (
                                          <Chip
                                            label="Connected"
                                            size="small"
                                            sx={{
                                              backgroundColor: 'rgba(34,197,94,0.1)',
                                              color: '#22C55E',
                                              fontWeight: 700
                                            }}
                                          />
                                        )}
                                      </Box>
                                    </Box>
                                    <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                                      <Chip
                                        label={`Channel ${net.channel}`}
                                        size="small"
                                        sx={{ backgroundColor: 'rgba(168,85,247,0.1)', color: '#A855F7', fontWeight: 600 }}
                                      />
                                      <Chip
                                        label={net.authentication}
                                        size="small"
                                        sx={{ backgroundColor: 'rgba(6,182,212,0.1)', color: '#06B6D4', fontWeight: 600 }}
                                      />
                                    </Box>
                                  </Box>
                                ))}
                              </Box>
                            </Paper>
                          )}

                          {structured.channel_counts && Object.keys(structured.channel_counts).length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(168,85,247,0.05)',
                                border: '1px solid rgba(168,85,247,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#A855F7', fontWeight: 700, mb: 2 }}>
                                Channel Utilization
                              </Typography>
                              <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
                                {Object.entries(structured.channel_counts).map(([channel, count]) => (
                                  <Chip
                                    key={channel}
                                    label={`Ch ${channel}: ${count}`}
                                    sx={{
                                      backgroundColor: count > 3 ? 'rgba(248,113,113,0.1)' : count > 1 ? 'rgba(234,179,8,0.1)' : 'rgba(34,197,94,0.1)',
                                      color: count > 3 ? '#EF4444' : count > 1 ? '#EAB308' : '#22C55E',
                                      fontWeight: 700
                                    }}
                                  />
                                ))}
                              </Box>
                            </Paper>
                          )}
                        </>
                      )}

                      {/* Internet View */}
                      {(structured.public_ip || structured.dns_tests) && (
                        <>
                          {structured.public_ip && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(34,197,94,0.05)',
                                border: '1px solid rgba(34,197,94,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#22C55E', fontWeight: 700, mb: 2 }}>
                                Public IP Info
                              </Typography>
                              <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', md: 'repeat(4, 1fr)' }, gap: 2 }}>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    IP Address
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600, fontFamily: 'monospace' }}>
                                    {structured.public_ip.query}
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Country
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.public_ip.country} ({structured.public_ip.countryCode})
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Region/City
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.public_ip.regionName}, {structured.public_ip.city}
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    ISP
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.public_ip.isp}
                                  </Typography>
                                </Box>
                              </Box>
                            </Paper>
                          )}

                          {structured.dns_tests && structured.dns_tests.length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(6,182,212,0.05)',
                                border: '1px solid rgba(6,182,212,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#06B6D4', fontWeight: 700, mb: 2 }}>
                                DNS Tests
                              </Typography>
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                                {structured.dns_tests.map((test, idx) => (
                                  <Box
                                    key={idx}
                                    sx={{
                                      display: 'flex',
                                      justifyContent: 'space-between',
                                      alignItems: 'center',
                                      p: 1.5,
                                      backgroundColor: 'rgba(0,0,0,0.2)',
                                      borderRadius: 1,
                                      border: test.success ? '1px solid rgba(34,197,94,0.2)' : '1px solid rgba(248,113,113,0.2)'
                                    }}
                                  >
                                    <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                                      {test.success ? (
                                        <CheckCircle2 size={18} color="#22C55E" />
                                      ) : (
                                        <XCircle size={18} color="#EF4444" />
                                      )}
                                      <Typography variant="body2" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                        {test.domain}
                                      </Typography>
                                      {test.ip && (
                                        <Typography variant="body2" sx={{ color: '#94A3B8', fontFamily: 'monospace' }}>
                                          {test.ip}
                                        </Typography>
                                      )}
                                    </Box>
                                    {test.latency_ms && (
                                      <Chip
                                        label={`${test.latency_ms.toFixed(2)} ms`}
                                        size="small"
                                        sx={{
                                          backgroundColor: test.latency_ms < 100 ? 'rgba(34,197,94,0.1)' : test.latency_ms < 300 ? 'rgba(234,179,8,0.1)' : 'rgba(248,113,113,0.1)',
                                          color: test.latency_ms < 100 ? '#22C55E' : test.latency_ms < 300 ? '#EAB308' : '#EF4444',
                                          fontWeight: 700
                                        }}
                                      />
                                    )}
                                  </Box>
                                ))}
                              </Box>
                            </Paper>
                          )}
                        </>
                      )}

                      {/* Performance View */}
                      {structured.ping_tests && structured.ping_tests.length > 0 && (
                        <>
                          <Paper
                            sx={{
                              p: 3,
                              borderRadius: 2,
                              backgroundColor: 'rgba(34,197,94,0.05)',
                              border: '1px solid rgba(34,197,94,0.2)'
                            }}
                          >
                            <Typography variant="h6" sx={{ color: '#22C55E', fontWeight: 700, mb: 2 }}>
                              Ping Tests
                            </Typography>
                            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                              {structured.ping_tests.map((test, idx) => (
                                <Box
                                  key={idx}
                                  sx={{
                                    display: 'flex',
                                    justifyContent: 'space-between',
                                    alignItems: 'center',
                                    p: 1.5,
                                    backgroundColor: 'rgba(0,0,0,0.2)',
                                    borderRadius: 1,
                                    border: !test.error ? '1px solid rgba(34,197,94,0.2)' : '1px solid rgba(248,113,113,0.2)'
                                  }}
                                >
                                  <Box sx={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                                    {!test.error ? (
                                      <CheckCircle2 size={18} color="#22C55E" />
                                    ) : (
                                      <XCircle size={18} color="#EF4444" />
                                    )}
                                    <Box>
                                      <Typography variant="body2" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                        {test.label}
                                      </Typography>
                                      <Typography variant="caption" sx={{ color: '#94A3B8', fontFamily: 'monospace' }}>
                                        {test.host}
                                      </Typography>
                                    </Box>
                                  </Box>
                                  {test.latency_ms !== undefined && (
                                    <Chip
                                      label={`${test.latency_ms} ms`}
                                      size="small"
                                      sx={{
                                        backgroundColor: test.latency_ms < 50 ? 'rgba(34,197,94,0.1)' : test.latency_ms < 150 ? 'rgba(234,179,8,0.1)' : 'rgba(248,113,113,0.1)',
                                        color: test.latency_ms < 50 ? '#22C55E' : test.latency_ms < 150 ? '#EAB308' : '#EF4444',
                                        fontWeight: 700
                                      }}
                                    />
                                  )}
                                </Box>
                              ))}
                            </Box>
                          </Paper>

                          {structured.path_mtu && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(6,182,212,0.05)',
                                border: '1px solid rgba(6,182,212,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#06B6D4', fontWeight: 700, mb: 2 }}>
                                Path MTU (to 8.8.8.8)
                              </Typography>
                              <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                {structured.path_mtu} bytes
                              </Typography>
                            </Paper>
                          )}
                        </>
                      )}

                      {/* Security View */}
                      {(structured.wireless_security || structured.risky_ports || structured.unknown_devices) && (
                        <>
                          {structured.wireless_security && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(34,197,94,0.05)',
                                border: '1px solid rgba(34,197,94,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#22C55E', fontWeight: 700, mb: 2 }}>
                                Wireless Security
                              </Typography>
                              <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)' }, gap: 2 }}>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Network
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.wireless_security.ssid}
                                  </Typography>
                                </Box>
                                <Box>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Authentication
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.wireless_security.authentication}
                                  </Typography>
                                </Box>
                                <Box sx={{ gridColumn: '1 / -1' }}>
                                  <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                    Encryption
                                  </Typography>
                                  <Typography variant="body1" sx={{ color: '#E2E8F0', fontWeight: 600 }}>
                                    {structured.wireless_security.encryption}
                                  </Typography>
                                </Box>
                              </Box>
                            </Paper>
                          )}

                          {structured.risky_ports && structured.risky_ports.length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(248,113,113,0.05)',
                                border: '1px solid rgba(248,113,113,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#EF4444', fontWeight: 700, mb: 2 }}>
                                Risky Open Ports ({structured.risky_ports.length} devices)
                              </Typography>
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                                {structured.risky_ports.map((device, idx) => (
                                  <Box
                                    key={idx}
                                    sx={{
                                      p: 2,
                                      backgroundColor: 'rgba(0,0,0,0.2)',
                                      borderRadius: 1.5,
                                      border: '1px solid rgba(248,113,113,0.2)'
                                    }}
                                  >
                                    <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', mb: 1.5 }}>
                                      <Box>
                                        <Typography variant="h6" sx={{ color: '#FFFFFF', fontWeight: 700 }}>
                                          {device.ip}
                                        </Typography>
                                        {device.hostname && (
                                          <Typography variant="body2" sx={{ color: '#94A3B8' }}>
                                            {device.hostname}
                                          </Typography>
                                        )}
                                        {device.manufacturer && (
                                          <Typography variant="body2" sx={{ color: '#94A3B8' }}>
                                            {device.manufacturer}
                                          </Typography>
                                        )}
                                      </Box>
                                    </Box>
                                    <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 1 }}>
                                      {device.risky_ports.map((port, i) => (
                                        <Chip
                                          key={i}
                                          label={`${port.port} - ${port.description}`}
                                          size="small"
                                          sx={{ backgroundColor: 'rgba(248,113,113,0.1)', color: '#EF4444', fontWeight: 700 }}
                                        />
                                      ))}
                                    </Box>
                                  </Box>
                                ))}
                              </Box>
                            </Paper>
                          )}

                          {structured.unknown_devices && structured.unknown_devices.length > 0 && (
                            <Paper
                              sx={{
                                p: 3,
                                borderRadius: 2,
                                backgroundColor: 'rgba(234,179,8,0.05)',
                                border: '1px solid rgba(234,179,8,0.2)'
                              }}
                            >
                              <Typography variant="h6" sx={{ color: '#EAB308', fontWeight: 700, mb: 2 }}>
                                Unknown Devices ({structured.unknown_devices.length})
                              </Typography>
                              <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1.5 }}>
                                {structured.unknown_devices.map((device, idx) => (
                                  <Box
                                    key={idx}
                                    sx={{
                                      display: 'flex',
                                      justifyContent: 'space-between',
                                      alignItems: 'center',
                                      p: 1.5,
                                      backgroundColor: 'rgba(0,0,0,0.2)',
                                      borderRadius: 1,
                                      border: '1px solid rgba(234,179,8,0.2)'
                                    }}
                                  >
                                    <Box>
                                      <Typography variant="body2" sx={{ color: '#E2E8F0', fontWeight: 600, fontFamily: 'monospace' }}>
                                        {device.ip}
                                      </Typography>
                                      <Typography variant="caption" sx={{ color: '#94A3B8', fontFamily: 'monospace' }}>
                                        {device.mac}
                                      </Typography>
                                      {device.hostname && (
                                        <Typography variant="caption" sx={{ color: '#94A3B8' }}>
                                          {device.hostname}
                                        </Typography>
                                      )}
                                    </Box>
                                    <AlertCircle size={20} color="#EAB308" />
                                  </Box>
                                ))}
                              </Box>
                            </Paper>
                          )}
                        </>
                      )}

                      {/* Traffic View */}
                      {structured.connection_breakdown && (
                        <Paper
                          sx={{
                            p: 3,
                            borderRadius: 2,
                            backgroundColor: 'rgba(34,197,94,0.05)',
                            border: '1px solid rgba(34,197,94,0.2)'
                          }}
                        >
                          <Typography variant="h6" sx={{ color: '#22C55E', fontWeight: 700, mb: 2 }}>
                            Connection Breakdown
                          </Typography>
                          <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)' }, gap: 2 }}>
                            <Box>
                              <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                Local IPs ({structured.connection_breakdown.local_ips.length})
                              </Typography>
                              <Box sx={{ maxHeight: '150px', overflowY: 'auto' }}>
                                {structured.connection_breakdown.local_ips.map((ip, idx) => (
                                  <Typography key={idx} variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace', mb: 0.5 }}>
                                    {ip}
                                  </Typography>
                                ))}
                              </Box>
                            </Box>
                            <Box>
                              <Typography variant="body2" sx={{ color: '#94A3B8', mb: 0.5 }}>
                                External IPs ({structured.connection_breakdown.external_ips.length})
                              </Typography>
                              <Box sx={{ maxHeight: '150px', overflowY: 'auto' }}>
                                {structured.connection_breakdown.external_ips.slice(0, 20).map((ip, idx) => (
                                  <Typography key={idx} variant="body2" sx={{ color: '#CBD5E1', fontFamily: 'monospace', mb: 0.5 }}>
                                    {ip}
                                  </Typography>
                                ))}
                                {structured.connection_breakdown.external_ips.length > 20 && (
                                  <Typography variant="body2" sx={{ color: '#94A3B8', fontStyle: 'italic' }}>
                                    ... and {structured.connection_breakdown.external_ips.length - 20} more
                                  </Typography>
                                )}
                              </Box>
                            </Box>
                          </Box>
                        </Paper>
                      )}

                      {/* Errors, if any */}
                      {structured.errors && structured.errors.length > 0 && (
                        <Paper
                          sx={{
                            p: 2.5,
                            borderRadius: 2,
                            backgroundColor: 'rgba(248, 113, 113, 0.05)',
                            border: '1px solid rgba(248, 113, 113, 0.2)'
                          }}
                        >
                          <Typography variant="h6" sx={{ color: '#EF4444', fontWeight: 700, mb: 2 }}>
                            Warnings
                          </Typography>
                          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                            {structured.errors.map((error, idx) => (
                              <Box
                                key={idx}
                                sx={{
                                  display: 'flex',
                                  gap: 1.5,
                                  alignItems: 'flex-start',
                                  p: 1.5,
                                  backgroundColor: 'rgba(248, 113, 113, 0.08)',
                                  borderRadius: 1
                                }}
                              >
                                <AlertCircle size={18} color="#EF4444" />
                                <Typography variant="body2" sx={{ color: '#FCA5A5' }}>
                                  {error}
                                </Typography>
                              </Box>
                            ))}
                          </Box>
                        </Paper>
                      )}
                    </Box>
                  ) : (
                    <Box
                      sx={{
                        fontFamily: '"JetBrains Mono", "Fira Code", "Courier New", Courier, monospace',
                        color: '#CCFFFC',
                        whiteSpace: 'pre-wrap',
                        fontSize: '0.95rem'
                      }}
                      dangerouslySetInnerHTML={{
                        __html: ansiUp.ansi_to_html(output)
                      }}
                    />
                  )}
                </Box>
              )}

              {output && activeTab === 1 && (
                <Box
                  sx={{
                    flex: 1,
                    overflowY: 'auto',
                    p: 3,
                    background: '#020617',
                    fontFamily: '"Courier New", Courier, monospace',
                    lineHeight: 1.6,
                    '&::-webkit-scrollbar': {
                      width: '8px'
                    },
                    '&::-webkit-scrollbar-track': {
                      background: 'rgba(0, 0, 0, 0.2)',
                      borderRadius: '4px'
                    },
                    '&::-webkit-scrollbar-thumb': {
                      background: 'rgba(100, 116, 139, 0.5)',
                      borderRadius: '4px'
                    }
                  }}
                >
                  <Typography
                    variant="body2"
                    sx={{
                      color: '#E2E8F0',
                      whiteSpace: 'pre-wrap',
                      fontSize: '0.9rem'
                    }}
                  >
                    {output}
                  </Typography>
                </Box>
              )}
            </Box>
          </Paper>
        </Box>
      </Box>
      <DeviceDetailsModal
        open={!!selectedDevice}
        onClose={() => setSelectedDevice(null)}
        device={selectedDevice}
      />
    </Container>
  )
}

export default Recon

