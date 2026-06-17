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
  Download
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
  Chip
} from '@mui/material'
import { runReconModule } from '../api'
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
interface ModuleResult {
  output: string
  structured?: {
    network?: NetworkInfo
    devices?: Device[]
    scan_duration?: number
    errors?: string[]
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

  const ansiUp = useMemo(() => new AnsiUp(), []);
  
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

  const handleExport = () => {
    const data = output
    const blob = new Blob([data], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ghostlink-recon-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`
    a.click()
    URL.revokeObjectURL(url)
    setSnackbar({
      open: true,
      message: 'Report exported successfully!',
      severity: 'success'
    })
  }

  return (
    <Container maxWidth="xl" disableGutters sx={{ p: 3 }}>
      <Box sx={{ mb: 3 }}>
        <Typography variant="h3" component="h1" sx={{ fontWeight: 800, color: '#FFFFFF', mb: 1 }}>
          Reconnaissance
        </Typography>
        <Typography variant="subtitle1" color="#94A3B8">
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
                <MuiButton
                  variant="outlined"
                  fullWidth
                  size="large"
                  startIcon={<Download size={20} />}
                  onClick={handleExport}
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
                      {/* Network Info Card */}
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

                      {/* Devices Section */}
                      {structured.devices && structured.devices.length > 0 && (
                        <Box>
                          <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', mb: 2 }}>
                            <Typography variant="h6" sx={{ color: '#00F5FF', fontWeight: 700 }}>
                              Discovered Devices ({structured.devices.length})
                            </Typography>
                            {structured.scan_duration && (
                              <Chip
                                label={`Scan took ${structured.scan_duration.toFixed(2)}s`}
                                sx={{ backgroundColor: 'rgba(139, 92, 246, 0.1)', color: '#8B5CF6', fontWeight: 600 }}
                              />
                            )}
                          </Box>
                          <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', md: 'repeat(2, 1fr)' }, gap: 2 }}>
                            {structured.devices.map((device, idx) => (
                              <Paper
                                key={idx}
                                sx={{
                                  p: 2.5,
                                  borderRadius: 2,
                                  backgroundColor: 'rgba(15,23,42,0.8)',
                                  border: '1px solid rgba(0,245,255,0.15)',
                                  transition: 'all 0.2s ease',
                                  '&:hover': {
                                    borderColor: 'rgba(0,245,255,0.4)',
                                    boxShadow: '0 0 20px rgba(0,245,255,0.1)'
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
                        </Box>
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
    </Container>
  )
}

export default Recon

