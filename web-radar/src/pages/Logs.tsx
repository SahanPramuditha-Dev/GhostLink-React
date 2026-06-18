import { useState, useEffect, useRef, useMemo } from 'react'
import {
  FileText,
  Pause,
  Play,
  Download,
  Search,
  RefreshCw,
  Shield,
  Zap,
  Wifi,
  Activity,
  CheckCircle2,
  Globe,
  Lock,
  Cpu,
  Eye,
  Trash2
} from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { useApi } from '../hooks/useApi'
import { getLogs, clearLogs } from '../api'
import {
  Container,
  Typography,
  Paper,
  TextField,
  IconButton,
  Button as MuiButton,
  Box,
  Chip,
  Divider,
  ToggleButton,
  ToggleButtonGroup
} from '@mui/material'

type LogType = 'all' | 'attack' | 'recon' | 'success' | 'info'

function LogsPage() {
  const { setSnackbar } = useAppContext()
  const { data: apiLogs = [], execute } = useApi<string[]>()
  const [searchTerm, setSearchTerm] = useState('')
  const [isPaused, setIsPaused] = useState(false)
  const [logType, setLogType] = useState<LogType>('all')
  const logsRef = useRef<HTMLDivElement>(null)

  // Just use API logs, no mock logs
  const allLogs = useMemo(() => {
    return Array.isArray(apiLogs) ? apiLogs : []
  }, [apiLogs])

  // Filter logs based on type and search term
  const filteredLogs = useMemo(() => {
    return allLogs.filter(log => {
      // Search filter
      const matchesSearch = log.toLowerCase().includes(searchTerm.toLowerCase())
      
      // Type filter
      let matchesType = true
      switch (logType) {
        case 'attack':
          matchesType = log.toLowerCase().includes('attack')
          break
        case 'recon':
          matchesType = log.toLowerCase().includes('recon')
          break
        case 'success':
          matchesType = log.toLowerCase().includes('succeeded') || log.toLowerCase().includes('success')
          break
        default:
          matchesType = true
      }
      
      return matchesSearch && matchesType
    })
  }, [allLogs, searchTerm, logType])

  // Auto-scroll to bottom when logs update
  useEffect(() => {
    if (logsRef.current && !isPaused) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight
    }
  }, [filteredLogs, isPaused])

  // Load logs on mount
  useEffect(() => {
    const loadLogs = async () => {
      await execute(getLogs)
    }
    loadLogs()
  }, [execute])

  // Auto-refresh logs
  useEffect(() => {
    if (isPaused) return
    const interval = setInterval(() => {
      execute(getLogs, { showError: false })
    }, 5000)
    return () => clearInterval(interval)
  }, [isPaused, execute])

  const handleExport = () => {
    const data = filteredLogs.join('\n')
    const blob = new Blob([data], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ghostlink-logs-${new Date().toISOString().replace(/[:.]/g, '-')}.txt`
    a.click()
    URL.revokeObjectURL(url)
    setSnackbar({
      open: true,
      message: 'Logs exported successfully!',
      severity: 'success'
    })
  }

  const handleClear = async () => {
    try {
      await execute(clearLogs)
      await execute(getLogs)
      setSnackbar({
        open: true,
        message: 'Logs cleared',
        severity: 'success'
      })
    } catch (err) {
      // Error handled by useApi
    }
  }

  // Helper to get icon and color for log entry
  const getLogStyle = (log: string) => {
    if (log.toLowerCase().includes('attack')) {
      return {
        icon: <Shield size={16} />,
        color: '#EF4444',
        bgColor: 'rgba(239, 68, 68, 0.1)',
        label: 'ATTACK'
      }
    } else if (log.toLowerCase().includes('recon')) {
      if (log.toLowerCase().includes('my device')) {
        return {
          icon: <Activity size={16} />,
          color: '#00F5FF',
          bgColor: 'rgba(0, 245, 255, 0.1)',
          label: 'MY DEVICE'
        }
      } else if (log.toLowerCase().includes('infrastructure')) {
        return {
          icon: <Lock size={16} />,
          color: '#A855F7',
          bgColor: 'rgba(168, 85, 247, 0.1)',
          label: 'INFRASTRUCTURE'
        }
      } else if (log.toLowerCase().includes('wireless')) {
        return {
          icon: <Wifi size={16} />,
          color: '#22C55E',
          bgColor: 'rgba(34, 197, 94, 0.1)',
          label: 'WIRELESS'
        }
      } else if (log.toLowerCase().includes('internet')) {
        return {
          icon: <Globe size={16} />,
          color: '#06B6D4',
          bgColor: 'rgba(6, 182, 212, 0.1)',
          label: 'INTERNET'
        }
      } else if (log.toLowerCase().includes('performance')) {
        return {
          icon: <Zap size={16} />,
          color: '#F59E0B',
          bgColor: 'rgba(245, 158, 11, 0.1)',
          label: 'PERFORMANCE'
        }
      } else if (log.toLowerCase().includes('resources')) {
        return {
          icon: <Cpu size={16} />,
          color: '#8B5CF6',
          bgColor: 'rgba(139, 92, 246, 0.1)',
          label: 'RESOURCES'
        }
      } else if (log.toLowerCase().includes('security')) {
        return {
          icon: <Shield size={16} />,
          color: '#EF4444',
          bgColor: 'rgba(239, 68, 68, 0.1)',
          label: 'SECURITY'
        }
      } else if (log.toLowerCase().includes('traffic')) {
        return {
          icon: <Activity size={16} />,
          color: '#10B981',
          bgColor: 'rgba(16, 185, 129, 0.1)',
          label: 'TRAFFIC'
        }
      } else {
        return {
          icon: <Eye size={16} />,
          color: '#64748B',
          bgColor: 'rgba(100, 116, 139, 0.1)',
          label: 'RECON'
        }
      }
    } else if (log.toLowerCase().includes('succeeded') || log.toLowerCase().includes('success')) {
      return {
        icon: <CheckCircle2 size={16} />,
        color: '#22C55E',
        bgColor: 'rgba(34, 197, 94, 0.1)',
        label: 'SUCCESS'
      }
    }
    return {
      icon: <FileText size={16} />,
      color: '#64748B',
      bgColor: 'rgba(100, 116, 139, 0.1)',
      label: 'INFO'
    }
  }

  // Extract time from log entry
  const extractTime = (log: string) => {
    const timeMatch = log.match(/\[([^\]]+)\]/)
    return timeMatch ? timeMatch[1] : ''
  }

  // Extract message from log entry
  const extractMessage = (log: string) => {
    const timeMatch = log.match(/\[([^\]]+)\]/)
    return timeMatch ? log.replace(timeMatch[0], '').trim() : log
  }

  return (
    <Container maxWidth="xl" disableGutters sx={{ p: 3 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 800, color: 'text.primary', mb: 1 }}>
          Log Viewer
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          View and manage application logs
        </Typography>
      </Box>

      {/* Controls */}
      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, backgroundColor: 'background.paper', border: 1, borderColor: 'divider' }}>
        <Box sx={{ display: 'flex', flexDirection: { xs: 'column', sm: 'row' }, gap: 2, alignItems: { xs: 'stretch', sm: 'center' } }}>
          <TextField
            fullWidth
            label="Search logs"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            slotProps={{
              input: {
                startAdornment: (
                  <Search size={20} style={{ marginRight: '8px', opacity: 0.5 }} />
                ),
              },
            }}
            sx={{ minWidth: { xs: '100%', sm: '300px' } }}
          />
          
          <ToggleButtonGroup
            value={logType}
            exclusive
            onChange={(_, newType) => newType && setLogType(newType)}
            size="small"
          >
            <ToggleButton value="all">All</ToggleButton>
            <ToggleButton value="attack">Attack</ToggleButton>
            <ToggleButton value="recon">Recon</ToggleButton>
            <ToggleButton value="success">Success</ToggleButton>
          </ToggleButtonGroup>

          <Box sx={{ display: 'flex', gap: 1, ml: 'auto' }}>
            <IconButton onClick={() => execute(getLogs)} title="Refresh" sx={{ color: '#00F5FF' }}>
              <RefreshCw size={24} />
            </IconButton>
            <IconButton onClick={() => setIsPaused(!isPaused)} title={isPaused ? "Resume" : "Pause"} sx={{ color: isPaused ? '#22C55E' : '#EF4444' }}>
              {isPaused ? <Play size={24} /> : <Pause size={24} />}
            </IconButton>
            <IconButton onClick={handleClear} title="Clear logs" sx={{ color: '#EF4444' }}>
              <Trash2 size={24} />
            </IconButton>
            <MuiButton variant="contained" startIcon={<Download size={18} />} onClick={handleExport} sx={{ background: 'linear-gradient(135deg, #A855F7, #7C3AED)' }}>
              Export
            </MuiButton>
          </Box>
        </Box>
      </Paper>

      {/* Log Display */}
      <Paper sx={{ backgroundColor: 'background.paper', border: 1, borderColor: 'divider', borderRadius: 3, p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <FileText size={24} color="#A855F7" />
          <Typography variant="h6" sx={{ fontWeight: 700, color: 'text.primary' }}>Logs</Typography>
          <Chip label={`${filteredLogs.length} entries`} size="small" sx={{ backgroundColor: 'rgba(168,85,247,0.1)', color: '#A855F7', fontWeight: 700 }} />
          {isPaused && (
            <Chip label="PAUSED" size="small" sx={{ backgroundColor: 'rgba(239, 68, 68, 0.2)', color: '#EF4444', fontWeight: 700 }} />
          )}
        </Box>
        <Divider sx={{ mb: 3, borderColor: 'divider' }} />
        <Box
          ref={logsRef}
          sx={{
            maxHeight: '70vh',
            height: '70vh',
            overflowY: 'auto',
            p: 2,
            background: 'linear-gradient(180deg, #020617 0%, #0f172a 100%)',
            borderRadius: 2,
            fontFamily: '"JetBrains Mono", "Fira Code", "Courier New", Courier, monospace',
            lineHeight: 1.8,
            position: 'relative',
            '&::before': {
              content: '""',
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: '2px',
              background: 'linear-gradient(90deg, transparent, #A855F7, transparent)',
              borderRadius: '3px 3px 0 0',
            },
            '&::-webkit-scrollbar': {
              width: '10px',
            },
            '&::-webkit-scrollbar-track': {
              background: 'rgba(0, 0, 0, 0.2)',
              borderRadius: '5px',
            },
            '&::-webkit-scrollbar-thumb': {
              background: 'linear-gradient(180deg, #A855F7, #7C3AED)',
              borderRadius: '5px',
            },
          }}
        >
          {filteredLogs.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 8 }}>
              <FileText size={48} color="text.secondary" style={{ opacity: 0.5, marginBottom: 16 }} />
              <Typography variant="body1" color="text.secondary">
                {searchTerm || logType !== 'all' ? 'No logs match your filter' : 'No logs found'}
              </Typography>
            </Box>
          ) : (
            filteredLogs.map((log, idx) => {
              const style = getLogStyle(log)
              const time = extractTime(log)
              const message = extractMessage(log)
              
              return (
                <Box
                  key={idx}
                  sx={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: 2,
                    mb: 1.5,
                    p: 2,
                    borderRadius: 2,
                    backgroundColor: style.bgColor,
                    border: `1px solid ${style.color}20`,
                    transition: 'all 0.2s ease',
                    '&:hover': {
                      borderColor: `${style.color}60`,
                      boxShadow: `0 0 20px ${style.color}15`
                    }
                  }}
                >
                  <Box
                    sx={{
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      minWidth: '32px',
                      height: '32px',
                      borderRadius: '50%',
                      backgroundColor: `${style.color}20`,
                      color: style.color,
                      flexShrink: 0
                    }}
                  >
                    {style.icon}
                  </Box>
                  <Box sx={{ flex: 1, minWidth: 0 }}>
                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 0.5, flexWrap: 'wrap' }}>
                      <Chip
                        label={style.label}
                        size="small"
                        sx={{
                          backgroundColor: `${style.color}20`,
                          color: style.color,
                          fontWeight: 700,
                          fontSize: '0.7rem',
                          height: '20px'
                        }}
                      />
                      {time && (
                        <Typography
                          variant="caption"
                          sx={{ color: 'text.secondary', fontFamily: 'inherit', fontSize: '0.8rem' }}
                        >
                          {time}
                        </Typography>
                      )}
                    </Box>
                    <Typography
                      variant="body2"
                      sx={{
                        color: 'text.primary',
                        whiteSpace: 'pre-wrap',
                        fontSize: '0.9rem',
                        textShadow: `0 0 5px ${style.color}15`
                      }}
                    >
                      {message}
                    </Typography>
                  </Box>
                </Box>
              )
            })
          )}
        </Box>
      </Paper>
    </Container>
  )
}

export default LogsPage
