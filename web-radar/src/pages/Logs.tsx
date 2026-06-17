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
  AlertCircle,
  CheckCircle2,
  Globe,
  Lock,
  Cpu,
  Eye,
  Filter,
  X,
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

// Mock logs for better visualization
const mockLogs = [
  '[00:19:44] Starting attack on Lucifer',
  '[00:31:26] Starting real attack on Lucifer',
  '[00:31:41] Attack succeeded for Lucifer',
  '[00:33:42] My device recon executed',
  '[00:38:41] My device recon executed',
  '[00:43:41] My device recon executed',
  '[00:43:47] Infrastructure recon executed',
  '[00:43:48] Infrastructure recon executed',
  '[00:45:20] Infrastructure recon executed',
  '[00:45:21] Wireless recon executed',
  '[00:45:22] Internet recon executed',
  '[00:52:11] Infrastructure recon executed',
  '[00:52:13] My device recon executed',
  '[00:52:16] Resources recon executed',
  '[00:52:22] Full recon executed',
  '[00:52:23] My device recon executed',
  '[00:52:24] Infrastructure recon executed',
  '[00:52:25] My device recon executed',
  '[00:52:25] Wireless recon executed',
  '[00:52:26] Internet recon executed',
  '[00:52:26] Performance recon executed',
  '[00:52:26] Resources recon executed',
  '[00:52:30] Security recon executed',
  '[00:52:30] Traffic recon executed',
  '[00:53:35] Full recon executed',
  '[00:53:36] My device recon executed',
  '[00:53:36] Infrastructure recon executed',
  '[00:53:36] Wireless recon executed',
  '[00:53:37] Internet recon executed',
  '[00:53:37] Performance recon executed',
  '[00:53:37] Resources recon executed',
  '[00:53:40] Security recon executed',
  '[00:53:40] Traffic recon executed',
  '[00:55:42] Full recon executed',
  '[00:55:43] My device recon executed',
  '[00:56:08] Infrastructure recon executed',
  '[00:56:09] Wireless recon executed',
  '[00:56:12] Internet recon executed',
  '[00:57:18] Performance recon executed',
  '[00:57:43] Resources recon executed',
  '[00:58:23] Security recon executed',
  '[00:58:24] Traffic recon executed',
  '[01:00:18] Performance recon executed',
  '[01:00:43] Resources recon executed',
  '[01:03:05] Infrastructure recon executed',
  '[01:03:14] Wireless recon executed',
  '[01:03:16] Wireless recon executed',
  '[01:03:17] Internet recon executed',
  '[01:04:27] Performance recon executed',
  '[01:06:36] Wireless recon executed',
  '[01:06:51] Full recon executed',
  '[01:06:52] My device recon executed',
  '[01:07:21] Infrastructure recon executed',
  '[01:07:21] My device recon executed',
  '[01:07:22] Wireless recon executed',
  '[01:07:23] Internet recon executed',
  '[01:08:10] Performance recon executed',
  '[01:08:36] Infrastructure recon executed',
  '[01:09:00] Resources recon executed',
  '[01:09:25] Resources recon executed',
  '[01:09:26] My device recon executed',
  '[01:10:08] Infrastructure recon executed',
  '[01:10:35] Full recon executed',
  '[01:10:36] My device recon executed',
  '[01:11:19] Infrastructure recon executed',
  '[01:11:20] Wireless recon executed',
  '[01:11:23] Internet recon executed',
  '[01:12:34] Performance recon executed',
  '[01:12:59] Resources recon executed',
  '[01:13:40] Security recon executed',
  '[01:13:52] Traffic recon executed',
  '[01:16:17] My device recon executed',
  '[01:16:51] Infrastructure recon executed',
  '[01:16:52] Wireless recon executed',
  '[01:19:20] My device recon executed',
  '[01:21:01] My device recon executed',
  '[01:21:04] Wireless recon executed',
  '[01:21:06] Wireless recon executed',
  '[01:21:11] Internet recon executed',
  '[01:21:56] Performance recon executed',
  '[01:22:18] Internet recon executed',
  '[01:22:26] Internet recon executed',
  '[01:23:26] Performance recon executed',
  '[01:23:37] My device recon executed',
  '[01:23:53] My device recon executed',
  '[01:24:16] Infrastructure recon executed',
  '[01:24:17] Wireless recon executed',
  '[01:25:08] Internet recon executed',
  '[01:25:50] Infrastructure recon executed',
  '[01:25:59] Internet recon executed',
  '[01:27:13] Infrastructure recon executed',
  '[01:27:14] Internet recon executed',
  '[01:28:53] Infrastructure recon executed',
  '[01:29:53] Internet recon executed',
  '[01:31:01] Infrastructure recon executed',
  '[01:31:02] Internet recon executed',
  '[01:32:59] Infrastructure recon executed',
  '[01:33:04] Internet recon executed',
  '[01:33:36] Infrastructure recon executed',
  '[01:33:54] Performance recon executed',
  '[01:34:01] My device recon executed',
  '[01:36:02] Internet recon executed',
  '[01:36:20] My device recon executed',
  '[01:40:23] Internet recon executed',
  '[01:40:40] My device recon executed',
  '[01:43:16] My device recon executed',
  '[01:50:15] My device recon executed',
  '[01:55:44] My device recon executed',
  '[01:55:58] Internet recon executed',
  '[01:57:18] My device recon executed',
  '[01:59:08] Internet recon executed',
  '[01:59:30] Infrastructure recon executed'
]

type LogType = 'all' | 'attack' | 'recon' | 'success' | 'info'

function LogsPage() {
  const { setSnackbar } = useAppContext()
  const { data: apiLogs = [], execute } = useApi<string[]>()
  const [searchTerm, setSearchTerm] = useState('')
  const [isPaused, setIsPaused] = useState(false)
  const [logType, setLogType] = useState<LogType>('all')
  const logsRef = useRef<HTMLDivElement>(null)

  // Combine API logs with mock logs for better demo
  const allLogs = useMemo(() => {
    const safeApiLogs = Array.isArray(apiLogs) ? apiLogs : []
    return [...mockLogs, ...safeApiLogs]
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
        <Typography variant="h4" component="h1" sx={{ fontWeight: 800, color: '#FFFFFF', mb: 1 }}>
          Log Viewer
        </Typography>
        <Typography variant="subtitle1" color="#94A3B8">
          View and manage application logs
        </Typography>
      </Box>

      {/* Controls */}
      <Paper sx={{ p: 3, mb: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
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
      <Paper sx={{ background: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)', borderRadius: 3, p: 3 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <FileText size={24} color="#A855F7" />
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#F8FAFC' }}>Logs</Typography>
          <Chip label={`${filteredLogs.length} entries`} size="small" sx={{ backgroundColor: 'rgba(168,85,247,0.1)', color: '#A855F7', fontWeight: 700 }} />
          {isPaused && (
            <Chip label="PAUSED" size="small" sx={{ backgroundColor: 'rgba(239, 68, 68, 0.2)', color: '#EF4444', fontWeight: 700 }} />
          )}
        </Box>
        <Divider sx={{ mb: 3, borderColor: 'rgba(255,255,255,0.08)' }} />
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
              <FileText size={48} color="#64748B" style={{ opacity: 0.5, marginBottom: 16 }} />
              <Typography variant="body1" color="#64748B">
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
                          sx={{ color: '#64748B', fontFamily: 'inherit', fontSize: '0.8rem' }}
                        >
                          {time}
                        </Typography>
                      )}
                    </Box>
                    <Typography
                      variant="body2"
                      sx={{
                        color: '#E0E7FF',
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
