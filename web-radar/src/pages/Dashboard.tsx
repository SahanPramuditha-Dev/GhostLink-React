import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Wifi, Zap, Eye, Shield, Activity, CheckCircle2, AlertCircle, Clock, Users, Terminal, Target, Cpu, MemoryStick, HardDrive } from 'lucide-react'
import { useApi } from '../hooks/useApi'
import type { StatusResponse } from '../types'
import {
  Container,
  Typography,
  Paper,
  Box,
  Button as MuiButton,
  Skeleton,
  List,
  ListItem,
  ListItemIcon,
  ListItemText,
  Chip,
  Tooltip
} from '@mui/material'
import {
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip as RechartsTooltip,
  ResponsiveContainer,
  AreaChart,
  Area
} from 'recharts'
import { getStatus, getPerformance, runReconModule } from '../api'
import NetworkTopology from '../components/NetworkTopology'

interface ActivityItem {
  id: string
  type: 'info' | 'success' | 'error' | 'warning'
  title: string
  message: string
  timestamp: number
}

const recentReconHistory = [
  { id: '1', module: 'My Device', status: 'Success', time: '2 minutes ago', result: 'Full device info collected' },
  { id: '2', module: 'Infrastructure', status: 'Success', time: '5 minutes ago', result: 'Gateway, DNS, and network info collected' },
  { id: '3', module: 'Wireless', status: 'Success', time: '10 minutes ago', result: 'Nearby networks scanned' },
  { id: '4', module: 'Full Recon', status: 'Success', time: '15 minutes ago', result: 'Complete reconnaissance executed' }
]

interface PerfDataPoint {
  time: string
  cpu: number
  memory: number
  network: number
}

function Dashboard() {
  const navigate = useNavigate()
  const { data: status, loading, execute } = useApi<StatusResponse>()
  const [activities, setActivities] = useState<ActivityItem[]>([])
  const [perfData, setPerfData] = useState<PerfDataPoint[]>([])
  const [reconData, setReconData] = useState<any>(null)

  const fetchDashboardData = useCallback(async () => {
    try {
      await execute(getStatus)
      setActivities([
        { id: '1', type: 'info', title: 'System initialized', message: 'GHOSTLINK frontend ready', timestamp: Date.now() - 60000 },
        { id: '2', type: 'info', title: 'Connected to backend', message: 'API communication established', timestamp: Date.now() - 50000 }
      ])
    } catch (err) {
      // Error handled by useApi hook
    }
  }, [execute])

  const fetchPerformance = useCallback(async () => {
    try {
      const perf = await getPerformance()
      if (perf) {
        setPerfData(prev => {
          const now = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
          const newData: PerfDataPoint = {
            time: now,
            cpu: perf.cpu || 0,
            memory: perf.memory || 0,
            network: perf.network || 0
          }
          // Keep last 10 data points
          const newPoints = [...prev, newData].slice(-10)
          return newPoints
        })
      }
    } catch (err) {
      console.error('Failed to get performance data:', err)
    }
  }, [])

  // Fetch recon data for network topology
  const fetchReconData = useCallback(async () => {
    try {
      const data = await execute(() => runReconModule('full'))
      if (data?.structured) {
        setReconData(data.structured)
      }
    } catch (err) {
      console.error('Failed to fetch recon data:', err)
    }
  }, [execute])

  useEffect(() => {
    fetchDashboardData()
    fetchPerformance()
    fetchReconData()
    // Real-time updates
    const interval = setInterval(() => {
      fetchPerformance()
    }, 3000)
    return () => clearInterval(interval)
  }, [fetchDashboardData, fetchPerformance, fetchReconData])

  const quickActions = [
    { path: '/scan', label: 'Scan Networks', icon: Wifi, color: '#22C55E', bgColor: 'rgba(34,197,94,0.1)' },
    { path: '/attack', label: 'Start Attack', icon: Zap, color: '#EF4444', bgColor: 'rgba(239,68,68,0.1)' },
    { path: '/progress', label: 'Live Telemetry', icon: Eye, color: '#00BCD4', bgColor: 'rgba(0,188,212,0.1)' },
    { path: '/recon', label: 'Reconnaissance', icon: Activity, color: '#00F5FF', bgColor: 'rgba(0,245,255,0.1)' }
  ]

  const statusCards = [
    {
      label: 'Target Network',
      value: status?.target?.ssid || 'Not selected',
      icon: Target,
      color: '#00F5FF',
      secondary: status?.target ? `Signal: ${status.target.signal}%` : 'Select a target'
    },
    {
      label: 'Attack Status',
      value: status?.attackStatus || 'Idle',
      icon: CheckCircle2,
      color: status?.attackStatus === 'running' ? '#22C55E' : '#9E9E9E',
      secondary: 'Ready to launch'
    },
    {
      label: 'Total Attempts',
      value: status?.totalAttempts?.toLocaleString() || '0',
      icon: Activity,
      color: '#A855F7',
      secondary: 'Since last reset'
    },
    {
      label: 'Cached Passwords',
      value: status?.cachedPasswords?.toLocaleString() || '0',
      icon: Shield,
      color: '#9C27B0',
      secondary: 'Stored in vault'
    }
  ]

  return (
    <Container maxWidth="xl" disableGutters sx={{ p: 3 }}>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 800, mb: 1, color: '#FFFFFF' }}>
          System Dashboard
        </Typography>
        <Typography variant="subtitle1" color="#94A3B8">
          Overview and quick access to all features
        </Typography>
      </Box>

      {/* KPI Cards */}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', sm: 'repeat(2, 1fr)', lg: 'repeat(4, 1fr)' }, gap: 3, mb: 4 }}>
        {loading ? (
          Array.from({ length: 4 }).map((_, i) => (
            <Paper key={i} sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
              <Skeleton variant="rectangular" height={100} sx={{ backgroundColor: 'rgba(255,255,255,0.05)' }} />
            </Paper>
          ))
        ) : (
          statusCards.map((card, i) => (
            <Paper
              key={i}
              sx={{
                p: 3,
                borderRadius: 3,
                backgroundColor: 'rgba(15,23,42,0.9)',
                border: '1px solid rgba(255,255,255,0.08)',
                transition: 'transform 0.2s, box-shadow 0.2s, border-color 0.2s',
                '&:hover': {
                  transform: 'translateY(-4px)',
                  boxShadow: `0 0 30px ${card.color}20`,
                  borderColor: `${card.color}50`
                }
              }}
            >
              <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
                <Box
                  sx={{
                    p: 1.5,
                    borderRadius: 2,
                    backgroundColor: `${card.color}20`
                  }}
                >
                  <card.icon size={28} color={card.color} />
                </Box>
                <Box sx={{ flex: 1 }}>
                  <Typography variant="caption" color="#94A3B8" sx={{ textTransform: 'uppercase', letterSpacing: 1, fontWeight: 700 }}>
                    {card.label}
                  </Typography>
                  <Typography variant="h5" sx={{ fontWeight: 700, mt: 0.5, color: '#FFFFFF' }}>
                    {card.value}
                  </Typography>
                </Box>
              </Box>
              <Typography variant="body2" color="#94A3B8">
                {card.secondary}
              </Typography>
            </Paper>
          ))
        )}
      </Box>

      {/* Network Topology */}
      <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)', mb: 4 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <Wifi size={24} color="#00F5FF" />
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#FFFFFF' }}>Network Topology</Typography>
        </Box>
        <Box sx={{ height: '450px' }}>
          <NetworkTopology 
            devices={reconData?.devices} 
            networkInfo={reconData?.network} 
          />
        </Box>
      </Paper>

      {/* Performance Charts */}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '2fr 1fr' }, gap: 3, mb: 4 }}>
        {/* Main Performance Chart */}
        <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <Activity size={24} color="#00F5FF" />
            <Typography variant="h6" sx={{ fontWeight: 700, color: '#FFFFFF' }}>Real-time Performance</Typography>
          </Box>
          <ResponsiveContainer width="100%" height={300}>
            <AreaChart data={perfData}>
              <defs>
                <linearGradient id="colorCpu" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#00F5FF" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#00F5FF" stopOpacity={0}/>
                </linearGradient>
                <linearGradient id="colorMemory" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#A855F7" stopOpacity={0.3}/>
                  <stop offset="95%" stopColor="#A855F7" stopOpacity={0}/>
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.05)" />
              <XAxis dataKey="time" stroke="#94A3B8" tick={{ fill: '#94A3B8' }} />
              <YAxis stroke="#94A3B8" tick={{ fill: '#94A3B8' }} />
              <RechartsTooltip
                contentStyle={{ backgroundColor: 'rgba(15,23,42,0.95)', border: '1px solid rgba(0,245,255,0.3)', borderRadius: '8px' }}
                itemStyle={{ color: '#E0E7FF' }}
              />
              <Area type="monotone" dataKey="cpu" stroke="#00F5FF" fillOpacity={1} fill="url(#colorCpu)" name="CPU" />
              <Area type="monotone" dataKey="memory" stroke="#A855F7" fillOpacity={1} fill="url(#colorMemory)" name="Memory" />
            </AreaChart>
          </ResponsiveContainer>
        </Paper>

        {/* Quick Stats Cards */}
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <Cpu size={20} color="#00F5FF" />
              <Typography variant="body2" color="#94A3B8" sx={{ fontWeight: 600 }}>CPU Usage</Typography>
            </Box>
            <Typography variant="h3" sx={{ color: '#E0E7FF', fontWeight: 800, mb: 1 }}>
              {perfData[perfData.length - 1]?.cpu}%
            </Typography>
            <Box sx={{ width: '100%', height: 8, backgroundColor: 'rgba(0,0,0,0.3)', borderRadius: 4, overflow: 'hidden' }}>
              <Box
                sx={{
                  height: '100%',
                  width: `${perfData[perfData.length - 1]?.cpu}%`,
                  background: 'linear-gradient(90deg, #00F5FF, #06B6D4)',
                  borderRadius: 4,
                  transition: 'width 0.5s ease-in-out'
                }}
              />
            </Box>
          </Paper>
          
          <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <MemoryStick size={20} color="#A855F7" />
              <Typography variant="body2" color="#94A3B8" sx={{ fontWeight: 600 }}>Memory Usage</Typography>
            </Box>
            <Typography variant="h3" sx={{ color: '#E0E7FF', fontWeight: 800, mb: 1 }}>
              {perfData[perfData.length - 1]?.memory}%
            </Typography>
            <Box sx={{ width: '100%', height: 8, backgroundColor: 'rgba(0,0,0,0.3)', borderRadius: 4, overflow: 'hidden' }}>
              <Box
                sx={{
                  height: '100%',
                  width: `${perfData[perfData.length - 1]?.memory}%`,
                  background: 'linear-gradient(90deg, #A855F7, #7C3AED)',
                  borderRadius: 4,
                  transition: 'width 0.5s ease-in-out'
                }}
              />
            </Box>
          </Paper>

          <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
              <HardDrive size={20} color="#22C55E" />
              <Typography variant="body2" color="#94A3B8" sx={{ fontWeight: 600 }}>Network Activity</Typography>
            </Box>
            <Typography variant="h3" sx={{ color: '#E0E7FF', fontWeight: 800, mb: 1 }}>
              {perfData[perfData.length - 1]?.network}%
            </Typography>
            <Box sx={{ width: '100%', height: 8, backgroundColor: 'rgba(0,0,0,0.3)', borderRadius: 4, overflow: 'hidden' }}>
              <Box
                sx={{
                  height: '100%',
                  width: `${perfData[perfData.length - 1]?.network}%`,
                  background: 'linear-gradient(90deg, #22C55E, #16A34A)',
                  borderRadius: 4,
                  transition: 'width 0.5s ease-in-out'
                }}
              />
            </Box>
          </Paper>
        </Box>
      </Box>

      {/* Quick Actions */}
      <Paper sx={{ p: 3, mb: 4, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <Terminal size={24} color="#00F5FF" />
          <Typography variant="h6" sx={{ fontWeight: 700, color: '#FFFFFF' }}>Quick Actions</Typography>
        </Box>
        <Box sx={{ display: 'flex', flexWrap: 'wrap', gap: 2 }}>
          {quickActions.map((action, i) => (
            <Tooltip key={i} title={`Navigate to ${action.label}`} placement="top">
              <MuiButton
                variant="contained"
                size="large"
                startIcon={<action.icon size={20} />}
                onClick={() => navigate(action.path)}
                sx={{
                  px: 3,
                  py: 1.5,
                  borderRadius: 2,
                  textTransform: 'none',
                  fontWeight: 700,
                  backgroundColor: action.bgColor,
                  color: action.color,
                  border: `1px solid ${action.color}50`,
                  transition: 'transform 0.2s, background-color 0.2s, box-shadow 0.2s',
                  '&:hover': {
                    backgroundColor: `${action.color}20`,
                    transform: 'scale(1.02)',
                    boxShadow: `0 0 20px ${action.color}30`
                  }
                }}
              >
                {action.label}
              </MuiButton>
            </Tooltip>
          ))}
        </Box>
      </Paper>

      {/* Recent Recon History and Activity */}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' }, gap: 3 }}>
        {/* Recent Recon History */}
        <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <Eye size={24} color="#00BCD4" />
            <Typography variant="h6" sx={{ fontWeight: 700, color: '#FFFFFF' }}>Recent Recon History</Typography>
          </Box>
          <List disablePadding>
            {recentReconHistory.map((item) => (
              <ListItem key={item.id} sx={{ px: 0, py: 1.5, borderRadius: 2, mb: 1, backgroundColor: 'rgba(255,255,255,0.02)', '&:hover': { backgroundColor: 'rgba(255,255,255,0.05)' } }}>
                <Box sx={{ flex: 1 }}>
                  <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5, mb: 0.5 }}>
                    <Typography variant="body1" sx={{ fontWeight: 700, color: '#E0E7FF' }}>{item.module}</Typography>
                    <Chip label={item.status} size="small" sx={{ backgroundColor: item.status === 'Success' ? 'rgba(34,197,94,0.1)' : 'rgba(245,158,11,0.1)', color: item.status === 'Success' ? '#22C55E' : '#F59E0B', fontWeight: 700, border: `1px solid ${item.status === 'Success' ? 'rgba(34,197,94,0.3)' : 'rgba(245,158,11,0.3)'}` }} />
                  </Box>
                  <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Typography variant="body2" color="#94A3B8">{item.result}</Typography>
                    <Typography variant="caption" color="#64748B">{item.time}</Typography>
                  </Box>
                </Box>
              </ListItem>
            ))}
          </List>
        </Paper>

        {/* Recent Activity */}
        <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <Clock size={24} color="#A855F7" />
            <Typography variant="h6" sx={{ fontWeight: 700, color: '#FFFFFF' }}>Recent Activity</Typography>
          </Box>
          {loading ? (
            <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
              <Skeleton variant="rectangular" height={60} sx={{ backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: 2 }} />
              <Skeleton variant="rectangular" height={60} sx={{ backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: 2 }} />
              <Skeleton variant="rectangular" height={60} sx={{ backgroundColor: 'rgba(255,255,255,0.05)', borderRadius: 2 }} />
            </Box>
          ) : activities.length === 0 ? (
            <Box sx={{ textAlign: 'center', py: 6 }}>
              <Activity size={48} color="#64748B" style={{ opacity: 0.5, marginBottom: 16 }} />
              <Typography variant="h6" sx={{ mt: 2, color: '#94A3B8' }}>
                No recent activity
              </Typography>
              <Typography variant="body2" color="#64748B">
                Activity will appear here as you use the system
              </Typography>
            </Box>
          ) : (
            <List disablePadding>
              {activities.map((item) => (
                <ListItem key={item.id} sx={{ px: 0, py: 1.5, borderRadius: 2, mb: 1, '&:hover': { backgroundColor: 'rgba(255,255,255,0.03)' } }}>
                  <ListItemIcon sx={{ minWidth: 40 }}>
                    {item.type === 'success' && <CheckCircle size={20} color="#22C55E" />}
                    {item.type === 'error' && <AlertCircle size={20} color="#EF4444" />}
                    {item.type === 'warning' && <AlertCircle size={20} color="#F59E0B" />}
                    {item.type === 'info' && <Activity size={20} color="#00F5FF" />}
                  </ListItemIcon>
                  <ListItemText
                    primary={
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, flexWrap: 'wrap' }}>
                        <Typography variant="body1" sx={{ fontWeight: 600, color: '#E0E7FF' }}>
                          {item.title}
                        </Typography>
                        <Chip
                          label={new Date(item.timestamp).toLocaleTimeString()}
                          size="small"
                          sx={{ backgroundColor: 'rgba(168,85,247,0.1)', color: '#A855F7', fontWeight: 700, border: '1px solid rgba(168,85,247,0.3)' }}
                        />
                      </Box>
                    }
                    secondary={item.message}
                    sx={{ '& .MuiListItemText-secondary': { color: '#94A3B8' } }}
                  />
                </ListItem>
              ))}
            </List>
          )}
        </Paper>
      </Box>

      {/* System Info */}
      <Box sx={{ mt: 4 }}>
        <Paper sx={{ p: 3, borderRadius: 3, backgroundColor: 'rgba(15,23,42,0.9)', border: '1px solid rgba(255,255,255,0.08)' }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <Users size={24} color="#9C27B0" />
            <Typography variant="h6" sx={{ fontWeight: 700, color: '#FFFFFF' }}>System Info</Typography>
          </Box>
          <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2.5 }}>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2" color="#94A3B8">
                Backend Status
              </Typography>
              <Chip
                label="Connected"
                size="small"
                sx={{ backgroundColor: 'rgba(34,197,94,0.1)', color: '#22C55E', fontWeight: 700, border: '1px solid rgba(34,197,94,0.3)' }}
              />
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2" color="#94A3B8">
                Frontend Version
              </Typography>
              <Typography variant="body2" sx={{ color: '#E0E7FF' }}>1.0.0</Typography>
            </Box>
            <Box sx={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <Typography variant="body2" color="#94A3B8">
                Last Updated
              </Typography>
              <Typography variant="body2" sx={{ color: '#E0E7FF' }}>{new Date().toLocaleTimeString()}</Typography>
            </Box>
          </Box>
        </Paper>
      </Box>
    </Container>
  )
}

export default Dashboard
