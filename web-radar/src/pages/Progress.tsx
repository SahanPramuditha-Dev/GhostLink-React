import { useState, useEffect, useRef } from 'react'
import { Zap, Eye, CheckCircle, AlertCircle, StopCircle, Activity, Timer, Hash, Terminal } from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { getAttackStatus } from '../api'
import {
  Container,
  Typography,
  Paper,
  Box,
  Button as MuiButton,
  LinearProgress,
  Chip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle
} from '@mui/material'

function Progress() {
  const { selectedNetwork, setSnackbar } = useAppContext()
  const logsEndRef = useRef<HTMLDivElement>(null)
  const [showResultDialog, setShowResultDialog] = useState(false)
  const [hasShownSuccess, setHasShownSuccess] = useState(false)
  const [status, setStatus] = useState<any>({
    running: false,
    attempts: 0,
    current_password: '',
    found_password: null,
    logs: ['Waiting for attack to start...'],
    speed: 0
  })

  // Poll for attack status
  useEffect(() => {
    const pollStatus = async () => {
      try {
        const newStatus = await getAttackStatus()
        setStatus(newStatus)
        
        // Show success dialog if password found AND we haven't shown it yet
        if (newStatus.found_password && !showResultDialog && !hasShownSuccess) {
          setShowResultDialog(true)
          setHasShownSuccess(true)
        }
      } catch (err) {
        console.error('Failed to get attack status:', err)
      }
    }

    pollStatus()
    const interval = setInterval(pollStatus, 500)
    return () => clearInterval(interval)
  }, [showResultDialog, hasShownSuccess])

  // Auto-scroll logs
  useEffect(() => {
    logsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [status.logs])

  // Reset hasShownSuccess when a new attack starts
  useEffect(() => {
    if (status.running) {
      setHasShownSuccess(false)
    }
  }, [status.running])

  const handleStopAttack = async () => {
    try {
      const res = await fetch(`${import.meta.env.VITE_API_BASE_URL || 'http://127.0.0.1:5966'}/api/attack/stop`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' }
      })
      if (res.ok) {
        setSnackbar({
          open: true,
          message: 'Attack stopped successfully',
          severity: 'info'
        })
      }
    } catch (err) {
      setSnackbar({
        open: true,
        message: 'Failed to stop attack',
        severity: 'error'
      })
    }
  }

  const handleCopyPassword = async () => {
    if (status.found_password) {
      try {
        await navigator.clipboard.writeText(status.found_password)
        setSnackbar({
          open: true,
          message: 'Password copied to clipboard',
          severity: 'success'
        })
      } catch (err) {
        setSnackbar({
          open: true,
          message: 'Failed to copy password',
          severity: 'error'
        })
      }
    }
  }

  const progress = Math.min(100, (status.attempts / 500) * 100)

  return (
    <Container maxWidth="xl">
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 4, flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 700, mb: 1 }}>
            Live Telemetry
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Real-time attack monitoring and status
          </Typography>
        </Box>
        {status.running && (
          <MuiButton
            variant="contained"
            color="error"
            size="large"
            startIcon={<StopCircle size={20} />}
            onClick={handleStopAttack}
            sx={{
              borderRadius: 1.5,
              textTransform: 'none',
              fontWeight: 600
            }}
          >
            Stop Attack
          </MuiButton>
        )}
      </Box>

      {/* Target Info */}
      {selectedNetwork && (
        <Paper sx={{ p: 3, mb: 3, borderRadius: 2 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
            <Box
              sx={{
                p: 1.5,
                borderRadius: 1.5,
                backgroundColor: 'rgba(0, 188, 212, 0.1)'
              }}
            >
              <Eye size={24} color="#00BCD4" />
            </Box>
            <Box>
              <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                Target Network
              </Typography>
              <Typography variant="h6" sx={{ fontWeight: 700 }}>
                {selectedNetwork.ssid}
              </Typography>
            </Box>
            <Chip
              label={
                status.running ? 'Running' :
                status.found_password ? 'Success' :
                'Idle'
              }
              color={
                status.running ? 'primary' :
                status.found_password ? 'success' :
                'default'
              }
              sx={{ ml: 'auto' }}
            />
          </Box>
        </Paper>
      )}

      {/* Progress Bar */}
      <Paper sx={{ p: 3, mb: 3, borderRadius: 2 }}>
        <Box sx={{ mb: 2 }}>
          <Box sx={{ display: 'flex', justifyContent: 'space-between', mb: 1 }}>
            <Typography variant="body1" sx={{ fontWeight: 600 }}>
              Attack Progress
            </Typography>
            <Typography variant="body1" sx={{ fontWeight: 700, color: '#00BCD4' }}>
              {Math.round(progress)}%
            </Typography>
          </Box>
          <LinearProgress
            variant="determinate"
            value={progress}
            sx={{
              height: 12,
              borderRadius: 6,
              backgroundColor: 'rgba(255,255,255,0.05)'
            }}
          />
        </Box>
        {status.current_password && status.running && (
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1, color: 'text.secondary' }}>
            <Activity size={16} />
            <Typography variant="body2" sx={{ fontFamily: 'monospace' }}>
              Trying: {status.current_password}
            </Typography>
          </Box>
        )}
      </Paper>

      {/* Metrics Grid */}
      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr 1fr', md: '1fr 1fr 1fr 1fr' }, gap: 3, mb: 3 }}>
        {[
          { label: 'Progress', value: `${Math.round(progress)}%`, icon: Activity, color: '#00BCD4' },
          { label: 'Attempts', value: status.attempts.toLocaleString(), icon: Hash, color: '#FF9800' },
          { label: 'Speed', value: `${status.speed} pw/s`, icon: Zap, color: '#4CAF50' },
          { label: 'Elapsed', value: `${Math.floor(status.attempts / 10)}s`, icon: Timer, color: '#9C27B0' }
        ].map((metric, i) => (
          <Paper key={i} sx={{ p: 3, borderRadius: 2, transition: 'transform 0.2s', '&:hover': { transform: 'translateY(-2px)' } }}>
            <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
              <Box
                sx={{
                  p: 1.5,
                  borderRadius: 1.5,
                  backgroundColor: `${metric.color}20`
                }}
              >
                <metric.icon size={24} color={metric.color} />
              </Box>
              <Box>
                <Typography variant="caption" color="text.secondary" sx={{ textTransform: 'uppercase', letterSpacing: 1 }}>
                  {metric.label}
                </Typography>
                <Typography variant="h5" sx={{ fontWeight: 700 }}>
                  {metric.value}
                </Typography>
              </Box>
            </Box>
          </Paper>
        ))}
      </Box>

      {/* Logs */}
      <Paper sx={{ p: 3, borderRadius: 2 }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
          <Terminal size={24} color="#9C27B0" />
          <Typography variant="h6" sx={{ fontWeight: 600 }}>
            Attack Logs
          </Typography>
        </Box>
        <Box
          sx={{
            background: 'linear-gradient(180deg, #020617 0%, #0f172a 100%)',
            borderRadius: 3,
            p: 3,
            maxHeight: '70vh',
            height: '70vh',
            overflowY: 'auto',
            fontFamily: '"JetBrains Mono", "Fira Code", "Courier New", Courier, monospace',
            fontSize: '0.9rem',
            lineHeight: 1.8,
            border: '1px solid rgba(34, 197, 94, 0.3)',
            boxShadow: '0 0 30px rgba(34, 197, 94, 0.1), inset 0 0 60px rgba(0, 0, 0, 0.3)',
            position: 'relative',
            '&::before': {
              content: '""',
              position: 'absolute',
              top: 0,
              left: 0,
              right: 0,
              height: '2px',
              background: 'linear-gradient(90deg, transparent, #22C55E, transparent)',
              borderRadius: '3px 3px 0 0',
            },
            '&::-webkit-scrollbar': {
              width: '8px',
            },
            '&::-webkit-scrollbar-track': {
              background: 'rgba(0, 0, 0, 0.2)',
              borderRadius: '4px',
            },
            '&::-webkit-scrollbar-thumb': {
              background: 'linear-gradient(180deg, #22C55E, #16A34A)',
              borderRadius: '4px',
            },
          }}
        >
          {status.logs.map((log: string, i: number) => (
            <Box key={i} sx={{ mb: 0.75 }}>
              <Typography
                variant="body2"
                component="span"
                sx={{
                  color: '#BBF7D0',
                  textShadow: '0 0 5px rgba(34, 197, 94, 0.2)',
                }}
              >
                {log}
              </Typography>
            </Box>
          ))}
          <div ref={logsEndRef} />
        </Box>
      </Paper>

      {/* Result Dialog */}
      <Dialog
        open={showResultDialog}
        onClose={() => setShowResultDialog(false)}
      >
        <DialogTitle>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
            {status.found_password ? <CheckCircle size={28} color="#4CAF50" /> : <AlertCircle size={28} color="#F44336" />}
            {status.found_password ? 'Attack Successful!' : 'Attack Failed'}
          </Box>
        </DialogTitle>
        <DialogContent>
          {status.found_password && (
            <Box>
              <DialogContentText sx={{ mb: 2 }}>
                Password found for <strong>{selectedNetwork?.ssid}</strong>:
              </DialogContentText>
              <Paper sx={{ p: 2, mb: 2, backgroundColor: 'rgba(76, 175, 80, 0.1)' }}>
                <Typography variant="h5" sx={{ fontFamily: 'monospace', fontWeight: 700, color: '#4CAF50' }}>
                  {status.found_password}
                </Typography>
              </Paper>
              <DialogContentText>
                Statistics:
                <br />
                • Attempts: {status.attempts.toLocaleString()}
                <br />
                • Time elapsed: {Math.floor(status.attempts / 10)} seconds
              </DialogContentText>
            </Box>
          )}
          {!status.found_password && status.running === false && (
            <DialogContentText>
              The attack was stopped or did not find the password.
            </DialogContentText>
          )}
        </DialogContent>
        <DialogActions>
          {status.found_password && (
            <MuiButton
              onClick={handleCopyPassword}
              startIcon={<Activity size={18} />}
            >
              Copy Password
            </MuiButton>
          )}
          <MuiButton onClick={() => setShowResultDialog(false)}>
            Close
          </MuiButton>
        </DialogActions>
      </Dialog>
    </Container>
  )
}

export default Progress
