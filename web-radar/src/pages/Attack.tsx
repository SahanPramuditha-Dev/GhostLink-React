import { useState, useEffect, useCallback } from 'react'
import { useNavigate } from 'react-router-dom'
import { Zap, Play, Settings, Shield, List as ListIcon, Hash, Clock, Upload, X } from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { useApi } from '../hooks/useApi'
import type { AttackConfig, AttackProfile } from '../types'
import {
  Container,
  Typography,
  Paper,
  Button as MuiButton,
  TextField,
  Select,
  MenuItem,
  FormControl,
  InputLabel,
  Slider,
  Switch,
  FormControlLabel,
  Box,
  Alert,
  Chip,
} from '@mui/material'
import { getProfiles, startAttack } from '../api'

// Mock profiles (matches ghostlink/engine/profiles.py)
const ATTACK_PROFILES: AttackProfile[] = [
  { id: '1', name: 'Numeric PINs', charset: '0123456789', description: '0-9 only' },
  { id: '2', name: 'Lowercase Letters', charset: 'abcdefghijklmnopqrstuvwxyz', description: 'a-z only' },
  { id: '3', name: 'Lower + Numeric', charset: 'abcdefghijklmnopqrstuvwxyz0123456789', description: 'a-z + 0-9' },
  { id: '4', name: 'Alphanumeric', charset: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789', description: 'a-z + A-Z + 0-9' },
  { id: '5', name: 'Full Charset', charset: 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()_+-=[]{}|;:,.<>?', description: 'All characters' },
]

function Attack() {
  const navigate = useNavigate()
  const { selectedNetwork, attackConfig, setAttackConfig, setSnackbar } = useAppContext()
  const { execute: executeGetProfiles } = useApi<AttackProfile[]>()
  const { execute: executeStartAttack } = useApi()
  const [selectedProfile, setSelectedProfile] = useState<string>('3')
  const [wordlistPath, setWordlistPath] = useState<string>('')
  const [profiles, setProfiles] = useState<AttackProfile[]>(ATTACK_PROFILES)

  const fetchProfiles = useCallback(async () => {
    try {
      const data = await executeGetProfiles(getProfiles)
      if (data && data.length > 0) {
        setProfiles(data)
      }
    } catch (err) {
      // Error handled by useApi hook
    }
  }, [executeGetProfiles])

  useEffect(() => {
    fetchProfiles()
  }, [fetchProfiles])

  useEffect(() => {
    if (selectedNetwork) {
      setAttackConfig((prev: AttackConfig) => {
        if (prev.ssid !== selectedNetwork.ssid) {
          return { ...prev, ssid: selectedNetwork.ssid }
        }
        return prev
      })
    }
  }, [selectedNetwork, setAttackConfig])

  useEffect(() => {
    const profile = profiles.find(p => p.id === selectedProfile)
    if (profile) {
      setAttackConfig((prev: AttackConfig) => {
        if (prev.charset !== profile.charset) {
          return { ...prev, charset: profile.charset }
        }
        return prev
      })
    }
  }, [selectedProfile, setAttackConfig, profiles])

  const handleStartAttack = async () => {
    if (!attackConfig.ssid) {
      setSnackbar({
        open: true,
        message: "Please select a target network first!",
        severity: "error"
      })
      return
    }
    try {
      await executeStartAttack(() => startAttack({
        ssid: attackConfig.ssid,
        minlen: attackConfig.minlen,
        maxlen: attackConfig.maxlen,
        charset: attackConfig.charset,
        threads: attackConfig.threads,
        timeout: attackConfig.timeout,
        useCache: attackConfig.useCache,
      }))
      navigate('/progress')
    } catch (err) {
      // Error handled by useApi hook
    }
  }

  return (
    <Container maxWidth="xl" disableGutters>
      <Typography variant="h4" component="h1" gutterBottom>
        Attack Configuration
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 4 }}>
        Configure and launch a brute-force attack
      </Typography>

      {selectedNetwork && (
        <Chip
          icon={<Shield size={16} />}
          label={`Target: ${selectedNetwork.ssid}`}
          color="primary"
          sx={{ mb: 3 }}
        />
      )}

      <Box sx={{ display: 'grid', gridTemplateColumns: { xs: '1fr', lg: '1fr 1fr' }, gap: 4 }}>
        {/* Configuration Panel */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <Settings size={24} color="#9C27B0" />
            <Typography variant="h6">Configuration</Typography>
          </Box>

          {!selectedNetwork && (
            <Alert severity="warning" sx={{ mb: 3 }}>
              No target network selected! Please select a network from the Scan & Select page.
            </Alert>
          )}

          <TextField
            fullWidth
            label="Target SSID"
            value={attackConfig.ssid}
            onChange={(e) => setAttackConfig({ ...attackConfig, ssid: e.target.value })}
            placeholder="Enter network SSID"
            sx={{ mb: 3 }}
            disabled
          />

          <FormControl fullWidth sx={{ mb: 3 }}>
            <InputLabel id="attack-profile-label">Attack Profile</InputLabel>
            <Select
              labelId="attack-profile-label"
              value={selectedProfile}
              label="Attack Profile"
              onChange={(e) => setSelectedProfile(e.target.value as string)}
            >
              {profiles.map((p) => (
                <MenuItem key={p.id} value={p.id}>
                  {p.name} ({p.description})
                </MenuItem>
              ))}
            </Select>
          </FormControl>

          <FormControl fullWidth sx={{ mb: 3 }}>
            <Typography gutterBottom>Password Length Range</Typography>
            <Slider
              value={[attackConfig.minlen, attackConfig.maxlen]}
              onChange={(_, value) => {
                const [min, max] = value as number[]
                setAttackConfig({ ...attackConfig, minlen: min, maxlen: max })
              }}
              valueLabelDisplay="auto"
              min={1}
              max={12}
            />
            <Box sx={{ display: 'flex', justifyContent: 'space-between' }}>
              <Typography variant="caption" color="text.secondary">
                Min: {attackConfig.minlen}
              </Typography>
              <Typography variant="caption" color="text.secondary">
                Max: {attackConfig.maxlen}
              </Typography>
            </Box>
          </FormControl>

          <FormControl fullWidth sx={{ mb: 3 }}>
            <Typography gutterBottom>Threads: {attackConfig.threads}</Typography>
            <Slider
              value={attackConfig.threads}
              onChange={(_, value) => setAttackConfig({ ...attackConfig, threads: value as number })}
              min={1}
              max={8}
            />
          </FormControl>

          <FormControl fullWidth sx={{ mb: 3 }}>
            <Typography gutterBottom>Timeout (seconds): {attackConfig.timeout}</Typography>
            <Slider
              value={attackConfig.timeout}
              onChange={(_, value) => setAttackConfig({ ...attackConfig, timeout: value as number })}
              min={3}
              max={30}
            />
          </FormControl>

          <TextField
            fullWidth
            label="Custom Charset"
            value={attackConfig.charset}
            onChange={(e) => setAttackConfig({ ...attackConfig, charset: e.target.value })}
            multiline
            rows={3}
            sx={{ mb: 3 }}
          />

          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <TextField
              fullWidth
              label="Wordlist Path"
              value={wordlistPath}
              placeholder="Select a wordlist file"
              slotProps={{ input: { readOnly: true } }}
            />
            {wordlistPath && (
              <MuiButton
                variant="outlined"
                color="error"
                size="small"
                onClick={() => setWordlistPath('')}
                startIcon={<X size={16} />}
              >
                Clear
              </MuiButton>
            )}
            <MuiButton
              variant="outlined"
              component="label"
              startIcon={<Upload size={16} />}
            >
              Browse
              <input
                type="file"
                hidden
                onChange={(e) => {
                  if (e.target.files?.[0]) {
                    setWordlistPath(e.target.files[0].name)
                  }
                }}
              />
            </MuiButton>
          </Box>

          <FormControlLabel
            control={
              <Switch
                checked={attackConfig.useCache}
                onChange={(_, checked) => setAttackConfig({ ...attackConfig, useCache: checked })}
              />
            }
            label="Include cached passwords"
            sx={{ mb: 3 }}
          />

          <MuiButton
            fullWidth
            variant="contained"
            color="error"
            size="large"
            startIcon={<Play size={20} />}
            onClick={handleStartAttack}
            disabled={!attackConfig.ssid}
          >
            Start Attack
          </MuiButton>
        </Paper>

        {/* Info Panel */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 3 }}>
            <ListIcon size={24} color="#00BCD4" />
            <Typography variant="h6">Attack Summary</Typography>
          </Box>

          <Box sx={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 2, mb: 4 }}>
            <Paper sx={{ p: 2, textAlign: 'center' }}>
              <Box sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
                <Hash size={32} color="#FFC107" />
              </Box>
              <Typography variant="h5">{attackConfig.charset.length}</Typography>
              <Typography variant="caption" color="text.secondary">Charset Size</Typography>
            </Paper>

            <Paper sx={{ p: 2, textAlign: 'center' }}>
              <Box sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
                <Clock size={32} color="#00BCD4" />
              </Box>
              <Typography variant="h5">{attackConfig.timeout}s</Typography>
              <Typography variant="caption" color="text.secondary">Timeout</Typography>
            </Paper>

            <Paper sx={{ p: 2, textAlign: 'center' }}>
              <Box sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
                <Zap size={32} color="#FF9800" />
              </Box>
              <Typography variant="h5">{attackConfig.threads}</Typography>
              <Typography variant="caption" color="text.secondary">Threads</Typography>
            </Paper>

            <Paper sx={{ p: 2, textAlign: 'center' }}>
              <Box sx={{ display: 'flex', justifyContent: 'center', mb: 1 }}>
                <Shield size={32} color="#4CAF50" />
              </Box>
              <Typography variant="h5">{attackConfig.useCache ? 'Yes' : 'No'}</Typography>
              <Typography variant="caption" color="text.secondary">Use Cache</Typography>
            </Paper>
          </Box>

          <Alert severity="info">
            <Typography variant="body2">
              <strong>Note:</strong> This is a demo application. In real usage, ensure you have explicit permission to test the target network.
            </Typography>
          </Alert>
        </Paper>
      </Box>
    </Container>
  )
}

export default Attack;
