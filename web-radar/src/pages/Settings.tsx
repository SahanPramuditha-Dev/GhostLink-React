import { useState } from 'react';
import { Palette, Wifi, Bell, Shield, Info, RefreshCw } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import {
  Container,
  Typography,
  Paper,
  FormControl,
  InputLabel,
  Select,
  MenuItem,
  FormControlLabel,
  Switch,
  Slider,
  Box,
  Button as MuiButton,
} from '@mui/material';

function SettingsPage() {
  const { setSnackbar, attackConfig, setAttackConfig, themeMode, toggleThemeMode } = useAppContext();
  const [interfaceName, setInterfaceName] = useState('wlan0');
  const [notificationsAttack, setNotificationsAttack] = useState(true);
  const [notificationsPassword, setNotificationsPassword] = useState(true);
  const [encryptVault, setEncryptVault] = useState(true);

  const handleSave = () => {
    setSnackbar({
      open: true,
      message: 'Settings saved successfully!',
      severity: 'success',
    });
  };

  const handleReset = () => {
    setInterfaceName('wlan0');
    setNotificationsAttack(true);
    setNotificationsPassword(true);
    setEncryptVault(true);
    setAttackConfig({
      ssid: attackConfig.ssid,
      minlen: 4,
      maxlen: 8,
      charset: 'abcdefghijklmnopqrstuvwxyz0123456789',
      threads: 2,
      timeout: 5,
      useCache: true,
    });
    setSnackbar({
      open: true,
      message: 'Settings reset to defaults!',
      severity: 'info',
    });
  };

  return (
    <Container maxWidth="xl" disableGutters>
      <Typography variant="h4" component="h1" gutterBottom sx={{ color: 'text.primary' }}>
        Settings
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 4 }}>
        Configure GhostLink preferences
      </Typography>

      <Box sx={{ display: 'flex', flexDirection: 'column', gap: 3, mb: 3 }}>
        {/* Appearance */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Palette size={24} color="#9C27B0" />
            <Typography variant="h6" color="text.primary">Appearance</Typography>
          </Box>
          <FormControl fullWidth>
            <InputLabel id="theme-select-label">Theme</InputLabel>
            <Select
              labelId="theme-select-label"
              value={themeMode}
              label="Theme"
              onChange={() => toggleThemeMode()}
            >
              <MenuItem value="light">Light</MenuItem>
              <MenuItem value="dark">Dark</MenuItem>
            </Select>
          </FormControl>
        </Paper>

        {/* Network */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Wifi size={24} color="#00BCD4" />
            <Typography variant="h6" color="text.primary">Network</Typography>
          </Box>
          <FormControl fullWidth sx={{ mb: 2 }}>
            <InputLabel id="interface-select-label">Wireless Interface</InputLabel>
            <Select
              labelId="interface-select-label"
              value={interfaceName}
              label="Wireless Interface"
              onChange={(e) => setInterfaceName(e.target.value as string)}
            >
              <MenuItem value="wlan0">wlan0</MenuItem>
              <MenuItem value="wlan1">wlan1</MenuItem>
              <MenuItem value="eth0">eth0</MenuItem>
            </Select>
          </FormControl>
          <Typography variant="subtitle2" gutterBottom color="text.primary">Default Attack Config</Typography>
          <FormControl fullWidth sx={{ mb: 1 }}>
            <Typography gutterBottom color="text.primary">Password Length Range</Typography>
            <Slider
              value={[attackConfig.minlen, attackConfig.maxlen]}
              onChange={(_, value) => {
                const [min, max] = value as number[];
                setAttackConfig({ ...attackConfig, minlen: min, maxlen: max });
              }}
              valueLabelDisplay="auto"
              min={1}
              max={12}
            />
          </FormControl>
          <FormControl fullWidth sx={{ mb: 1 }}>
            <Typography gutterBottom color="text.primary">Threads: {attackConfig.threads}</Typography>
            <Slider
              value={attackConfig.threads}
              onChange={(_, value) => setAttackConfig({ ...attackConfig, threads: value as number })}
              min={1}
              max={8}
            />
          </FormControl>
          <FormControl fullWidth sx={{ mb: 1 }}>
            <Typography gutterBottom color="text.primary">Timeout (seconds): {attackConfig.timeout}</Typography>
            <Slider
              value={attackConfig.timeout}
              onChange={(_, value) => setAttackConfig({ ...attackConfig, timeout: value as number })}
              min={3}
              max={30}
            />
          </FormControl>
          <FormControlLabel
            control={
              <Switch
                checked={attackConfig.useCache}
                onChange={(_, checked) => setAttackConfig({ ...attackConfig, useCache: checked })}
              />
            }
            label="Use Cached Passwords"
          />
        </Paper>

        {/* Notifications */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Bell size={24} color="#FF9800" />
            <Typography variant="h6" color="text.primary">Notifications</Typography>
          </Box>
          <FormControlLabel
            control={
              <Switch
                checked={notificationsAttack}
                onChange={(_, checked) => setNotificationsAttack(checked)}
              />
            }
            label="Attack Complete"
            sx={{ display: 'flex', mb: 1 }}
          />
          <Typography variant="body2" color="text.secondary" sx={{ mb: 2, ml: 4 }}>
            Notify when an attack finishes
          </Typography>
          <FormControlLabel
            control={
              <Switch
                checked={notificationsPassword}
                onChange={(_, checked) => setNotificationsPassword(checked)}
              />
            }
            label="Password Found"
            sx={{ display: 'flex', mb: 1 }}
          />
          <Typography variant="body2" color="text.secondary" sx={{ ml: 4 }}>
            Notify when a password is discovered
          </Typography>
        </Paper>

        {/* Security */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Shield size={24} color="#4CAF50" />
            <Typography variant="h6" color="text.primary">Security</Typography>
          </Box>
          <FormControlLabel
            control={
              <Switch
                checked={encryptVault}
                onChange={(_, checked) => setEncryptVault(checked)}
              />
            }
            label="Encrypt Vault"
            sx={{ display: 'flex', mb: 1 }}
          />
          <Typography variant="body2" color="text.secondary" sx={{ ml: 4 }}>
            Encrypt saved passwords
          </Typography>
        </Paper>

        {/* About */}
        <Paper sx={{ p: 3 }}>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 2 }}>
            <Info size={24} color="text.secondary" />
            <Typography variant="h6" color="text.primary">About</Typography>
          </Box>
          <Box sx={{ textAlign: 'center', py: 2 }}>
            <Typography variant="h4" sx={{ fontWeight: 'bold', mb: 1, color: 'text.primary' }}>
              GhostLink
            </Typography>
            <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 1 }}>
              Version 1.0.0
            </Typography>
            <Typography variant="body2" color="text.secondary">
              Wi‑Fi Security Testing Framework
            </Typography>
          </Box>
        </Paper>

        {/* Buttons */}
        <Box sx={{ display: 'flex', gap: 2, justifyContent: 'flex-end' }}>
          <MuiButton
            variant="outlined"
            onClick={handleReset}
            startIcon={<RefreshCw size={18} />}
          >
            Reset
          </MuiButton>
          <MuiButton
            variant="contained"
            color="primary"
            onClick={handleSave}
          >
            Save
          </MuiButton>
        </Box>
      </Box>
    </Container>
  );
}

export default SettingsPage;
