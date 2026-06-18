import { useState, useEffect } from 'react'
import {
  AppBar,
  Toolbar,
  Typography,
  IconButton,
  Drawer,
  List as MuiList,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText,
  Box,
  Snackbar,
  Alert,
  useTheme,
  useMediaQuery,
  Chip,
} from '@mui/material'
import {
  Menu as MenuIcon,
  Home,
  Wifi,
  Zap,
  Eye,
  Shield,
  HelpCircle,
  Settings,
  FileText,
  Lock,
  List as ListIcon,
  X,
  Target,
  Sun,
  Moon,
} from 'lucide-react'
import { useLocation, useNavigate } from 'react-router-dom'
import { useAppContext } from '../context/AppContext'
import GhostlinkLogo from '../assets/GhostlinkLogo.png'

const DRAWER_WIDTH = 260

interface AppShellProps {
  children: React.ReactNode
}

export const AppShell: React.FC<AppShellProps> = ({ children }) => {
  const [mobileOpen, setMobileOpen] = useState(false)
  const { setIsAdmin, selectedNetwork, snackbar, setSnackbar, themeMode, toggleThemeMode } = useAppContext()

  const theme = useTheme()
  const isMobile = useMediaQuery(theme.breakpoints.down('md'))
  const navigate = useNavigate()
  const location = useLocation()

  useEffect(() => {
    const checkAdmin = async () => {
      try {
        setIsAdmin(true)
      } catch (error) {
        setIsAdmin(false)
      }
    }
    checkAdmin()
  }, [setIsAdmin])

  const handleSnackbarClose = () => {
    setSnackbar({ ...snackbar, open: false })
  }

  const navItems = [
    { path: '/', label: 'Dashboard', icon: Home },
    { path: '/scan', label: 'Scan & Select', icon: Wifi },
    { path: '/attack', label: 'Attack Config', icon: Zap },
    { path: '/progress', label: 'Live Telemetry', icon: Eye },
    { path: '/recon', label: 'Reconnaissance', icon: Lock },
    { path: '/vault', label: 'Password Vault', icon: Shield },
    { path: '/reports', label: 'Reports', icon: FileText },
    { path: '/logs', label: 'Log Viewer', icon: ListIcon },
    { path: '/help', label: 'Help & Info', icon: HelpCircle },
    { path: '/settings', label: 'Settings', icon: Settings },
  ]

  const drawer = (
    <Box sx={{ height: '100%', display: 'flex', flexDirection: 'column' }}>
      <Toolbar sx={{ 
        minHeight: '72px !important', 
        borderBottom: 1, 
        borderColor: 'divider',
        px: 3 
      }}>
        <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
          <Box
            sx={{
              width: 56,
              height: 56,
              borderRadius: '50%',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              backgroundColor: 'rgba(0, 245, 255, 0.05)',
              border: '2px solid rgba(0, 245, 255, 0.3)',
              boxShadow: '0 0 20px rgba(0, 245, 255, 0.2)',
              transition: 'all 0.3s ease',
              '&:hover': {
                borderColor: 'rgba(0, 245, 255, 0.6)',
                boxShadow: '0 0 30px rgba(0, 245, 255, 0.4)',
              },
            }}
          >
            <img 
              src={GhostlinkLogo} 
              alt="GHOSTLINK Logo" 
              style={{ 
                width: '80%', 
                height: '80%', 
                objectFit: 'contain',
                borderRadius: '50%', 
              }} 
            />
          </Box>
          <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 700 }}>
            GHOSTLINK
          </Typography>
        </Box>
        {isMobile && (
          <IconButton
            onClick={() => setMobileOpen(false)}
            sx={{ ml: 'auto' }}
          >
            <X size={24} />
          </IconButton>
        )}
      </Toolbar>
      <MuiList sx={{ flexGrow: 1, px: 2, py: 1 }}>
        {navItems.map((item) => (
          <ListItem key={item.path} disablePadding sx={{ mb: 0.5 }}>
            <ListItemButton
              selected={location.pathname === item.path}
              onClick={() => {
                navigate(item.path)
                if (isMobile) setMobileOpen(false)
              }}
              sx={{
                borderRadius: 2,
                '&.Mui-selected': {
                  backgroundColor: 'rgba(0, 188, 212, 0.1)',
                  '&:hover': {
                    backgroundColor: 'rgba(0, 188, 212, 0.15)',
                  },
                  '& .MuiListItemIcon-root': {
                    color: '#00BCD4',
                  },
                },
              }}
            >
              <ListItemIcon>
                <item.icon size={20} />
              </ListItemIcon>
              <ListItemText primary={item.label} sx={{ '& .MuiListItemText-primary': { fontWeight: 500 } }} />
            </ListItemButton>
          </ListItem>
        ))}
      </MuiList>
    </Box>
  )

  return (
    <Box sx={{ display: 'flex' }}>
      <AppBar
        position="fixed"
        sx={{
          width: { md: `calc(100% - ${DRAWER_WIDTH}px)` },
          ml: { md: `${DRAWER_WIDTH}px` },
          backgroundColor: (theme) => theme.palette.background.paper,
          boxShadow: 'none',
          borderBottom: 1,
          borderColor: 'divider',
        }}
      >
        <Toolbar sx={{ minHeight: '72px !important' }}>
          <IconButton
            color="inherit"
            aria-label="open drawer"
            edge="start"
            onClick={() => setMobileOpen(true)}
            sx={{ mr: 2, display: { md: 'none' } }}
          >
            <MenuIcon size={24} />
          </IconButton>
          <Box>
            <Typography variant="h6" noWrap component="div" sx={{ fontWeight: 600 }}>
              {navItems.find((item) => item.path === location.pathname)?.label || 'Dashboard'}
            </Typography>
          </Box>
          <Box sx={{ ml: 'auto', display: 'flex', alignItems: 'center', gap: 1 }}>
            <IconButton
              onClick={toggleThemeMode}
              color="inherit"
              aria-label="Toggle theme"
            >
              {themeMode === 'dark' ? <Sun size={20} /> : <Moon size={20} />}
            </IconButton>
            {selectedNetwork && (
              <>
                <Target size={18} color={theme.palette.primary.main} />
                <Chip
                  label={`Target: ${selectedNetwork.ssid}`}
                  size="small"
                  sx={{
                    backgroundColor: `${theme.palette.primary.main}1A`, // 10% opacity
                    color: theme.palette.primary.main,
                    fontWeight: 500,
                  }}
                />
              </>
            )}
          </Box>
        </Toolbar>
      </AppBar>
      <Box
        component="nav"
        sx={{ width: { md: DRAWER_WIDTH }, flexShrink: { md: 0 } }}
        aria-label="main navigation"
      >
        <Drawer
          variant="temporary"
          open={mobileOpen}
          onClose={() => setMobileOpen(false)}
          ModalProps={{ keepMounted: true }}
          sx={{
            display: { xs: 'block', md: 'none' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: DRAWER_WIDTH,
              backgroundColor: (theme) => theme.palette.background.paper,
              borderRight: 'none',
            },
          }}
        >
          {drawer}
        </Drawer>
        <Drawer
          variant="permanent"
          sx={{
            display: { xs: 'none', md: 'block' },
            '& .MuiDrawer-paper': {
              boxSizing: 'border-box',
              width: DRAWER_WIDTH,
              backgroundColor: (theme) => theme.palette.background.paper,
              borderRight: 1,
              borderColor: 'divider',
            },
          }}
          open
        >
          {drawer}
        </Drawer>
      </Box>
      <Box
        component="main"
        sx={{
          flexGrow: 1,
          p: { xs: 2, sm: 3, md: 4 },
          mt: '72px',
          minHeight: 'calc(100vh - 72px)',
          backgroundColor: 'background.default',
        }}
      >
        {children}
      </Box>
      <Snackbar
        open={snackbar.open}
        autoHideDuration={4000}
        onClose={handleSnackbarClose}
        anchorOrigin={{ vertical: 'bottom', horizontal: 'right' }}
      >
        <Alert
          severity={snackbar.severity}
          sx={{
            width: '100%',
            borderRadius: 2,
            boxShadow: 3,
          }}
        >
          {snackbar.message}
        </Alert>
      </Snackbar>
    </Box>
  )
}
