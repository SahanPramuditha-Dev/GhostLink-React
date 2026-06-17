import { Suspense, lazy } from 'react'
import { Routes, Route } from 'react-router-dom'
import { AppShell } from './components/AppShell'
import { Box, CircularProgress, Typography } from '@mui/material'

const LoginPage = lazy(() => import('./pages/Login'))
const Dashboard = lazy(() => import('./pages/Dashboard'))
const Scanner = lazy(() => import('./pages/Scanner'))
const Attack = lazy(() => import('./pages/Attack'))
const Progress = lazy(() => import('./pages/Progress'))
const Recon = lazy(() => import('./pages/Recon'))
const Vault = lazy(() => import('./pages/Vault'))
const Reports = lazy(() => import('./pages/Reports'))
const SettingsPage = lazy(() => import('./pages/Settings'))
const HelpPage = lazy(() => import('./pages/Help'))
const LogsPage = lazy(() => import('./pages/Logs'))

function PageLoader() {
  return (
    <Box
      sx={{
        display: 'flex',
        flexDirection: 'column',
        alignItems: 'center',
        justifyContent: 'center',
        height: '50vh',
        gap: 2
      }}
    >
      <CircularProgress size={40} />
      <Typography variant="body1" color="text.secondary">
        Loading...
      </Typography>
    </Box>
  );
}

function App() {
  return (
    <AppShell>
      <Suspense fallback={<PageLoader />}>
        <Routes>
          <Route path="/login" element={<LoginPage />} />
          <Route path="/" element={<Dashboard />} />
          <Route path="/scan" element={<Scanner />} />
          <Route path="/attack" element={<Attack />} />
          <Route path="/progress" element={<Progress />} />
          <Route path="/recon" element={<Recon />} />
          <Route path="/vault" element={<Vault />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/help" element={<HelpPage />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="/logs" element={<LogsPage />} />
        </Routes>
      </Suspense>
    </AppShell>
  );
}

export default App;
