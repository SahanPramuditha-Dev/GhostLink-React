import { useState } from 'react'
import { Wifi, Lock, Unlock, CheckCircle } from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { useApi } from '../hooks/useApi'
import type { WifiNetwork, ScanResponse } from '../types'
import {
  Container,
  Typography,
  Button as MuiButton,
  Paper,
  Table,
  TableContainer,
  TableHead,
  TableBody,
  TableRow,
  TableCell,
  LinearProgress,
  Chip,
  Alert,
  Box,
  TablePagination
} from '@mui/material'
import { scanNetworks, setTarget as setTargetAPI } from '../api'

function Scanner() {
  const { setSelectedNetwork, setSnackbar } = useAppContext()
  const { data: scanData, loading: isScanning, execute: executeScan } = useApi<ScanResponse>()
  const { execute: executeSetTarget } = useApi()
  const [selectedNetwork, setSelectedNetworkState] = useState<WifiNetwork | null>(null)
  const [page, setPage] = useState(0)
  const [rowsPerPage, setRowsPerPage] = useState(5)

  const networks = scanData?.networks || []
  const scanError = scanData?.error || null

  const handleScan = async () => {
    try {
      await executeScan(scanNetworks)
    } catch (err) {
      // Error handled by useApi hook
    }
  }

  const handleSelectTarget = async () => {
    if (selectedNetwork) {
      setSelectedNetwork(selectedNetwork)
      try {
        await executeSetTarget(() => setTargetAPI({
          ssid: selectedNetwork.ssid,
          signal: selectedNetwork.signal ?? 0,
          security: selectedNetwork.security ?? 'Unknown'
        }))
        setSnackbar({
          open: true,
          message: `Target set to ${selectedNetwork.ssid}`,
          severity: "success"
        })
      } catch (err) {
        // Error handled by useApi hook
      }
    }
  }

  const getSecurityColor = (security: string | undefined) => {
    if (!security) return 'default'
    const lower = security.toLowerCase()
    if (lower.includes('wpa3')) return 'info'
    if (lower.includes('wpa2')) return 'success'
    if (lower.includes('wpa')) return 'primary'
    if (lower.includes('open')) return 'warning'
    return 'default'
  }

  const handleChangePage = (_: unknown, newPage: number) => {
    setPage(newPage)
  }

  const handleChangeRowsPerPage = (event: React.ChangeEvent<HTMLInputElement>) => {
    setRowsPerPage(parseInt(event.target.value, 10))
    setPage(0)
  }

  return (
    <Container maxWidth="xl" disableGutters>
      <Box sx={{ mb: 4 }}>
        <Typography variant="h4" component="h1" sx={{ fontWeight: 700, mb: 1 }}>
          Target Discovery
        </Typography>
        <Typography variant="subtitle1" color="text.secondary">
          Scan nearby networks and select a target
        </Typography>
      </Box>

      <Box sx={{ display: 'flex', gap: 2, alignItems: 'center', mb: 3, flexWrap: 'wrap' }}>
        <MuiButton
          variant="contained"
          color="primary"
          startIcon={<Wifi size={20} />}
          onClick={handleScan}
          disabled={isScanning}
          size="large"
        >
          {isScanning ? 'Scanning...' : 'Scan Networks'}
        </MuiButton>
        {selectedNetwork && (
          <Chip
            icon={<CheckCircle size={16} />}
            label={`Target: ${selectedNetwork.ssid}`}
            color="primary"
          />
        )}
      </Box>

      {isScanning && <LinearProgress sx={{ mb: 3, borderRadius: 1 }} />}
      
      {scanError && (
        <Alert severity="error" sx={{ mb: 3, borderRadius: 2 }}>
          {scanError}
        </Alert>
      )}

      {networks.length === 0 && !isScanning && !scanError && (
        <Alert severity="info" sx={{ borderRadius: 2 }}>
          No networks found. Click "Scan Networks" to start.
        </Alert>
      )}

      {networks.length > 0 && (
        <>
          <TableContainer component={Paper} sx={{ borderRadius: 2 }}>
            <Table>
              <TableHead sx={{ backgroundColor: 'rgba(255,255,255,0.03)' }}>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700 }}>SSID</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Signal</TableCell>
                  <TableCell sx={{ fontWeight: 700 }}>Security</TableCell>
                  <TableCell sx={{ fontWeight: 700, display: { xs: 'none', md: 'table-cell' } }}>BSSID</TableCell>
                  <TableCell sx={{ fontWeight: 700, display: { xs: 'none', sm: 'table-cell' } }}>Channel</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {networks.slice(page * rowsPerPage, page * rowsPerPage + rowsPerPage).map((network, index) => (
                  <TableRow
                    key={index}
                    hover
                    onClick={() => setSelectedNetworkState(network)}
                    sx={{
                      cursor: 'pointer',
                      backgroundColor: selectedNetwork?.ssid === network.ssid ? 'rgba(0, 188, 212, 0.1)' : 'transparent',
                      '&:hover': {
                        backgroundColor: selectedNetwork?.ssid === network.ssid ? 'rgba(0, 188, 212, 0.15)' : 'rgba(255,255,255,0.02)'
                      }
                    }}
                  >
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1 }}>
                        {network.security?.toLowerCase() === 'open' ? <Unlock size={16} /> : <Lock size={16} />}
                        <Typography variant="body1" sx={{ fontWeight: selectedNetwork?.ssid === network.ssid ? 600 : 400 }}>
                          {network.ssid}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                        <Box sx={{ width: 100 }}>
                          <LinearProgress
                            variant="determinate"
                            value={network.signal ?? 0}
                            sx={{
                              height: 8,
                              borderRadius: 4,
                              backgroundColor: 'rgba(255,255,255,0.1)',
                              '& .MuiLinearProgress-bar': {
                                backgroundColor: (network.signal ?? 0) > 70 ? '#4caf50' : (network.signal ?? 0) > 30 ? '#ff9800' : '#f44336'
                              }
                            }}
                          />
                        </Box>
                        <Typography variant="body2" sx={{ fontWeight: 600 }}>
                          {network.signal ?? 0}%
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={network.security ?? 'Unknown'}
                        color={getSecurityColor(network.security)}
                        size="small"
                      />
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', md: 'table-cell' } }}>
                      {network.bssid || 'N/A'}
                    </TableCell>
                    <TableCell sx={{ display: { xs: 'none', sm: 'table-cell' } }}>
                      {network.channel || 'N/A'}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            <TablePagination
              rowsPerPageOptions={[5, 10, 25]}
              component="div"
              count={networks.length}
              rowsPerPage={rowsPerPage}
              page={page}
              onPageChange={handleChangePage}
              onRowsPerPageChange={handleChangeRowsPerPage}
            />
          </TableContainer>

          <Box sx={{ mt: 3, display: 'flex', justifyContent: 'flex-end' }}>
            <MuiButton
              variant="contained"
              color="success"
              disabled={!selectedNetwork}
              onClick={handleSelectTarget}
              size="large"
              startIcon={<CheckCircle size={20} />}
            >
              Select Target
            </MuiButton>
          </Box>
        </>
      )}
    </Container>
  )
}

export default Scanner;
