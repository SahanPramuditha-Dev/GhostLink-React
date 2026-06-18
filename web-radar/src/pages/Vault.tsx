import { useState, useEffect, useCallback } from 'react'
import { Search, Copy, Trash2, Download, Upload, Eye, EyeOff, Shield, AlertCircle } from 'lucide-react'
import { useAppContext } from '../context/AppContext'
import { useApi } from '../hooks/useApi'
import type { VaultEntry } from '../types'
import {
  Container,
  Typography,
  Paper,
  Box,
  Button as MuiButton,
  TextField,
  IconButton,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip,
  Dialog,
  DialogActions,
  DialogContent,
  DialogContentText,
  DialogTitle,
  Chip,
  InputAdornment,
  Skeleton
} from '@mui/material'
import { getVault, deleteVaultEntry, importVault, exportVault } from '../api'

function Vault() {
  const { vault, setVault, setSnackbar } = useAppContext()
  const { loading, execute: executeGetVault } = useApi<VaultEntry[]>()
  const { execute: executeDeleteEntry } = useApi()
  const [search, setSearch] = useState('')
  const [showPasswords, setShowPasswords] = useState(false)
  const [deleteDialog, setDeleteDialog] = useState<{ open: boolean; entry: VaultEntry | null }>({ open: false, entry: null })

  const loadVault = useCallback(async () => {
    try {
      const vaultData = await executeGetVault(getVault)
      if (vaultData) {
        setVault(vaultData)
      }
    } catch (err) {
      // Error handled by useApi hook
    }
  }, [executeGetVault, setVault])

  useEffect(() => {
    loadVault()
  }, [loadVault])

  const filteredVault = vault.filter(entry =>
    entry.ssid.toLowerCase().includes(search.toLowerCase())
  )

  const handleCopyPassword = async (password: string) => {
    try {
      await navigator.clipboard.writeText(password)
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

  const handleDeleteEntry = (entry: VaultEntry) => {
    setDeleteDialog({ open: true, entry })
  }

  const confirmDeleteEntry = async () => {
    if (deleteDialog.entry) {
      try {
        await executeDeleteEntry(() => deleteVaultEntry(deleteDialog.entry!.id))
        const updatedVault = vault.filter(entry => entry.id !== deleteDialog.entry?.id)
        setVault(updatedVault)
        setSnackbar({
          open: true,
          message: 'Entry deleted from vault',
          severity: 'success'
        })
      } catch (err) {
        // Error handled by useApi hook
      }
    }
    setDeleteDialog({ open: false, entry: null })
  }

  const handleExport = async () => {
    try {
      const data = await exportVault()
      const dataStr = JSON.stringify(data, null, 2)
      const dataBlob = new Blob([dataStr], { type: 'application/json' })
      const url = URL.createObjectURL(dataBlob)
      const link = document.createElement('a')
      link.href = url
      link.download = `ghostlink-vault-${new Date().toISOString().split('T')[0]}.json`
      link.click()
      URL.revokeObjectURL(url)
      setSnackbar({
        open: true,
        message: 'Vault exported successfully',
        severity: 'success'
      })
    } catch (err) {
      setSnackbar({
        open: true,
        message: 'Failed to export vault',
        severity: 'error'
      })
    }
  }

  const handleImport = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      const reader = new FileReader()
      reader.onload = async (event) => {
        try {
          const data = JSON.parse(event.target?.result as string)
          await importVault(data)
          setVault(data)
          setSnackbar({
            open: true,
            message: 'Vault imported successfully',
            severity: 'success'
          })
        } catch (err) {
          setSnackbar({
            open: true,
            message: 'Invalid vault file',
            severity: 'error'
          })
        }
      }
      reader.readAsText(file)
    }
  }

  return (
    <Container maxWidth="xl" disableGutters>
      <Box sx={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', mb: 4, flexWrap: 'wrap', gap: 2 }}>
        <Box>
          <Typography variant="h4" component="h1" sx={{ fontWeight: 700, mb: 1, color: 'text.primary' }}>
            Password Vault
          </Typography>
          <Typography variant="subtitle1" color="text.secondary">
            Manage and organize your saved passwords
          </Typography>
        </Box>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap' }}>
          <input
            type="file"
            accept=".json"
            id="import-file"
            hidden
            onChange={handleImport}
          />
          <MuiButton
            variant="outlined"
            size="large"
            startIcon={<Upload size={20} />}
            component="label"
            htmlFor="import-file"
            sx={{
              borderRadius: 1.5,
              textTransform: 'none',
              fontWeight: 600
            }}
          >
            Import
          </MuiButton>
          <MuiButton
            variant="contained"
            size="large"
            startIcon={<Download size={20} />}
            onClick={handleExport}
            disabled={vault.length === 0}
            sx={{
              borderRadius: 1.5,
              textTransform: 'none',
              fontWeight: 600
            }}
          >
            Export
          </MuiButton>
        </Box>
      </Box>

      {/* Search and Controls */}
      <Paper sx={{ p: 3, mb: 3, borderRadius: 2 }}>
        <Box sx={{ display: 'flex', gap: 2, flexWrap: 'wrap', alignItems: 'center' }}>
          <TextField
            fullWidth
            placeholder="Search by SSID..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            slotProps={{
              input: {
                startAdornment: (
                  <InputAdornment position="start">
                    <Search size={20} color="rgba(255,255,255,0.5)" />
                  </InputAdornment>
                )
              }
            }}
            sx={{ flex: { xs: '1 1 100%', md: '1 1 auto' }, minWidth: { xs: '100%', md: 300 } }}
          />
          <Tooltip title={showPasswords ? 'Hide passwords' : 'Show passwords'}>
            <IconButton onClick={() => setShowPasswords(!showPasswords)}>
              {showPasswords ? <EyeOff size={24} /> : <Eye size={24} />}
            </IconButton>
          </Tooltip>
        </Box>
      </Paper>

      {/* Vault Table */}
      <Paper sx={{ borderRadius: 2, overflow: 'hidden' }}>
        {loading ? (
          <Box sx={{ p: 3 }}>
            <Skeleton variant="rectangular" height={400} />
          </Box>
        ) : vault.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 8, px: 2 }}>
            <Shield size={64} color="text.secondary" />
            <Typography variant="h5" sx={{ mt: 3, fontWeight: 600, color: 'text.primary' }}>
              Vault is Empty
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mt: 1, maxWidth: 400, mx: 'auto' }}>
              You haven't saved any passwords yet. Start by running an attack!
            </Typography>
          </Box>
        ) : filteredVault.length === 0 ? (
          <Box sx={{ textAlign: 'center', py: 8, px: 2 }}>
            <AlertCircle size={64} color="text.secondary" />
            <Typography variant="h5" sx={{ mt: 3, fontWeight: 600, color: 'text.primary' }}>
              No Results Found
            </Typography>
            <Typography variant="body1" color="text.secondary" sx={{ mt: 1 }}>
              Try adjusting your search criteria
            </Typography>
          </Box>
        ) : (
          <TableContainer>
            <Table>
              <TableHead sx={{ backgroundColor: 'rgba(255,255,255,0.03)' }}>
                <TableRow>
                  <TableCell sx={{ fontWeight: 700, color: 'text.primary' }}>SSID</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: 'text.primary' }}>Password</TableCell>
                  <TableCell sx={{ fontWeight: 700, color: 'text.primary' }}>Saved On</TableCell>
                  <TableCell sx={{ fontWeight: 700, textAlign: 'right', color: 'text.primary' }}>Actions</TableCell>
                </TableRow>
              </TableHead>
              <TableBody>
                {filteredVault.map((entry) => (
                  <TableRow key={entry.id} hover>
                    <TableCell>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 1.5 }}>
                        <Shield size={18} color="#4CAF50" />
                        <Typography variant="body1" sx={{ fontWeight: 600, color: 'text.primary' }}>
                          {entry.ssid}
                        </Typography>
                      </Box>
                    </TableCell>
                    <TableCell>
                      <Typography
                        variant="body1"
                        sx={{ fontFamily: 'monospace', color: 'text.primary' }}
                      >
                        {showPasswords ? entry.password : '•'.repeat(Math.min(entry.password.length, 20))}
                      </Typography>
                    </TableCell>
                    <TableCell>
                      <Chip
                        label={new Date(entry.timestamp).toLocaleString()}
                        size="small"
                        variant="outlined"
                      />
                    </TableCell>
                    <TableCell align="right">
                      <Box sx={{ display: 'flex', gap: 1, justifyContent: 'flex-end' }}>
                        <Tooltip title="Copy password">
                          <IconButton
                            onClick={() => handleCopyPassword(entry.password)}
                          >
                            <Copy size={20} />
                          </IconButton>
                        </Tooltip>
                        <Tooltip title="Delete entry">
                          <IconButton
                            color="error"
                            onClick={() => handleDeleteEntry(entry)}
                          >
                            <Trash2 size={20} />
                          </IconButton>
                        </Tooltip>
                      </Box>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </TableContainer>
        )}
      </Paper>

      {/* Delete Confirmation Dialog */}
      <Dialog
        open={deleteDialog.open}
        onClose={() => setDeleteDialog({ open: false, entry: null })}
      >
        <DialogTitle>Delete Entry</DialogTitle>
        <DialogContent>
          <DialogContentText>
            Are you sure you want to delete the password for <strong>{deleteDialog.entry?.ssid}</strong>?
            This action cannot be undone.
          </DialogContentText>
        </DialogContent>
        <DialogActions>
          <MuiButton
            onClick={() => setDeleteDialog({ open: false, entry: null })}
          >
            Cancel
          </MuiButton>
          <MuiButton
            onClick={confirmDeleteEntry}
            color="error"
            startIcon={<Trash2 size={18} />}
          >
            Delete
          </MuiButton>
        </DialogActions>
      </Dialog>
    </Container>
  )
}

export default Vault;
