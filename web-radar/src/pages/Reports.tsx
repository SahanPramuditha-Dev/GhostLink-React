import { FileText, Download, Shield, Zap, Calendar, Hash, Clock } from 'lucide-react';
import { useAppContext } from '../context/AppContext';
import {
  Container,
  Typography,
  Paper,
  Button as MuiButton,
  Box,
  Chip,
} from '@mui/material';

function Reports() {
  const { reports } = useAppContext();

  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60);
    const secs = Math.floor(seconds % 60);
    return `${mins}m ${secs}s`;
  };

  return (
    <Container maxWidth="xl" disableGutters>
      <Typography variant="h4" component="h1" gutterBottom sx={{ color: 'text.primary' }}>
        Reports
      </Typography>
      <Typography variant="subtitle1" color="text.secondary" sx={{ mb: 4 }}>
        View and export attack reports
      </Typography>

      {reports.length === 0 ? (
        <Paper sx={{ p: 6, textAlign: 'center' }}>
          <Box sx={{ display: 'flex', justifyContent: 'center', mb: 2 }}>
            <FileText size={64} color="text.secondary" />
          </Box>
          <Typography variant="h6" gutterBottom color="text.primary">
            No Reports
          </Typography>
          <Typography color="text.secondary">
            No attack reports generated yet. Run an attack to create a report.
          </Typography>
        </Paper>
      ) : (
        <Box sx={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
          {reports.slice().reverse().map((report) => (
            <Paper key={report.id} sx={{ p: 3 }}>
              <Box sx={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between' }}>
                <Box sx={{ display: 'flex', alignItems: 'flex-start', gap: 3 }}>
                  <Box
                    sx={{
                      p: 2,
                      borderRadius: 2,
                      backgroundColor: report.verified
                        ? 'rgba(76, 175, 80, 0.1)'
                        : 'rgba(244, 67, 54, 0.1)',
                    }}
                  >
                    {report.verified ? (
                      <Shield size={32} color="#4CAF50" />
                    ) : (
                      <Zap size={32} color="#F44336" />
                    )}
                  </Box>

                  <Box sx={{ flex: 1 }}>
                    <Typography variant="h6" gutterBottom color="text.primary">
                      {report.ssid}
                    </Typography>

                    <Box sx={{ display: 'flex', alignItems: 'center', gap: 3, mt: 1, flexWrap: 'wrap' }}>
                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'text.secondary' }}>
                        <Calendar size={16} />
                        <Typography variant="body2" color="text.secondary">
                          {new Date(report.timestamp).toLocaleDateString()} {new Date(report.timestamp).toLocaleTimeString()}
                        </Typography>
                      </Box>

                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'text.secondary' }}>
                        <Hash size={16} />
                        <Typography variant="body2" color="text.secondary">
                          {report.attempts.toLocaleString()} attempts
                        </Typography>
                      </Box>

                      <Box sx={{ display: 'flex', alignItems: 'center', gap: 0.5, color: 'text.secondary' }}>
                        <Clock size={16} />
                        <Typography variant="body2" color="text.secondary">
                          {formatDuration(report.elapsed)}
                        </Typography>
                      </Box>

                      <Chip
                        label={report.verified ? 'Success' : 'Failed'}
                        color={report.verified ? 'success' : 'error'}
                        size="small"
                      />
                    </Box>

                    {report.password && report.verified && (
                      <Paper
                        sx={{
                          mt: 2,
                          p: 2,
                          backgroundColor: 'rgba(0,0,0,0.05)',
                          borderRadius: 1,
                        }}
                      >
                        <Typography variant="body2" color="text.secondary">
                          Discovered Password:
                        </Typography>
                        <Typography
                          variant="body1"
                          sx={{ fontFamily: 'monospace', fontWeight: 'bold', color: '#4CAF50' }}
                        >
                          {report.password}
                        </Typography>
                      </Paper>
                    )}
                  </Box>
                </Box>

                <MuiButton
                  variant="outlined"
                  size="small"
                  startIcon={<Download size={16} />}
                >
                  Export
                </MuiButton>
              </Box>
            </Paper>
          ))}
        </Box>
      )}
    </Container>
  );
}

export default Reports;
