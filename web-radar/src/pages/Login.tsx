import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  Paper,
  CardContent,
  Typography,
  TextField,
  Button,
  Alert,
  CircularProgress,
  InputAdornment,
  IconButton,
  Box,
} from '@mui/material';
import {
  Eye,
  EyeOff,
} from 'lucide-react';
import { useAppContext } from '../context/AppContext';

function LoginPage() {
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState('');
  const navigate = useNavigate();
  const { setSnackbar } = useAppContext();

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError('');

    try {
      await new Promise(resolve => setTimeout(resolve, 1000));
      if (password === 'demo123') {
        setSnackbar({
          open: true,
          message: 'Login successful!',
          severity: 'success',
        });
        navigate('/');
      } else {
        setError('Invalid credentials');
      }
    } catch (err) {
      setError('Login failed');
    } finally {
      setLoading(false);
    }
  };

  return (
    <Box
      sx={{
        display: 'flex',
        justifyContent: 'center',
        alignItems: 'center',
        minHeight: 'calc(100vh - 150px)',
      }}
    >
      <Paper elevation={3} sx={{ maxWidth: 400, width: '100%', p: 4 }}>
        <CardContent>
          <Typography variant="h4" component="h1" gutterBottom align="center">
            GHOSTLINK Login
          </Typography>
          {error && (
            <Alert severity="error" sx={{ mb: 2 }}>
              {error}
            </Alert>
          )}
          <Box component="form" onSubmit={handleSubmit} sx={{ mt: 2 }}>
            <TextField
              fullWidth
              label="Password"
              type={showPassword ? 'text' : 'password'}
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              slotProps={{
                input: {
                  endAdornment: (
                    <InputAdornment position="end">
                      <IconButton
                        onClick={() => setShowPassword(!showPassword)}
                        edge="end"
                      >
                        {showPassword ? <EyeOff /> : <Eye />}
                      </IconButton>
                    </InputAdornment>
                  ),
                },
              }}
              sx={{ mb: 3 }}
            />
            <Button
              type="submit"
              variant="contained"
              color="primary"
              fullWidth
              disabled={loading}
            >
              {loading ? (
                <CircularProgress size={24} sx={{ mr: 1 }} />
              ) : null}
              {loading ? 'Logging in...' : 'Login'}
            </Button>
          </Box>
        </CardContent>
      </Paper>
    </Box>
  );
}

export default LoginPage;
