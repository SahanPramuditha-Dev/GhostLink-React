import { createTheme } from '@mui/material/styles';

export const theme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#00BCD4', // Cyan
    },
    secondary: {
      main: '#9C27B0', // Purple
    },
    background: {
      default: '#0A0E1A', // Deep navy
      paper: '#151929', // Slightly lighter navy
    },
  },
  typography: {
    fontFamily: '"Roboto", "Helvetica", "Arial", sans-serif',
  },
  components: {
    MuiButton: {
      styleOverrides: {
        root: {
          textTransform: 'none',
        },
      },
    },
  },
});