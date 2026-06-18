import { createTheme } from '@mui/material/styles';

// Dark theme
export const darkTheme = createTheme({
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
    text: {
      primary: '#FFFFFF',
      secondary: '#FFFFFF',
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
    MuiTypography: {
      styleOverrides: {
        subtitle1: {
          color: '#FFFFFF',
        },
        subtitle2: {
          color: '#FFFFFF',
        },
      },
    },
  },
});

// Light theme
export const lightTheme = createTheme({
  palette: {
    mode: 'light',
    primary: {
      main: '#0097A7', // Darker cyan for light mode
    },
    secondary: {
      main: '#7B1FA2', // Darker purple for light mode
    },
    background: {
      default: '#F5F7FA', // Light grey
      paper: '#FFFFFF', // White
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