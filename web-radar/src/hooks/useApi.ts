import { useState, useCallback } from 'react';
import { useAppContext } from '../context/AppContext';

interface UseApiState<T> {
  data: T | null;
  loading: boolean;
  error: string | null;
}

export function useApi<T>() {
  const [state, setState] = useState<UseApiState<T>>({
    data: null,
    loading: false,
    error: null,
  });
  const { setSnackbar } = useAppContext();

  const execute = useCallback(
    async (apiCall: () => Promise<T>, options?: { showError: boolean }) => {
      const { showError = true } = options || {};
      setState({ data: null, loading: true, error: null });
      try {
        const data = await apiCall();
        setState({ data, loading: false, error: null });
        return data;
      } catch (err) {
        const errorMessage = err instanceof Error ? err.message : 'An error occurred';
        setState({ data: null, loading: false, error: errorMessage });
        if (showError) {
          setSnackbar({
            open: true,
            message: errorMessage,
            severity: 'error',
          });
        }
        throw err;
      }
    },
    [setSnackbar]
  );

  return { ...state, execute };
}
