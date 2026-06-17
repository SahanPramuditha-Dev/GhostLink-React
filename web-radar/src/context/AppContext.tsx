import { createContext, useContext, useState, useEffect } from 'react';
import type { ReactNode } from 'react';
import type { WifiNetwork, AttackConfig, VaultEntry, Report } from '../types';
import { getVault, addReport as addReportApi, checkAdmin, getReports } from '../api';

interface AppContextType {
  selectedNetwork: WifiNetwork | null;
  setSelectedNetwork: (network: WifiNetwork | null) => void;
  attackConfig: AttackConfig;
  setAttackConfig: (config: AttackConfig | ((prev: AttackConfig) => AttackConfig)) => void;
  vault: VaultEntry[];
  setVault: (vault: VaultEntry[] | ((prev: VaultEntry[]) => VaultEntry[])) => void;
  addVaultEntry: (entry: VaultEntry) => void;
  reports: Report[];
  addReport: (report: Report) => void;
  isAdmin: boolean;
  setIsAdmin: (admin: boolean) => void;
  snackbar: { open: boolean; message: string; severity: 'success' | 'error' | 'info' | 'warning'; };
  setSnackbar: (snackbar: { open: boolean; message: string; severity: 'success' | 'error' | 'info' | 'warning'; } | ((prev: { open: boolean; message: string; severity: 'success' | 'error' | 'info' | 'warning'; }) => { open: boolean; message: string; severity: 'success' | 'error' | 'info' | 'warning'; })) => void;
}

const AppContext = createContext<AppContextType | undefined>(undefined);

export function AppProvider({ children }: { children: ReactNode }) {
  const [selectedNetwork, setSelectedNetwork] = useState<WifiNetwork | null>(null);
  const [attackConfig, setAttackConfig] = useState<AttackConfig>({
    ssid: '',
    minlen: 4,
    maxlen: 8,
    charset: 'abcdefghijklmnopqrstuvwxyz0123456789',
    threads: 2,
    timeout: 5,
    useCache: true,
  });
  const [vault, setVault] = useState<VaultEntry[]>([]);
  const [reports, setReports] = useState<Report[]>([]);
  const [isAdmin, setIsAdmin] = useState(true); // Mock admin for demo
  const [loading, setLoading] = useState(true);
  const [snackbar, setSnackbar] = useState<{
    open: boolean;
    message: string;
    severity: 'success' | 'error' | 'info' | 'warning';
  }>({
    open: false,
    message: '',
    severity: 'info',
  });

  // Load initial data from backend
  useEffect(() => {
    const loadData = async () => {
      try {
        const [vaultData, reportsData, adminData] = await Promise.all([
          getVault(),
          getReports(),
          checkAdmin()
        ]);
        setVault(vaultData || []);
        setReports(reportsData || []);
        setIsAdmin(adminData.isAdmin);
      } catch (err) {
        console.error('Failed to load initial data:', err);
      } finally {
        setLoading(false);
      }
    };
    loadData();
  }, []);

  const addVaultEntry = (entry: VaultEntry) => {
    setVault(prev => [...prev, entry]);
  };

  const addReport = async (report: Report) => {
    try {
      await addReportApi(report);
      setReports(prev => [...prev, report]);
    } catch (err) {
      console.error('Failed to add report:', err);
      // Still add to local state even if API fails
      setReports(prev => [...prev, report]);
    }
  };

  return (
    <AppContext.Provider
      value={{
        selectedNetwork,
        setSelectedNetwork,
        attackConfig,
        setAttackConfig,
        vault,
        setVault,
        addVaultEntry,
        reports,
        addReport,
        isAdmin,
        setIsAdmin,
        snackbar,
        setSnackbar,
      }}
    >
      {loading ? (
        <div style={{ display: 'flex', justifyContent: 'center', alignItems: 'center', height: '100vh' }}>
          <div>Loading...</div>
        </div>
      ) : children}
    </AppContext.Provider>
  );
}

export function useAppContext() {
  const context = useContext(AppContext);
  if (context === undefined) {
    throw new Error('useAppContext must be used within an AppProvider');
  }
  return context;
}