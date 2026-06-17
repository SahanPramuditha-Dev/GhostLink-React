export interface WifiNetwork {
  ssid: string;
  bssid?: string;
  signal?: number;
  channel?: number;
  security?: string;
}

export interface AttackProfile {
  id: string;
  name: string;
  charset: string;
  description: string;
}

export interface AttackConfig {
  ssid: string;
  minlen: number;
  maxlen: number;
  charset: string;
  wordlist?: string;
  threads: number;
  timeout: number;
  useCache: boolean;
}

export interface AttackResult {
  password?: string;
  attempts: number;
  elapsed: number;
  verified: boolean;
}

export interface VaultEntry {
  id: string;
  ssid: string;
  password: string;
  timestamp: number;
}

export interface Report {
  id: string;
  ssid: string;
  password?: string;
  attempts: number;
  elapsed: number;
  verified: boolean;
  timestamp: number;
}

export interface StatusResponse {
  target: WifiNetwork | null;
  attackStatus: string;
  totalAttempts: number;
  cachedPasswords: number;
}

export interface ScanResponse {
  networks: WifiNetwork[];
  error?: string;
}

export interface ApiResponse<T = unknown> {
  success?: boolean;
  error?: string;
  data?: T;
}