export const API_ENDPOINTS = {
  ADMIN: '/api/admin',
  STATUS: '/api/status',
  ACTIVITY: '/api/activity',
  SCAN: '/api/scan',
  TARGET: '/api/target',
  PROFILES: '/api/profiles',
  ATTACK_START: '/api/attack/start',
  ATTACK_STOP: '/api/attack/stop',
  VAULT: '/api/vault',
  VAULT_IMPORT: '/api/vault/import',
  VAULT_EXPORT: '/api/vault/export',
  RECON: '/api/recon',
} as const;

export const ATTACK_CONFIG_DEFAULTS = {
  MIN_LENGTH: 4,
  MAX_LENGTH: 8,
  THREADS: 2,
  TIMEOUT: 5,
  USE_CACHE: true,
} as const;

export const PAGINATION_DEFAULTS = {
  PAGE: 0,
  ROWS_PER_PAGE: 5,
} as const;

export const SNACKBAR_DURATION = 4000;

export const DRAWER_WIDTH = 260;

export const SECURITY_TYPES = {
  WPA3: 'wpa3',
  WPA2: 'wpa2',
  WPA: 'wpa',
  OPEN: 'open',
} as const;
