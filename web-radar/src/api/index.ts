const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || "http://127.0.0.1:5966";

export async function checkAdmin(): Promise<{ isAdmin: boolean }> {
  const res = await fetch(`${API_BASE_URL}/api/admin`);
  return res.json();
}

export async function getStatus() {
  const res = await fetch(`${API_BASE_URL}/api/status`);
  return res.json();
}

export async function getActivity() {
  const res = await fetch(`${API_BASE_URL}/api/activity`);
  return res.json();
}

export async function scanNetworks() {
  const res = await fetch(`${API_BASE_URL}/api/scan`, { method: "POST" });
  return res.json();
}

export async function setTarget(network: { ssid: string; signal: number; security: string }) {
  const res = await fetch(`${API_BASE_URL}/api/target`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(network),
  });
  return res.json();
}

export async function getProfiles() {
  const res = await fetch(`${API_BASE_URL}/api/profiles`);
  return res.json();
}

export async function startAttack(config: {
  ssid: string;
  minlen: number;
  maxlen: number;
  charset: string;
  threads: number;
  timeout: number;
  useCache: boolean;
}) {
  const res = await fetch(`${API_BASE_URL}/api/attack/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      ...config,
      use_cache: config.useCache,
    }),
  });
  return res.json();
}

export async function stopAttack() {
  const res = await fetch(`${API_BASE_URL}/api/attack/stop`, {
    method: "POST",
  });
  return res.json();
}

export async function getVault() {
  const res = await fetch(`${API_BASE_URL}/api/vault`)
  return res.json()
}

export async function deleteVaultEntry(entryId: string) {
  const res = await fetch(`${API_BASE_URL}/api/vault/${entryId}`, { method: "DELETE" })
  return res.json()
}

export async function importVault(entries: any[]) {
  const res = await fetch(`${API_BASE_URL}/api/vault/import`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(entries)
  })
  return res.json()
}

export async function exportVault() {
  const res = await fetch(`${API_BASE_URL}/api/vault/export`)
  return res.json()
}

export async function runReconModule(module: string) {
  const res = await fetch(`${API_BASE_URL}/api/recon/${module}`, { method: "POST" })
  return res.json()
}

// New endpoints
export async function getReports() {
  const res = await fetch(`${API_BASE_URL}/api/reports`)
  return res.json()
}

export async function addReport(report: any) {
  const res = await fetch(`${API_BASE_URL}/api/reports`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(report)
  })
  return res.json()
}

export async function clearReports() {
  const res = await fetch(`${API_BASE_URL}/api/reports`, { method: "DELETE" })
  return res.json()
}

export async function getLogs() {
  const res = await fetch(`${API_BASE_URL}/api/logs`)
  return res.json()
}

export async function addLog(message: string) {
  const res = await fetch(`${API_BASE_URL}/api/logs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ message })
  })
  return res.json()
}

export async function clearLogs() {
    const res = await fetch(`${API_BASE_URL}/api/logs`, { method: "DELETE" })
    return res.json()
}

export async function getAttackStatus() {
    const res = await fetch(`${API_BASE_URL}/api/attack/status`)
    return res.json()
}

export async function getPerformance() {
    const res = await fetch(`${API_BASE_URL}/api/performance`)
    return res.json()
}
