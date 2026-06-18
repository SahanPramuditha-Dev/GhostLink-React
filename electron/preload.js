const { contextBridge, ipcRenderer } = require('electron')

contextBridge.exposeInMainWorld('electronAPI', {
  openLogWindow: () => ipcRenderer.invoke('open-log-window'),
  toggleBackendConsole: () => ipcRenderer.invoke('toggle-backend-console'),
  restartBackend: () => ipcRenderer.invoke('restart-backend')
})
