const { app, BrowserWindow, ipcMain, Menu } = require('electron')
const path = require('path')
const { spawn } = require('child_process')

let mainWindow
let logWindow
let backendProc = null
let backendShowConsole = false

function createMenu() {
  const isProd = app.isPackaged
  const template = [
    {
      label: 'Debug',
      submenu: [
        {
          label: 'Open Debug Logs',
          accelerator: 'F12',
          click: () => {
            createLogWindow()
          }
        },
        {
          label: 'Toggle Backend Console',
          accelerator: 'F11',
          click: () => {
            const enabled = !backendShowConsole
            backendShowConsole = enabled
            console.log(`Backend console ${enabled ? 'enabled' : 'disabled'}`)
            if (backendProc) {
              stopBackend()
              setTimeout(startBackend, 500)
            }
          }
        },
        {
          label: 'Restart Backend',
          accelerator: 'F10',
          click: () => {
            stopBackend()
            setTimeout(startBackend, 500)
          }
        },
        {
          type: 'separator'
        },
        {
          label: 'Toggle DevTools',
          accelerator: 'Ctrl+Shift+I',
          click: () => {
            if (mainWindow) {
              mainWindow.webContents.toggleDevTools()
            }
          }
        }
      ]
    }
  ]
  
  const menu = Menu.buildFromTemplate(template)
  Menu.setApplicationMenu(menu)
}

function startBackend() {
  const isProd = app.isPackaged
  const backendArgs = []
  
  // Clean up existing backend if running
  stopBackend()

  if (isProd) {
    const exePath = path.join(process.resourcesPath, 'backend', 'main.exe')
    const spawnOpts = {
      detached: !backendShowConsole,
      stdio: backendShowConsole ? 'inherit' : 'ignore',
      shell: backendShowConsole,
      windowsHide: !backendShowConsole
    }
    backendProc = spawn(exePath, backendArgs, spawnOpts)
    if (!backendShowConsole) backendProc.unref()
  } else {
    const python = process.platform === 'win32' ? 'python' : 'python3'
    backendProc = spawn(python, [path.join(__dirname, '..', 'ghostlink', 'api', 'server.py')], {
      stdio: 'inherit',
      shell: true
    })
  }

  backendProc.on('error', (err) => {
    console.error("Failed to start backend:", err)
    if (logWindow) {
      logWindow.webContents.send('log-message', `ERROR: Failed to start backend - ${err.message}`)
    }
  })

  backendProc.on('exit', (code, signal) => {
    const msg = `Backend process exited with code ${code}, signal ${signal}`
    console.log(msg)
    if (logWindow) {
      logWindow.webContents.send('log-message', msg)
    }
  })
}

function stopBackend() {
  if (backendProc) {
    try {
      if (process.platform === 'win32') {
        spawn('taskkill', ['/F', '/T', '/PID', backendProc.pid], {
          stdio: 'ignore',
          shell: true
        })
      } else {
        backendProc.kill('SIGKILL')
      }
    } catch (e) {
      console.error("Error stopping backend:", e)
      if (logWindow) {
        logWindow.webContents.send('log-message', `WARNING: Error stopping backend - ${e.message}`)
      }
    }
    backendProc = null
  }
}

function createMainWindow() {
  const isProd = app.isPackaged

  let indexPath
  let iconPath

  if (isProd) {
    indexPath = path.join(__dirname, '..', 'web-radar', 'dist', 'index.html')
    iconPath = path.join(__dirname, '..', 'scripts', 'ghostlink.ico')
  } else {
    indexPath = 'http://localhost:5173'
    iconPath = path.join(__dirname, '..', 'scripts', 'ghostlink.ico')
  }

  mainWindow = new BrowserWindow({
    width: 1200,
    height: 800,
    minWidth: 900,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      devTools: true // always allow dev tools for debugging
    },
    icon: iconPath,
    menuBarVisible: false // Hide menu bar by default
  })

  // Keep menu available for debug even if hidden
  mainWindow.setMenuBarVisibility(false)

  // Allow toggle menu bar with Alt key
  mainWindow.on('before-input-event', (event, input) => {
    if (input.key === 'Alt' && input.type === 'keyDown') {
      mainWindow.setMenuBarVisibility(!mainWindow.isMenuBarVisible())
    }
  })

  if (!isProd) {
    mainWindow.webContents.openDevTools()
  }

  if (isProd) {
    mainWindow.loadFile(indexPath)
  } else {
    mainWindow.loadURL(indexPath)
  }
}

function createLogWindow() {
  if (logWindow) {
    logWindow.focus()
    return
  }

  logWindow = new BrowserWindow({
    width: 800,
    height: 600,
    title: 'GHOSTLINK Debug Logs',
    webPreferences: {
      devTools: true
    }
  })

  // Simple log viewer HTML
  logWindow.loadURL(`data:text/html;charset=utf-8,
  <!DOCTYPE html>
  <html>
    <head>
      <title>Debug Logs</title>
      <style>
        body {
          font-family: system-ui, -apple-system, sans-serif;
          background-color: #0f172a;
          color: #e2e8f0;
          margin: 0;
          padding: 20px;
        }
        #logs {
          background: #1e293b;
          border-radius: 8px;
          padding: 15px;
          max-height: calc(100vh - 40px);
          overflow-y: auto;
          font-family: ui-monospace, 'Cascadia Code', monospace;
          white-space: pre-wrap;
          word-break: break-all;
        }
        .log-item {
          margin: 4px 0;
          padding: 6px 10px;
          border-radius: 4px;
        }
        .log-error { background: rgba(239, 68, 68, 0.2); border-left: 4px solid #ef4444; }
        .log-warn { background: rgba(245, 158, 11, 0.2); border-left: 4px solid #f59e0b; }
        .log-info { background: rgba(59, 130, 246, 0.2); border-left: 4px solid #3b82f6; }
      </style>
    </head>
    <body>
      <h2>GHOSTLINK Debug Logs</h2>
      <div id="logs"></div>
      <script>
        const logsDiv = document.getElementById('logs')
        window.electronAPI = {
          onLogMessage: (callback) => {
            require('electron').ipcRenderer.on('log-message', (event, msg) => {
              callback(msg)
            })
          }
        }
        window.electronAPI.onLogMessage((msg) => {
          const logItem = document.createElement('div')
          logItem.className = 'log-item ' + 
            (msg.toLowerCase().includes('error') ? 'log-error' : 
             msg.toLowerCase().includes('warning') ? 'log-warn' : 'log-info')
          logItem.textContent = '[' + new Date().toLocaleTimeString() + '] ' + msg
          logsDiv.appendChild(logItem)
          logsDiv.scrollTop = logsDiv.scrollHeight
        })
        // Initial welcome log
        const welcome = document.createElement('div')
        welcome.className = 'log-item log-info'
        welcome.textContent = '[' + new Date().toLocaleTimeString() + '] Log viewer ready!'
        logsDiv.appendChild(welcome)
      </script>
    </body>
  </html>
  `)

  logWindow.on('closed', () => {
    logWindow = null
  })
}

// IPC Handlers
ipcMain.handle('open-log-window', () => {
  createLogWindow()
})

ipcMain.handle('toggle-backend-console', () => {
  backendShowConsole = !backendShowConsole
  console.log(`Backend console ${backendShowConsole ? 'enabled' : 'disabled'}`)
  if (backendProc) {
    stopBackend()
    setTimeout(startBackend, 500) // Restart after a short delay
  }
  return backendShowConsole
})

ipcMain.handle('restart-backend', () => {
  stopBackend()
  setTimeout(startBackend, 500)
  return 'Backend restarting'
})

// App Lifecycle
app.whenReady().then(() => {
  createMenu()
  startBackend()
  createMainWindow()

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createMainWindow()
    }
  })
})

app.on('window-all-closed', () => {
  stopBackend()
  if (process.platform !== 'darwin') {
    app.quit()
  }
})
