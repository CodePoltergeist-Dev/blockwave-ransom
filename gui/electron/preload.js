const { contextBridge, ipcRenderer } = require('electron');

// Expose IPC API to renderer process
contextBridge.exposeInMainWorld('electronAPI', {
  // Settings management
  getSettings: () => ipcRenderer.invoke('get-settings'),
  saveSettings: (settings) => ipcRenderer.invoke('save-settings', settings),
  
  // File operations
  openLogFile: (path) => ipcRenderer.invoke('open-log-file', path),
  
  // App info and control
  getAppVersion: () => ipcRenderer.invoke('get-app-version'),
  quitApp: () => ipcRenderer.invoke('quit-app')
}); 