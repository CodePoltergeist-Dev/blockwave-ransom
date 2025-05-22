const { app, BrowserWindow, ipcMain, shell } = require('electron');
const path = require('path');
const Store = require('electron-store');

// Initialize settings store
const store = new Store();

// Keep a global reference of the window object
let mainWindow;

function createWindow() {
  // Create the browser window
  mainWindow = new BrowserWindow({
    width: 1280,
    height: 800,
    minWidth: 800,
    minHeight: 600,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false
    },
    // Use native window frame
    frame: true,
    // Use hardware acceleration if available
    webPreferences: {
      accelerator: true
    },
    icon: path.join(__dirname, '../assets/icon.png')
  });

  // Load the app based on environment
  if (app.isPackaged) {
    // Production: Load built files
    mainWindow.loadFile(path.join(__dirname, '../dist/index.html'));
  } else {
    // Development: Load from dev server
    mainWindow.loadURL('http://localhost:5173');
    // Open DevTools in development mode
    mainWindow.webContents.openDevTools();
  }

  // Handle external links
  mainWindow.webContents.setWindowOpenHandler(({ url }) => {
    shell.openExternal(url);
    return { action: 'deny' };
  });

  // Emitted when the window is closed
  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

// Create window when Electron is ready
app.whenReady().then(() => {
  createWindow();

  // On macOS it's common to re-create a window when the dock icon is clicked
  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) {
      createWindow();
    }
  });
});

// Quit when all windows are closed, except on macOS
app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

// IPC handlers for main process operations
ipcMain.handle('get-settings', async () => {
  return store.get('settings') || {
    apiEndpoint: 'ws://localhost:8000',
    theme: 'system',
    notificationsEnabled: true,
    autoRefreshInterval: 10000
  };
});

ipcMain.handle('save-settings', async (_, settings) => {
  store.set('settings', settings);
  return true;
});

// Handle opening log files
ipcMain.handle('open-log-file', async (_, path) => {
  try {
    shell.openPath(path);
    return true;
  } catch (error) {
    console.error('Failed to open log file:', error);
    return false;
  }
});

// Handle getting app version
ipcMain.handle('get-app-version', () => {
  return app.getVersion();
});

// Handle app quit
ipcMain.handle('quit-app', () => {
  app.quit();
}); 