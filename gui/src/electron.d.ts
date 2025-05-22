interface ElectronAPI {
  getSettings: () => Promise<{
    apiEndpoint: string;
    theme: 'light' | 'dark' | 'system';
    notificationsEnabled: boolean;
    autoRefreshInterval: number;
  }>;
  saveSettings: (settings: any) => Promise<boolean>;
  openLogFile: (path: string) => Promise<boolean>;
  getAppVersion: () => Promise<string>;
  quitApp: () => Promise<void>;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}

export {}; 