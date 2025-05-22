import { useState, useEffect, useCallback } from 'react';

interface Settings {
  apiEndpoint: string;
  theme: 'light' | 'dark' | 'system';
  notificationsEnabled: boolean;
  autoRefreshInterval: number;
}

export function useSettings() {
  const [settings, setSettings] = useState<Settings>({
    apiEndpoint: 'ws://localhost:8000',
    theme: 'system',
    notificationsEnabled: true,
    autoRefreshInterval: 10000,
  });
  const [loading, setLoading] = useState(true);

  // Load settings from Electron store on mount
  useEffect(() => {
    const loadSettings = async () => {
      try {
        // Check if we're in Electron context
        if (window.electronAPI) {
          const storedSettings = await window.electronAPI.getSettings();
          setSettings(storedSettings);
        }
      } catch (error) {
        console.error('Failed to load settings:', error);
      } finally {
        setLoading(false);
      }
    };

    loadSettings();
  }, []);

  // Update settings in Electron store
  const updateSettings = useCallback(async (newSettings: Partial<Settings>) => {
    try {
      const updatedSettings = { ...settings, ...newSettings };
      setSettings(updatedSettings);
      
      // Save to Electron store if available
      if (window.electronAPI) {
        await window.electronAPI.saveSettings(updatedSettings);
      }
      
      return true;
    } catch (error) {
      console.error('Failed to update settings:', error);
      return false;
    }
  }, [settings]);

  return {
    settings,
    loading,
    updateSettings,
  };
} 