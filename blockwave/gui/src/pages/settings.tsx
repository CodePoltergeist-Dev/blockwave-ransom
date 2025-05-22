import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { useSettings } from '@/hooks/use-settings';
import { useTheme } from '@/components/theme-provider';
import { useToast } from '@/components/ui/use-toast';
import {
  Settings as SettingsIcon,
  Save,
  RefreshCw,
  Globe,
  Sun,
  Moon,
  Laptop,
  Bell,
  BellOff,
  Info,
} from 'lucide-react';

export function Settings() {
  const { settings, updateSettings, loading } = useSettings();
  const { toast } = useToast();
  const { theme, setTheme } = useTheme();
  const [isSaving, setIsSaving] = useState(false);
  const [formValues, setFormValues] = useState({
    apiEndpoint: '',
    notificationsEnabled: true,
    autoRefreshInterval: 10000,
  });
  const [appInfo, setAppInfo] = useState({
    version: '',
    platform: '',
  });

  // Load app info
  useEffect(() => {
    const getAppInfo = async () => {
      try {
        if (window.electronAPI) {
          const appVersion = await window.electronAPI.getAppVersion();
          setAppInfo({
            version: appVersion,
            platform: navigator.platform,
          });
        }
      } catch (error) {
        console.error('Failed to get app info:', error);
      }
    };
    
    getAppInfo();
  }, []);

  // Initialize form with current settings
  useEffect(() => {
    if (!loading && settings) {
      setFormValues({
        apiEndpoint: settings.apiEndpoint,
        notificationsEnabled: settings.notificationsEnabled,
        autoRefreshInterval: settings.autoRefreshInterval,
      });
    }
  }, [loading, settings]);

  // Handle input changes
  const handleInputChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value, type, checked } = e.target;
    setFormValues({
      ...formValues,
      [name]: type === 'checkbox' ? checked : value,
    });
  };

  // Handle number input changes
  const handleNumberChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormValues({
      ...formValues,
      [name]: parseInt(value, 10),
    });
  };

  // Handle form submission
  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsSaving(true);
    
    try {
      await updateSettings(formValues);
      toast({
        title: 'Settings saved',
        description: 'Your settings have been updated successfully.',
        variant: 'success',
      });
    } catch (error) {
      toast({
        title: 'Error saving settings',
        description: 'There was a problem saving your settings.',
        variant: 'destructive',
      });
    } finally {
      setIsSaving(false);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold tracking-tight">Settings</h1>
      </div>

      <div className="grid grid-cols-1 gap-6 md:grid-cols-2">
        <motion.form
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3 }}
          onSubmit={handleSubmit}
          className="space-y-4 md:col-span-2 lg:col-span-1"
        >
          <div className="border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b bg-muted/40 flex items-center">
              <Globe className="w-5 h-5 mr-2" />
              <h2 className="text-lg font-medium">Connection Settings</h2>
            </div>
            <div className="p-4 space-y-4">
              <div className="space-y-2">
                <label htmlFor="apiEndpoint" className="text-sm font-medium">
                  Backend API Endpoint
                </label>
                <input
                  id="apiEndpoint"
                  name="apiEndpoint"
                  type="text"
                  value={formValues.apiEndpoint}
                  onChange={handleInputChange}
                  placeholder="ws://localhost:8000"
                  className="w-full px-3 py-2 rounded-md border bg-background"
                />
                <p className="text-xs text-muted-foreground">
                  The WebSocket endpoint for real-time events and actions.
                </p>
              </div>
            </div>
          </div>

          <div className="border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b bg-muted/40 flex items-center">
              <Bell className="w-5 h-5 mr-2" />
              <h2 className="text-lg font-medium">Notification Settings</h2>
            </div>
            <div className="p-4 space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <label htmlFor="notificationsEnabled" className="text-sm font-medium">
                    Enable Notifications
                  </label>
                  <p className="text-xs text-muted-foreground">
                    Receive notifications for critical events.
                  </p>
                </div>
                <div className="flex items-center h-5">
                  <input
                    id="notificationsEnabled"
                    name="notificationsEnabled"
                    type="checkbox"
                    checked={formValues.notificationsEnabled}
                    onChange={handleInputChange}
                    className="w-4 h-4 rounded border-gray-300"
                  />
                </div>
              </div>

              <div className="space-y-2">
                <label htmlFor="autoRefreshInterval" className="text-sm font-medium">
                  Auto-Refresh Interval (ms)
                </label>
                <input
                  id="autoRefreshInterval"
                  name="autoRefreshInterval"
                  type="number"
                  min="1000"
                  max="60000"
                  step="1000"
                  value={formValues.autoRefreshInterval}
                  onChange={handleNumberChange}
                  className="w-full px-3 py-2 rounded-md border bg-background"
                />
                <p className="text-xs text-muted-foreground">
                  How often to refresh data from the server (in milliseconds).
                </p>
              </div>
            </div>
          </div>

          <div className="border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b bg-muted/40 flex items-center">
              <Sun className="w-5 h-5 mr-2" />
              <h2 className="text-lg font-medium">Appearance</h2>
            </div>
            <div className="p-4">
              <label className="text-sm font-medium mb-2 block">Theme</label>
              <div className="grid grid-cols-3 gap-2">
                <button
                  type="button"
                  onClick={() => setTheme('light')}
                  className={`flex flex-col items-center justify-center p-3 rounded-md ${
                    theme === 'light' ? 'bg-primary/10 border-primary border' : 'border'
                  }`}
                >
                  <Sun className="h-5 w-5 mb-1" />
                  <span className="text-sm">Light</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTheme('dark')}
                  className={`flex flex-col items-center justify-center p-3 rounded-md ${
                    theme === 'dark' ? 'bg-primary/10 border-primary border' : 'border'
                  }`}
                >
                  <Moon className="h-5 w-5 mb-1" />
                  <span className="text-sm">Dark</span>
                </button>
                <button
                  type="button"
                  onClick={() => setTheme('system')}
                  className={`flex flex-col items-center justify-center p-3 rounded-md ${
                    theme === 'system' ? 'bg-primary/10 border-primary border' : 'border'
                  }`}
                >
                  <Laptop className="h-5 w-5 mb-1" />
                  <span className="text-sm">System</span>
                </button>
              </div>
            </div>
          </div>

          <div className="flex justify-end">
            <button
              type="submit"
              disabled={isSaving}
              className="inline-flex items-center px-4 py-2 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
            >
              {isSaving ? (
                <>
                  <RefreshCw className="mr-2 h-4 w-4 animate-spin" />
                  Saving...
                </>
              ) : (
                <>
                  <Save className="mr-2 h-4 w-4" />
                  Save Settings
                </>
              )}
            </button>
          </div>
        </motion.form>

        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.3, delay: 0.1 }}
        >
          <div className="border rounded-lg overflow-hidden">
            <div className="px-4 py-3 border-b bg-muted/40 flex items-center">
              <Info className="w-5 h-5 mr-2" />
              <h2 className="text-lg font-medium">About</h2>
            </div>
            <div className="p-4">
              <div className="flex flex-col items-center justify-center py-6">
                <SettingsIcon className="h-16 w-16 text-primary mb-4" />
                <h3 className="text-xl font-bold mb-1">BlockWave-Ransom</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Real-time ransomware detection and mitigation
                </p>
                <div className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm w-full max-w-xs">
                  <div className="text-muted-foreground">Version:</div>
                  <div>{appInfo.version || 'Unknown'}</div>
                  <div className="text-muted-foreground">Platform:</div>
                  <div>{appInfo.platform || 'Unknown'}</div>
                </div>
              </div>
            </div>
          </div>
        </motion.div>
      </div>
    </div>
  );
} 