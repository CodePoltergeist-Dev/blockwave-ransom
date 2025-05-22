import { useEffect } from 'react';
import { Routes, Route } from 'react-router-dom';
import { useTheme } from './components/theme-provider';
import { Dashboard } from './pages/dashboard';
import { Events } from './pages/events';
import { Quarantine } from './pages/quarantine';
import { Rules } from './pages/rules';
import { Settings } from './pages/settings';
import { Layout } from './components/layout';
import { useSettings } from './hooks/use-settings';
import { useSocket } from './hooks/use-socket';
import { useToast } from './components/ui/use-toast';

function App() {
  const { theme } = useTheme();
  const { settings } = useSettings();
  const { toast } = useToast();
  const { connect, disconnect, connected } = useSocket();

  // Connect to websocket when app starts
  useEffect(() => {
    if (settings.apiEndpoint) {
      connect(settings.apiEndpoint);
      
      return () => {
        disconnect();
      };
    }
  }, [settings.apiEndpoint, connect, disconnect]);

  // Show toast when connection status changes
  useEffect(() => {
    if (connected) {
      toast({
        title: 'Connected to BlockWave-Ransom',
        description: 'Successfully connected to the backend service.',
        variant: 'default',
      });
    } else {
      toast({
        title: 'Connection lost',
        description: 'Trying to reconnect to the backend service...',
        variant: 'destructive',
      });
    }
  }, [connected, toast]);

  return (
    <div className={theme}>
      <div className="min-h-screen bg-background font-sans antialiased">
        <Routes>
          <Route path="/" element={<Layout />}>
            <Route index element={<Dashboard />} />
            <Route path="events" element={<Events />} />
            <Route path="quarantine" element={<Quarantine />} />
            <Route path="rules" element={<Rules />} />
            <Route path="settings" element={<Settings />} />
          </Route>
        </Routes>
      </div>
    </div>
  );
}

export default App; 