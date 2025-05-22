import { useState } from 'react';
import { Outlet } from 'react-router-dom';
import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Shield,
  AlertCircle,
  HardDrive,
  LayoutDashboard,
  Settings,
  Menu,
  X,
  Lock,
  Moon,
  Sun,
  Laptop,
} from 'lucide-react';
import { useTheme } from './theme-provider';
import { cn } from '@/lib/utils';

const sidebarItems = [
  {
    name: 'Dashboard',
    path: '/',
    icon: <LayoutDashboard className="w-5 h-5" />,
  },
  {
    name: 'Events',
    path: '/events',
    icon: <AlertCircle className="w-5 h-5" />,
  },
  {
    name: 'Quarantine',
    path: '/quarantine',
    icon: <Lock className="w-5 h-5" />,
  },
  {
    name: 'Rules',
    path: '/rules',
    icon: <Shield className="w-5 h-5" />,
  },
  {
    name: 'Settings',
    path: '/settings',
    icon: <Settings className="w-5 h-5" />,
  },
];

export function Layout() {
  const { pathname } = useLocation();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const { theme, setTheme } = useTheme();

  const toggleSidebar = () => {
    setSidebarOpen(!sidebarOpen);
  };

  return (
    <div className="relative flex min-h-screen">
      {/* Mobile sidebar toggle */}
      <button
        onClick={toggleSidebar}
        className="md:hidden fixed z-20 top-4 left-4 p-2 rounded-md bg-background border"
      >
        {sidebarOpen ? <X size={20} /> : <Menu size={20} />}
      </button>

      {/* Sidebar Backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/50 z-10 md:hidden"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      {/* Sidebar */}
      <motion.aside
        className={cn(
          "fixed md:sticky top-0 left-0 z-20 h-full w-64 border-r bg-background transition-all flex flex-col",
          sidebarOpen ? "translate-x-0" : "-translate-x-full md:translate-x-0"
        )}
        initial={false}
        animate={{ x: sidebarOpen ? 0 : -280 }}
        transition={{ type: "spring", damping: 25, stiffness: 300 }}
      >
        <div className="flex items-center h-16 px-4 border-b">
          <HardDrive className="w-6 h-6 mr-2 text-primary" />
          <h1 className="text-lg font-semibold">BlockWave-Ransom</h1>
        </div>

        <nav className="flex-1 overflow-y-auto py-4">
          <ul className="space-y-1 px-2">
            {sidebarItems.map((item) => (
              <li key={item.path}>
                <Link
                  to={item.path}
                  className={cn(
                    "flex items-center rounded-md px-3 py-2 text-sm font-medium transition-colors",
                    pathname === item.path
                      ? "bg-primary/10 text-primary"
                      : "hover:bg-muted"
                  )}
                  onClick={() => setSidebarOpen(false)}
                >
                  <span className="mr-3">{item.icon}</span>
                  {item.name}
                </Link>
              </li>
            ))}
          </ul>
        </nav>

        <div className="p-4 border-t">
          <div className="flex items-center justify-center space-x-2">
            <button
              onClick={() => setTheme('light')}
              className={cn(
                "p-2 rounded-md transition-colors",
                theme === 'light' ? "bg-primary/10 text-primary" : "hover:bg-muted"
              )}
            >
              <Sun size={16} />
            </button>
            <button
              onClick={() => setTheme('system')}
              className={cn(
                "p-2 rounded-md transition-colors",
                theme === 'system' ? "bg-primary/10 text-primary" : "hover:bg-muted"
              )}
            >
              <Laptop size={16} />
            </button>
            <button
              onClick={() => setTheme('dark')}
              className={cn(
                "p-2 rounded-md transition-colors",
                theme === 'dark' ? "bg-primary/10 text-primary" : "hover:bg-muted"
              )}
            >
              <Moon size={16} />
            </button>
          </div>
        </div>
      </motion.aside>

      {/* Main content */}
      <main className="flex-1 flex flex-col">
        <div className="flex-1 container mx-auto p-4 md:p-6 max-w-7xl">
          <Outlet />
        </div>
      </main>
    </div>
  );
} 