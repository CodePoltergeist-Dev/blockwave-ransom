import { useEffect, useState } from 'react';
import { motion } from 'framer-motion';
import { useEventStore } from '@/store/events';
import { formatDate, getSeverityColor } from '@/lib/utils';
import {
  AlertCircle,
  ShieldCheck,
  Clock,
  HardDrive,
  FileWarning,
  Shield,
} from 'lucide-react';

export function Dashboard() {
  const { events } = useEventStore();
  const [stats, setStats] = useState({
    totalEvents: 0,
    criticalEvents: 0,
    lastEvent: null as number | null,
    activeMonitoring: true,
    quarantinedFiles: 0,
    detectionRules: 0,
  });

  // Update stats when events change
  useEffect(() => {
    const criticalEvents = events.filter(
      (event) => event.severity === 'CRITICAL' || event.severity === 'ERROR'
    ).length;

    const lastEvent = events.length > 0 ? events[0].timestamp : null;

    setStats({
      ...stats,
      totalEvents: events.length,
      criticalEvents,
      lastEvent,
    });
  }, [events]);

  // Count types of events
  const eventTypeCount = events.reduce((acc, event) => {
    const type = event.type;
    acc[type] = (acc[type] || 0) + 1;
    return acc;
  }, {} as Record<string, number>);

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <h1 className="text-2xl font-bold tracking-tight">Dashboard</h1>
        <div className="flex items-center space-x-2">
          <div className="flex items-center text-success">
            <div className="w-2 h-2 rounded-full bg-success mr-2 animate-pulse" />
            <span className="text-sm font-medium">System Active</span>
          </div>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        <StatCard
          title="Total Events"
          value={stats.totalEvents}
          icon={<AlertCircle />}
          color="bg-primary/10 text-primary"
        />
        <StatCard
          title="Critical Alerts"
          value={stats.criticalEvents}
          icon={<FileWarning />}
          color="bg-destructive/10 text-destructive"
        />
        <StatCard
          title="Last Event"
          value={stats.lastEvent ? formatDate(stats.lastEvent) : 'No events yet'}
          icon={<Clock />}
          color="bg-muted text-muted-foreground"
          isText
        />
      </div>

      {/* Recent Events */}
      <div className="border rounded-lg">
        <div className="px-4 py-3 border-b bg-muted/40">
          <h2 className="text-lg font-medium">Recent Events</h2>
        </div>
        <div className="divide-y">
          {events.slice(0, 5).map((event) => (
            <motion.div
              key={event.id}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="p-4"
            >
              <div className="flex items-start justify-between">
                <div className="flex items-start space-x-3">
                  <div className={`mt-0.5 ${getSeverityColor(event.severity)}`}>
                    <AlertCircle size={18} />
                  </div>
                  <div>
                    <p className="font-medium">{event.message}</p>
                    <div className="flex items-center text-sm text-muted-foreground mt-1 space-x-3">
                      <span>{event.source}</span>
                      <span>•</span>
                      <span>{event.type}</span>
                      <span>•</span>
                      <span>{formatDate(event.timestamp)}</span>
                    </div>
                  </div>
                </div>
                <div
                  className={`px-2 py-1 text-xs font-medium rounded-full ${getSeverityColor(
                    event.severity
                  )} bg-background border`}
                >
                  {event.severity}
                </div>
              </div>
            </motion.div>
          ))}
          {events.length === 0 && (
            <div className="p-8 text-center">
              <div className="inline-flex items-center justify-center p-3 rounded-full bg-muted mb-4">
                <Clock className="h-6 w-6 text-muted-foreground" />
              </div>
              <p className="text-muted-foreground">No events recorded yet.</p>
              <p className="text-sm text-muted-foreground mt-1">
                Events will appear here once detected.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

interface StatCardProps {
  title: string;
  value: number | string;
  icon: React.ReactNode;
  color: string;
  isText?: boolean;
}

function StatCard({ title, value, icon, color, isText = false }: StatCardProps) {
  return (
    <motion.div
      initial={{ opacity: 0, y: 20 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="border rounded-lg p-4 h-full"
    >
      <div className="flex justify-between items-start">
        <div>
          <p className="text-sm font-medium text-muted-foreground">{title}</p>
          <h3 className={`mt-2 text-2xl font-bold ${isText ? 'text-base' : ''}`}>
            {value}
          </h3>
        </div>
        <div className={`p-2 rounded-full ${color}`}>{icon}</div>
      </div>
    </motion.div>
  );
} 