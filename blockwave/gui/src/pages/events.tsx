import { useState, useEffect } from 'react';
import { useEventStore, EventData } from '@/store/events';
import { formatDate, getSeverityColor } from '@/lib/utils';
import { motion, AnimatePresence } from 'framer-motion';
import {
  AlertCircle,
  Filter,
  X,
  Clock,
  Search,
  Download,
  RefreshCw,
} from 'lucide-react';

// Event type options for filtering
const EVENT_TYPES = [
  'All Types',
  'DETECTION',
  'MITIGATION',
  'SYSTEM',
  'FILE',
  'PROCESS',
  'NETWORK',
  'BACKUP',
  'RESTORE',
  'ERROR',
  'WARNING',
  'INFO',
];

// Severity options for filtering
const SEVERITY_LEVELS = [
  'All Levels',
  'CRITICAL',
  'ERROR',
  'WARNING',
  'INFO',
  'DEBUG',
];

export function Events() {
  const { events, filteredEvents, setFilters, clearFilters } = useEventStore();
  const [searchText, setSearchText] = useState('');
  const [typeFilter, setTypeFilter] = useState('All Types');
  const [severityFilter, setSeverityFilter] = useState('All Levels');
  const [isFiltersOpen, setIsFiltersOpen] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // Apply filters when they change
  useEffect(() => {
    setFilters({
      type: typeFilter === 'All Types' ? null : typeFilter,
      severity: severityFilter === 'All Levels' ? null : severityFilter,
      searchText,
    });
  }, [searchText, typeFilter, severityFilter, setFilters]);

  // Handle search input
  const handleSearch = (e: React.ChangeEvent<HTMLInputElement>) => {
    setSearchText(e.target.value);
  };

  // Reset all filters
  const handleResetFilters = () => {
    setSearchText('');
    setTypeFilter('All Types');
    setSeverityFilter('All Levels');
    clearFilters();
  };

  // Simulate refreshing events
  const handleRefresh = () => {
    setIsLoading(true);
    setTimeout(() => {
      setIsLoading(false);
    }, 500);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <h1 className="text-2xl font-bold tracking-tight">Events</h1>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-muted-foreground">
            {filteredEvents.length} events
          </span>
        </div>
      </div>

      {/* Search and filters */}
      <div className="flex flex-col md:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search events..."
            className="w-full pl-9 pr-4 py-2 rounded-md border bg-background"
            value={searchText}
            onChange={handleSearch}
          />
          {searchText && (
            <button
              onClick={() => setSearchText('')}
              className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground hover:text-foreground"
            >
              <X size={16} />
            </button>
          )}
        </div>

        <button
          onClick={() => setIsFiltersOpen(!isFiltersOpen)}
          className="flex items-center gap-2 px-3 py-2 rounded-md border bg-background hover:bg-secondary transition-colors"
        >
          <Filter size={16} />
          <span>Filters</span>
          {(typeFilter !== 'All Types' || severityFilter !== 'All Levels') && (
            <span className="flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs text-primary-foreground">
              {(typeFilter !== 'All Types' ? 1 : 0) +
                (severityFilter !== 'All Levels' ? 1 : 0)}
            </span>
          )}
        </button>

        <div className="flex gap-2">
          <button
            onClick={handleRefresh}
            className="flex items-center gap-2 px-3 py-2 rounded-md border bg-background hover:bg-secondary transition-colors"
          >
            <RefreshCw
              size={16}
              className={isLoading ? 'animate-spin' : undefined}
            />
            <span>Refresh</span>
          </button>

          <button
            onClick={handleResetFilters}
            className="flex items-center gap-2 px-3 py-2 rounded-md border bg-background hover:bg-secondary transition-colors"
            disabled={
              typeFilter === 'All Types' &&
              severityFilter === 'All Levels' &&
              !searchText
            }
          >
            <X size={16} />
            <span>Reset</span>
          </button>
        </div>
      </div>

      {/* Filters panel */}
      <AnimatePresence>
        {isFiltersOpen && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden border rounded-md"
          >
            <div className="p-4 grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium mb-1">
                  Event Type
                </label>
                <select
                  value={typeFilter}
                  onChange={(e) => setTypeFilter(e.target.value)}
                  className="w-full p-2 rounded-md border bg-background"
                >
                  {EVENT_TYPES.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium mb-1">
                  Severity Level
                </label>
                <select
                  value={severityFilter}
                  onChange={(e) => setSeverityFilter(e.target.value)}
                  className="w-full p-2 rounded-md border bg-background"
                >
                  {SEVERITY_LEVELS.map((level) => (
                    <option key={level} value={level}>
                      {level}
                    </option>
                  ))}
                </select>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Events list */}
      <div className="border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b bg-muted/40 flex items-center justify-between">
          <h2 className="text-lg font-medium">Event Log</h2>
          <button
            className="flex items-center gap-1 text-sm text-primary hover:underline"
            onClick={() => {
              /* Would download events as CSV/JSON */
              alert('This would download events as CSV/JSON');
            }}
          >
            <Download size={14} />
            <span>Export</span>
          </button>
        </div>

        {filteredEvents.length > 0 ? (
          <div className="divide-y">
            {filteredEvents.map((event) => (
              <EventRow key={event.id} event={event} />
            ))}
          </div>
        ) : (
          <div className="p-8 text-center">
            <div className="inline-flex items-center justify-center p-3 rounded-full bg-muted mb-4">
              {searchText || typeFilter !== 'All Types' || severityFilter !== 'All Levels' ? (
                <Filter className="h-6 w-6 text-muted-foreground" />
              ) : (
                <Clock className="h-6 w-6 text-muted-foreground" />
              )}
            </div>
            <p className="text-muted-foreground">
              {searchText || typeFilter !== 'All Types' || severityFilter !== 'All Levels'
                ? 'No events match your filters.'
                : 'No events recorded yet.'}
            </p>
            <p className="text-sm text-muted-foreground mt-1">
              {searchText || typeFilter !== 'All Types' || severityFilter !== 'All Levels'
                ? 'Try changing your search or filter criteria.'
                : 'Events will appear here once detected.'}
            </p>
          </div>
        )}
      </div>
    </div>
  );
}

interface EventRowProps {
  event: EventData;
}

function EventRow({ event }: EventRowProps) {
  const [expanded, setExpanded] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: -10 }}
      animate={{ opacity: 1, y: 0 }}
      className="p-4 hover:bg-muted/20 transition-colors cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start justify-between">
        <div className="flex items-start space-x-3">
          <div className={`mt-0.5 ${getSeverityColor(event.severity)}`}>
            <AlertCircle size={18} />
          </div>
          <div>
            <p className="font-medium">{event.message}</p>
            <div className="flex flex-wrap items-center text-sm text-muted-foreground mt-1 gap-x-3 gap-y-1">
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

      {/* Metadata display when expanded */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="mt-3 pl-7 overflow-hidden"
          >
            <div className="pl-3 border-l text-sm">
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <p className="text-muted-foreground">ID:</p>
                  <p className="font-mono text-xs">{event.id}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Timestamp:</p>
                  <p>{formatDate(event.timestamp, true)}</p>
                </div>
              </div>

              <div className="mt-2">
                <p className="text-muted-foreground">Metadata:</p>
                <pre className="mt-1 p-2 bg-muted/30 rounded text-xs overflow-x-auto">
                  {JSON.stringify(event.metadata, null, 2)}
                </pre>
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
} 