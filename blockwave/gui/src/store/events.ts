import { create } from 'zustand';

export interface EventData {
  id: string;
  timestamp: number;
  type: string;
  severity: 'DEBUG' | 'INFO' | 'WARNING' | 'ERROR' | 'CRITICAL';
  source: string;
  message: string;
  metadata: Record<string, any>;
}

interface EventState {
  events: EventData[];
  filteredEvents: EventData[];
  filters: {
    type: string | null;
    severity: string | null;
    source: string | null;
    startTime: number | null;
    endTime: number | null;
    searchText: string;
  };
  addEvent: (event: EventData) => void;
  clearEvents: () => void;
  setFilters: (filters: Partial<EventState['filters']>) => void;
  clearFilters: () => void;
}

// Default filters
const defaultFilters = {
  type: null,
  severity: null,
  source: null,
  startTime: null,
  endTime: null,
  searchText: '',
};

export const useEventStore = create<EventState>((set, get) => ({
  events: [],
  filteredEvents: [],
  filters: { ...defaultFilters },

  addEvent: (event) => {
    set((state) => {
      const newEvents = [event, ...state.events];
      // Keep only the latest 1000 events to prevent memory issues
      const trimmedEvents = newEvents.slice(0, 1000);
      
      // Apply current filters to the new events list
      const filtered = applyFilters(trimmedEvents, state.filters);
      
      return {
        events: trimmedEvents,
        filteredEvents: filtered,
      };
    });
  },

  clearEvents: () => {
    set({ events: [], filteredEvents: [] });
  },

  setFilters: (newFilters) => {
    set((state) => {
      const updatedFilters = { ...state.filters, ...newFilters };
      const filtered = applyFilters(state.events, updatedFilters);
      
      return {
        filters: updatedFilters,
        filteredEvents: filtered,
      };
    });
  },
  
  clearFilters: () => {
    set((state) => ({
      filters: { ...defaultFilters },
      filteredEvents: state.events,
    }));
  },
}));

// Helper function to apply filters
function applyFilters(events: EventData[], filters: EventState['filters']): EventData[] {
  return events.filter((event) => {
    // Type filter
    if (filters.type && event.type !== filters.type) {
      return false;
    }
    
    // Severity filter
    if (filters.severity && event.severity !== filters.severity) {
      return false;
    }
    
    // Source filter
    if (filters.source && event.source !== filters.source) {
      return false;
    }
    
    // Time range filters
    if (filters.startTime && event.timestamp < filters.startTime) {
      return false;
    }
    
    if (filters.endTime && event.timestamp > filters.endTime) {
      return false;
    }
    
    // Search text (case insensitive)
    if (filters.searchText) {
      const searchLower = filters.searchText.toLowerCase();
      const messageMatch = event.message.toLowerCase().includes(searchLower);
      const sourceMatch = event.source.toLowerCase().includes(searchLower);
      const typeMatch = event.type.toLowerCase().includes(searchLower);
      
      // Also search in metadata if it's a string
      let metadataMatch = false;
      if (event.metadata) {
        try {
          if (typeof event.metadata === 'string') {
            metadataMatch = event.metadata.toLowerCase().includes(searchLower);
          } else {
            // Try to stringify the metadata and search in it
            metadataMatch = JSON.stringify(event.metadata).toLowerCase().includes(searchLower);
          }
        } catch (e) {
          // Ignore errors in metadata searching
        }
      }
      
      if (!messageMatch && !sourceMatch && !typeMatch && !metadataMatch) {
        return false;
      }
    }
    
    return true;
  });
} 