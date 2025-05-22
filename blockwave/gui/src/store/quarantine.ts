import { create } from 'zustand';

export interface QuarantineItem {
  id: string;
  filepath: string;
  originalPath: string;
  timestamp: number;
  reason: string;
  hash: string;
  size: number;
  status: 'quarantined' | 'restored' | 'deleted';
  metadata?: Record<string, any>;
}

interface QuarantineState {
  items: QuarantineItem[];
  loading: boolean;
  error: string | null;
  
  // Actions
  fetchItems: () => Promise<void>;
  addItem: (item: QuarantineItem) => void;
  updateItem: (item: QuarantineItem) => void;
  removeItem: (id: string) => void;
  
  // Quarantine operations
  restoreFile: (id: string) => Promise<boolean>;
  deleteFile: (id: string) => Promise<boolean>;
}

export const useQuarantineStore = create<QuarantineState>((set, get) => ({
  items: [],
  loading: false,
  error: null,
  
  fetchItems: async () => {
    set({ loading: true, error: null });
    try {
      // In a real implementation, this would fetch from the backend
      // For now, we'll just simulate a delay
      await new Promise(resolve => setTimeout(resolve, 500));
      
      // For demo purposes, we're not actually fetching anything here
      set({ loading: false });
    } catch (error) {
      set({ 
        loading: false, 
        error: error instanceof Error ? error.message : 'Failed to fetch quarantined items' 
      });
    }
  },
  
  addItem: (item) => {
    set(state => ({
      items: [item, ...state.items]
    }));
  },
  
  updateItem: (updatedItem) => {
    set(state => ({
      items: state.items.map(item => 
        item.id === updatedItem.id ? updatedItem : item
      )
    }));
  },
  
  removeItem: (id) => {
    set(state => ({
      items: state.items.filter(item => item.id !== id)
    }));
  },
  
  // These methods would call the backend API
  restoreFile: async (id) => {
    const { socket } = window as any;
    if (!socket) return false;
    
    try {
      set(state => ({
        items: state.items.map(item => 
          item.id === id 
            ? { ...item, status: 'restored' } 
            : item
        )
      }));
      
      // Call backend action
      socket.emit('action', {
        action: 'restore_quarantined_file',
        payload: { id }
      });
      
      return true;
    } catch (error) {
      console.error('Failed to restore file:', error);
      return false;
    }
  },
  
  deleteFile: async (id) => {
    const { socket } = window as any;
    if (!socket) return false;
    
    try {
      set(state => ({
        items: state.items.map(item => 
          item.id === id 
            ? { ...item, status: 'deleted' } 
            : item
        )
      }));
      
      // Call backend action
      socket.emit('action', {
        action: 'delete_quarantined_file',
        payload: { id }
      });
      
      return true;
    } catch (error) {
      console.error('Failed to delete file:', error);
      return false;
    }
  },
})); 