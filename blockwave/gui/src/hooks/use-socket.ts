import { useState, useCallback, useEffect } from 'react';
import { io, Socket } from 'socket.io-client';
import { useEventStore } from '../store/events';
import { useQuarantineStore } from '../store/quarantine';

interface UseSocketReturn {
  socket: Socket | null;
  connected: boolean;
  connect: (url: string) => void;
  disconnect: () => void;
  sendAction: (action: string, payload: any) => void;
}

export function useSocket(): UseSocketReturn {
  const [socket, setSocket] = useState<Socket | null>(null);
  const [connected, setConnected] = useState(false);
  const addEvent = useEventStore((state) => state.addEvent);
  const addQuarantineItem = useQuarantineStore((state) => state.addItem);
  const updateQuarantineItem = useQuarantineStore((state) => state.updateItem);

  const connect = useCallback((url: string) => {
    const newSocket = io(url, {
      reconnectionAttempts: 5,
      reconnectionDelay: 1000,
      timeout: 10000,
      path: '/socket.io',
      transports: ['websocket', 'polling'],
    });

    newSocket.on('connect', () => {
      console.log('Socket connected');
      setConnected(true);
    });

    newSocket.on('disconnect', () => {
      console.log('Socket disconnected');
      setConnected(false);
    });

    newSocket.on('error', (error) => {
      console.error('Socket error:', error);
      setConnected(false);
    });

    // Set up event listeners
    newSocket.on('event', (data) => {
      console.log('Received event:', data);
      addEvent(data);
    });

    newSocket.on('quarantineUpdate', (data) => {
      console.log('Quarantine update:', data);
      // Determine if we need to add or update
      if (data.action === 'add') {
        addQuarantineItem(data.item);
      } else if (data.action === 'update') {
        updateQuarantineItem(data.item);
      }
    });

    // Subscribe to event stream
    newSocket.emit('subscribe', { stream: 'events' });

    setSocket(newSocket);

    return () => {
      newSocket.disconnect();
    };
  }, [addEvent, addQuarantineItem, updateQuarantineItem]);

  const disconnect = useCallback(() => {
    if (socket) {
      socket.disconnect();
      setSocket(null);
      setConnected(false);
    }
  }, [socket]);

  const sendAction = useCallback(
    (action: string, payload: any) => {
      if (socket && connected) {
        socket.emit('action', { action, payload });
      } else {
        console.error('Cannot send action, socket not connected');
      }
    },
    [socket, connected]
  );

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      if (socket) {
        socket.disconnect();
      }
    };
  }, [socket]);

  return {
    socket,
    connected,
    connect,
    disconnect,
    sendAction,
  };
} 