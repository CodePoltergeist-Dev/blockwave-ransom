import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { useQuarantineStore, QuarantineItem } from '@/store/quarantine';
import { formatDate, formatBytes, truncate } from '@/lib/utils';
import {
  AlertTriangle,
  FileArchive,
  Trash2,
  FileQuestion,
  RefreshCw,
  Check,
  X,
  Clock,
  Search,
} from 'lucide-react';

export function Quarantine() {
  const { items, fetchItems, restoreFile, deleteFile } = useQuarantineStore();
  const [searchText, setSearchText] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [actionItem, setActionItem] = useState<string | null>(null);
  const [actionType, setActionType] = useState<'restore' | 'delete' | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);

  // Filter items based on search
  const filteredItems = items.filter((item) => {
    if (!searchText) return true;
    
    const search = searchText.toLowerCase();
    return (
      item.filepath.toLowerCase().includes(search) ||
      item.originalPath.toLowerCase().includes(search) ||
      item.reason.toLowerCase().includes(search) ||
      item.hash.toLowerCase().includes(search)
    );
  });

  // Load quarantine items on mount
  useEffect(() => {
    fetchItems();
  }, [fetchItems]);

  // Handle refresh
  const handleRefresh = () => {
    setIsLoading(true);
    fetchItems().finally(() => {
      setTimeout(() => setIsLoading(false), 500);
    });
  };

  // Handle restore
  const onRestore = async (id: string) => {
    setActionItem(id);
    setActionType('restore');
    setShowConfirm(true);
  };

  // Handle delete
  const onDelete = async (id: string) => {
    setActionItem(id);
    setActionType('delete');
    setShowConfirm(true);
  };

  // Handle confirmation
  const handleConfirm = async () => {
    if (!actionItem || !actionType) return;
    
    try {
      if (actionType === 'restore') {
        await restoreFile(actionItem);
      } else if (actionType === 'delete') {
        await deleteFile(actionItem);
      }
    } catch (error) {
      console.error(`Failed to ${actionType} file:`, error);
    } finally {
      setShowConfirm(false);
      setActionItem(null);
      setActionType(null);
    }
  };

  // Cancel confirmation
  const handleCancel = () => {
    setShowConfirm(false);
    setActionItem(null);
    setActionType(null);
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <h1 className="text-2xl font-bold tracking-tight">Quarantine</h1>
        <div className="flex items-center space-x-2">
          <span className="text-sm text-muted-foreground">
            {filteredItems.length} quarantined files
          </span>
        </div>
      </div>

      {/* Search bar */}
      <div className="flex flex-col md:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Search quarantined files..."
            className="w-full pl-9 pr-4 py-2 rounded-md border bg-background"
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
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
          onClick={handleRefresh}
          className="flex items-center gap-2 px-3 py-2 rounded-md border bg-background hover:bg-secondary transition-colors"
        >
          <RefreshCw size={16} className={isLoading ? 'animate-spin' : undefined} />
          <span>Refresh</span>
        </button>
      </div>

      {/* Quarantine items */}
      <div className="border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b bg-muted/40">
          <h2 className="text-lg font-medium">Quarantined Files</h2>
        </div>

        {filteredItems.length > 0 ? (
          <div className="divide-y">
            {filteredItems.map((item) => (
              <QuarantineItemRow
                key={item.id}
                item={item}
                onRestore={onRestore}
                onDelete={onDelete}
              />
            ))}
          </div>
        ) : (
          <div className="p-8 text-center">
            <div className="inline-flex items-center justify-center p-3 rounded-full bg-muted mb-4">
              {searchText ? (
                <Search className="h-6 w-6 text-muted-foreground" />
              ) : (
                <FileArchive className="h-6 w-6 text-muted-foreground" />
              )}
            </div>
            <p className="text-muted-foreground">
              {searchText ? 'No files match your search.' : 'No quarantined files.'}
            </p>
            <p className="text-sm text-muted-foreground mt-1">
              {searchText
                ? 'Try changing your search term.'
                : 'Files will appear here when they are quarantined.'}
            </p>
          </div>
        )}
      </div>

      {/* Confirmation modal */}
      <AnimatePresence>
        {showConfirm && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center"
          >
            <motion.div
              initial={{ scale: 0.9, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              exit={{ scale: 0.9, opacity: 0 }}
              className="relative rounded-lg border bg-background p-6 shadow-lg max-w-md w-full"
            >
              <div className="flex flex-col items-center gap-4">
                <div className="p-3 rounded-full bg-muted">
                  {actionType === 'restore' ? (
                    <FileArchive className="h-6 w-6 text-warning" />
                  ) : (
                    <AlertTriangle className="h-6 w-6 text-destructive" />
                  )}
                </div>
                <h2 className="text-xl font-semibold">
                  {actionType === 'restore'
                    ? 'Restore quarantined file?'
                    : 'Permanently delete file?'}
                </h2>
                <p className="text-center text-muted-foreground">
                  {actionType === 'restore'
                    ? 'This file was quarantined for a reason. Are you sure you want to restore it to its original location?'
                    : 'This file will be permanently removed from the quarantine and cannot be recovered. Continue?'}
                </p>

                <div className="flex gap-3 mt-4 w-full">
                  <button
                    onClick={handleCancel}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md border hover:bg-muted transition-colors"
                  >
                    <X size={18} />
                    <span>Cancel</span>
                  </button>
                  <button
                    onClick={handleConfirm}
                    className={`flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-white transition-colors ${
                      actionType === 'restore'
                        ? 'bg-warning hover:bg-warning/90'
                        : 'bg-destructive hover:bg-destructive/90'
                    }`}
                  >
                    <Check size={18} />
                    <span>Confirm</span>
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

interface QuarantineItemRowProps {
  item: QuarantineItem;
  onRestore: (id: string) => void;
  onDelete: (id: string) => void;
}

function QuarantineItemRow({ item, onRestore, onDelete }: QuarantineItemRowProps) {
  const [expanded, setExpanded] = useState(false);

  // Determine status icon and color
  const statusInfo = {
    quarantined: { icon: <FileArchive size={16} />, color: 'text-warning' },
    restored: { icon: <Check size={16} />, color: 'text-success' },
    deleted: { icon: <Trash2 size={16} />, color: 'text-muted-foreground' },
  }[item.status];

  // Get filename from path
  const fileName = item.originalPath.split('/').pop() || item.originalPath;

  return (
    <div className="group">
      <div
        className="p-4 hover:bg-muted/20 transition-colors cursor-pointer group"
        onClick={() => setExpanded(!expanded)}
      >
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
          <div className="flex items-center space-x-3">
            <div className={`${statusInfo.color}`}>
              {statusInfo.icon}
            </div>
            <div className="overflow-hidden">
              <p className="font-medium truncate" title={fileName}>
                {truncate(fileName, 40)}
              </p>
              <p className="text-sm text-muted-foreground">
                {formatBytes(item.size)} • {formatDate(item.timestamp, false)}
              </p>
            </div>
          </div>

          {item.status === 'quarantined' && (
            <div className="flex ml-8 sm:ml-0 space-x-2 opacity-0 group-hover:opacity-100 transition-opacity">
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onRestore(item.id);
                }}
                className="flex items-center px-2 py-1 text-xs rounded border border-warning text-warning hover:bg-warning/10 transition-colors"
              >
                Restore
              </button>
              <button
                onClick={(e) => {
                  e.stopPropagation();
                  onDelete(item.id);
                }}
                className="flex items-center px-2 py-1 text-xs rounded border border-destructive text-destructive hover:bg-destructive/10 transition-colors"
              >
                Delete
              </button>
            </div>
          )}
        </div>
      </div>

      {/* Expanded details */}
      <AnimatePresence>
        {expanded && (
          <motion.div
            initial={{ height: 0, opacity: 0 }}
            animate={{ height: 'auto', opacity: 1 }}
            exit={{ height: 0, opacity: 0 }}
            transition={{ duration: 0.2 }}
            className="overflow-hidden bg-muted/20"
          >
            <div className="p-4 pl-10 text-sm grid gap-2">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <p className="text-muted-foreground mb-1">Original Path</p>
                  <p className="font-mono text-xs bg-muted p-2 rounded overflow-x-auto">
                    {item.originalPath}
                  </p>
                </div>
                <div>
                  <p className="text-muted-foreground mb-1">Quarantine Path</p>
                  <p className="font-mono text-xs bg-muted p-2 rounded overflow-x-auto">
                    {item.filepath}
                  </p>
                </div>
              </div>

              <div>
                <p className="text-muted-foreground mb-1">Hash</p>
                <p className="font-mono text-xs bg-muted p-2 rounded overflow-x-auto">
                  {item.hash}
                </p>
              </div>

              <div>
                <p className="text-muted-foreground mb-1">Reason for Quarantine</p>
                <p className="bg-muted p-2 rounded">{item.reason}</p>
              </div>

              {item.metadata && (
                <div>
                  <p className="text-muted-foreground mb-1">Additional Information</p>
                  <pre className="font-mono text-xs bg-muted p-2 rounded overflow-x-auto">
                    {JSON.stringify(item.metadata, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
} 