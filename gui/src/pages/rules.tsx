import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Shield,
  ToggleLeft,
  ToggleRight,
  Plus,
  Edit,
  Trash2,
  AlertCircle,
  Check,
  X,
  ChevronDown,
  ChevronUp,
} from 'lucide-react';

// Mock rules data
const mockRules = [
  {
    id: '1',
    name: 'File Encryption Detection',
    description: 'Detects rapid encryption of multiple files',
    enabled: true,
    category: 'file',
    severity: 'critical',
    actions: ['alert', 'quarantine', 'process_kill'],
    conditions: [
      { type: 'file_activity', op: 'count', threshold: 10, timeframe: '5s' },
      { type: 'file_entropy', op: 'gte', value: 7.8 },
    ],
  },
  {
    id: '2',
    name: 'Ransom Note Detection',
    description: 'Detects creation of common ransom note files',
    enabled: true,
    category: 'file',
    severity: 'critical',
    actions: ['alert', 'process_kill'],
    conditions: [
      {
        type: 'file_pattern',
        op: 'match',
        pattern: ['READ_ME.txt', 'HOW_TO_DECRYPT.txt', 'RECOVERY.txt'],
      },
    ],
  },
  {
    id: '3',
    name: 'Suspicious Process Activity',
    description: 'Detects processes showing ransomware-like behavior',
    enabled: false,
    category: 'process',
    severity: 'high',
    actions: ['alert'],
    conditions: [
      { type: 'process_name', op: 'in', list: ['unknown.exe', 'svchost32.exe'] },
      { type: 'file_access', op: 'count', threshold: 50, timeframe: '10s' },
    ],
  },
];

export function Rules() {
  const [rules, setRules] = useState(mockRules);
  const [expandedRule, setExpandedRule] = useState<string | null>(null);
  const [showConfirm, setShowConfirm] = useState(false);
  const [selectedRule, setSelectedRule] = useState<string | null>(null);
  const [showAddEdit, setShowAddEdit] = useState(false);
  const [isEdit, setIsEdit] = useState(false);

  // Toggle rule enabled state
  const toggleRuleState = (id: string) => {
    setRules((prev) =>
      prev.map((rule) =>
        rule.id === id ? { ...rule, enabled: !rule.enabled } : rule
      )
    );
  };

  // Toggle expanded state for a rule
  const toggleExpanded = (id: string) => {
    setExpandedRule(expandedRule === id ? null : id);
  };

  // Handle edit rule
  const handleEdit = (id: string) => {
    setSelectedRule(id);
    setIsEdit(true);
    setShowAddEdit(true);
  };

  // Handle delete rule
  const handleDelete = (id: string) => {
    setSelectedRule(id);
    setShowConfirm(true);
  };

  // Confirm delete rule
  const confirmDelete = () => {
    if (selectedRule) {
      setRules((prev) => prev.filter((rule) => rule.id !== selectedRule));
    }
    setShowConfirm(false);
    setSelectedRule(null);
  };

  // Handle add new rule
  const handleAddRule = () => {
    setSelectedRule(null);
    setIsEdit(false);
    setShowAddEdit(true);
  };

  // Get a CSS class for severity
  const getSeverityClass = (severity: string) => {
    switch (severity) {
      case 'critical':
        return 'bg-destructive/10 text-destructive border-destructive';
      case 'high':
        return 'bg-warning/10 text-warning border-warning';
      case 'medium':
        return 'bg-yellow-500/10 text-yellow-500 border-yellow-500';
      case 'low':
        return 'bg-primary/10 text-primary border-primary';
      default:
        return 'bg-muted text-muted-foreground';
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between space-y-2 sm:space-y-0">
        <h1 className="text-2xl font-bold tracking-tight">Detection Rules</h1>
        <button
          onClick={handleAddRule}
          className="inline-flex items-center gap-2 px-3 py-2 rounded-md bg-primary text-primary-foreground hover:bg-primary/90 transition-colors"
        >
          <Plus size={16} />
          <span>Add Rule</span>
        </button>
      </div>

      {/* Rules list */}
      <div className="border rounded-lg overflow-hidden">
        <div className="px-4 py-3 border-b bg-muted/40">
          <h2 className="text-lg font-medium">Active Rules</h2>
        </div>

        <div className="divide-y">
          {rules.map((rule) => (
            <div
              key={rule.id}
              className="hover:bg-muted/20 transition-colors"
            >
              <div className="p-4 flex items-center justify-between">
                <div
                  className="flex-1 flex items-center gap-3 cursor-pointer"
                  onClick={() => toggleExpanded(rule.id)}
                >
                  <div>
                    <Shield
                      size={20}
                      className={rule.enabled ? 'text-primary' : 'text-muted-foreground'}
                    />
                  </div>
                  <div className="flex-1">
                    <div className="flex items-center">
                      <h3 className="font-medium">{rule.name}</h3>
                      <div
                        className={`ml-2 px-2 py-0.5 text-xs rounded-full border ${getSeverityClass(
                          rule.severity
                        )}`}
                      >
                        {rule.severity}
                      </div>
                    </div>
                    <p className="text-sm text-muted-foreground mt-1">
                      {rule.description}
                    </p>
                  </div>
                  <button className="p-1">
                    {expandedRule === rule.id ? (
                      <ChevronUp size={16} />
                    ) : (
                      <ChevronDown size={16} />
                    )}
                  </button>
                </div>

                <div className="flex items-center ml-4 space-x-2">
                  <button
                    onClick={() => toggleRuleState(rule.id)}
                    className="p-1"
                    title={rule.enabled ? 'Disable rule' : 'Enable rule'}
                  >
                    {rule.enabled ? (
                      <ToggleRight size={20} className="text-success" />
                    ) : (
                      <ToggleLeft size={20} className="text-muted-foreground" />
                    )}
                  </button>
                  <button
                    onClick={() => handleEdit(rule.id)}
                    className="p-1 text-muted-foreground hover:text-foreground"
                    title="Edit rule"
                  >
                    <Edit size={16} />
                  </button>
                  <button
                    onClick={() => handleDelete(rule.id)}
                    className="p-1 text-muted-foreground hover:text-destructive"
                    title="Delete rule"
                  >
                    <Trash2 size={16} />
                  </button>
                </div>
              </div>

              {/* Expanded rule details */}
              <AnimatePresence>
                {expandedRule === rule.id && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: 'auto', opacity: 1 }}
                    exit={{ height: 0, opacity: 0 }}
                    transition={{ duration: 0.2 }}
                    className="overflow-hidden bg-muted/10"
                  >
                    <div className="p-4 pl-12 grid gap-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <h4 className="text-sm font-medium mb-2">Conditions</h4>
                          <div className="space-y-2">
                            {rule.conditions.map((condition, i) => (
                              <div
                                key={i}
                                className="p-2 text-xs bg-background border rounded"
                              >
                                <code>{JSON.stringify(condition)}</code>
                              </div>
                            ))}
                          </div>
                        </div>

                        <div>
                          <h4 className="text-sm font-medium mb-2">Actions</h4>
                          <div className="flex flex-wrap gap-2">
                            {rule.actions.map((action) => (
                              <span
                                key={action}
                                className="px-2 py-1 text-xs bg-background border rounded"
                              >
                                {action}
                              </span>
                            ))}
                          </div>

                          <h4 className="text-sm font-medium mt-4 mb-2">Details</h4>
                          <dl className="grid grid-cols-2 gap-x-4 gap-y-2 text-sm">
                            <dt className="text-muted-foreground">Category:</dt>
                            <dd>{rule.category}</dd>
                            <dt className="text-muted-foreground">ID:</dt>
                            <dd className="font-mono">{rule.id}</dd>
                          </dl>
                        </div>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          ))}

          {rules.length === 0 && (
            <div className="p-8 text-center">
              <div className="inline-flex items-center justify-center p-3 rounded-full bg-muted mb-4">
                <Shield className="h-6 w-6 text-muted-foreground" />
              </div>
              <p className="text-muted-foreground">No rules defined.</p>
              <p className="text-sm text-muted-foreground mt-1">
                Click "Add Rule" to create your first detection rule.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Delete confirmation modal */}
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
                  <AlertCircle className="h-6 w-6 text-destructive" />
                </div>
                <h2 className="text-xl font-semibold">Delete Rule?</h2>
                <p className="text-center text-muted-foreground">
                  Are you sure you want to delete this detection rule? This
                  action cannot be undone.
                </p>

                <div className="flex gap-3 mt-4 w-full">
                  <button
                    onClick={() => setShowConfirm(false)}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md border hover:bg-muted transition-colors"
                  >
                    <X size={18} />
                    <span>Cancel</span>
                  </button>
                  <button
                    onClick={confirmDelete}
                    className="flex-1 flex items-center justify-center gap-2 px-4 py-2 rounded-md text-white bg-destructive hover:bg-destructive/90 transition-colors"
                  >
                    <Check size={18} />
                    <span>Delete</span>
                  </button>
                </div>
              </div>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>

      {/* Add/Edit rule modal - This would be a more complex form in the real implementation */}
      <AnimatePresence>
        {showAddEdit && (
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
              className="relative rounded-lg border bg-background p-6 shadow-lg max-w-2xl w-full"
            >
              <div className="flex flex-col gap-4">
                <div className="flex items-center justify-between">
                  <h2 className="text-xl font-semibold">
                    {isEdit ? 'Edit Rule' : 'Add New Rule'}
                  </h2>
                  <button
                    onClick={() => setShowAddEdit(false)}
                    className="p-1 rounded-full hover:bg-muted"
                  >
                    <X size={20} />
                  </button>
                </div>

                <div className="h-96 flex items-center justify-center border rounded-md">
                  <p className="text-muted-foreground">
                    Rule editor form would go here in a real implementation.
                  </p>
                </div>

                <div className="flex justify-end gap-3 mt-4">
                  <button
                    onClick={() => setShowAddEdit(false)}
                    className="flex items-center gap-2 px-4 py-2 rounded-md border hover:bg-muted transition-colors"
                  >
                    <X size={18} />
                    <span>Cancel</span>
                  </button>
                  <button
                    onClick={() => setShowAddEdit(false)}
                    className="flex items-center gap-2 px-4 py-2 rounded-md text-white bg-primary hover:bg-primary/90 transition-colors"
                  >
                    <Check size={18} />
                    <span>{isEdit ? 'Save Changes' : 'Create Rule'}</span>
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