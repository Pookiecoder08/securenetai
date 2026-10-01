import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import { apiClient } from '../api/client';
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  applyNodeChanges,
  applyEdgeChanges,
  addEdge,
  Handle,
  Position,
  Panel
} from '@xyflow/react';
import {
  Network,
  Save,
  Plus,
  RotateCcw,
  Shield,
  Server,
  Database,
  Radio,
  Router as RouterIcon,
  CheckCircle2,
  Lock,
  Edit3,
  Search,
  Maximize2,
  Info,
  X,
  Globe,
  Monitor,
  Flame,
  AlertTriangle,
  Layers,
  ArrowRight
} from 'lucide-react';

// Custom Light Enterprise Node Component
const CustomNode = ({ data, isConnectable }) => {
  const category = (data.category || data.type || 'server').toLowerCase();
  
  const getIcon = () => {
    switch (category) {
      case 'router':
        return <RouterIcon className="w-5 h-5 text-blue-600" />;
      case 'firewall':
        return <Shield className="w-5 h-5 text-rose-600" />;
      case 'threat_source':
        return <Flame className="w-5 h-5 text-rose-600 animate-pulse" />;
      case 'sensor':
        return <Radio className="w-5 h-5 text-teal-600" />;
      case 'database':
        return <Database className="w-5 h-5 text-amber-600" />;
      case 'workstation':
        return <Monitor className="w-5 h-5 text-indigo-600" />;
      default:
        return <Server className="w-5 h-5 text-blue-600" />;
    }
  };

  const getBorderColor = () => {
    if (data.isThreatTarget || category === 'threat_source') {
      return 'border-rose-500 shadow-rose-100';
    }
    switch (category) {
      case 'router':
        return 'border-blue-300 hover:border-blue-500';
      case 'firewall':
        return 'border-rose-300 hover:border-rose-500';
      case 'sensor':
        return 'border-teal-300 hover:border-teal-500';
      case 'database':
        return 'border-amber-300 hover:border-amber-500';
      case 'workstation':
        return 'border-indigo-300 hover:border-indigo-500';
      default:
        return 'border-slate-300 hover:border-blue-500';
    }
  };

  return (
    <div
      className={`px-4 py-3 rounded-2xl bg-white border-2 ${getBorderColor()} shadow-md min-w-[210px] text-xs font-sans transition-all hover:shadow-lg relative group`}
    >
      <Handle type="target" position={Position.Left} isConnectable={isConnectable} className="!bg-blue-600 !w-2.5 !h-2.5" />
      <Handle type="target" position={Position.Top} isConnectable={isConnectable} className="!bg-blue-600 !w-2.5 !h-2.5" />

      <div className="flex items-center gap-2.5 mb-2">
        <div className="p-2 rounded-xl bg-slate-50 border border-slate-200 shrink-0">
          {getIcon()}
        </div>
        <div className="flex-1 min-w-0">
          <div className="font-bold text-slate-900 text-xs truncate">{data.label || data.name}</div>
          <div className="text-[10px] text-slate-500 font-mono capitalize">{category}</div>
        </div>
      </div>

      <div className="flex items-center justify-between pt-2 border-t border-slate-100 font-mono">
        <span className="text-[11px] font-bold text-blue-700">{data.ip}</span>
        <span
          className={`text-[9px] px-1.5 py-0.5 rounded font-bold uppercase ${
            data.status === 'warning'
              ? 'bg-amber-50 text-amber-700 border border-amber-200'
              : data.status === 'critical'
              ? 'bg-rose-50 text-rose-700 border border-rose-200'
              : 'bg-emerald-50 text-emerald-700 border border-emerald-200'
          }`}
        >
          {data.status || 'ONLINE'}
        </span>
      </div>

      <Handle type="source" position={Position.Right} isConnectable={isConnectable} className="!bg-blue-600 !w-2.5 !h-2.5" />
      <Handle type="source" position={Position.Bottom} isConnectable={isConnectable} className="!bg-blue-600 !w-2.5 !h-2.5" />
    </div>
  );
};

const nodeTypes = {
  customNode: CustomNode
};

const Topology = () => {
  const { isAdmin } = useAuth();
  const { livePackets } = useSOC();

  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [updatedAt, setUpdatedAt] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isSaving, setIsSaving] = useState(false);
  const [feedback, setFeedback] = useState(null);

  // Inspector & Filter state
  const [selectedNode, setSelectedNode] = useState(null);
  const [searchTerm, setSearchTerm] = useState('');

  // Node creation state (Admin only)
  const [showAddModal, setShowAddModal] = useState(false);
  const [newNodeName, setNewNodeName] = useState('');
  const [newNodeIp, setNewNodeIp] = useState('');
  const [newNodeCategory, setNewNodeCategory] = useState('server');
  const [formError, setFormError] = useState('');

  // Load Topology strictly from GET /api/topology
  const loadTopologyFromBackend = useCallback(async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getTopology();
      if (data && data.nodes && data.edges) {
        setNodes(data.nodes);
        setEdges(data.edges);
        setUpdatedAt(data.updated_at || null);
      }
    } catch (err) {
      setFeedback({ success: false, message: 'Failed to load topology from backend.' });
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    loadTopologyFromBackend();
  }, [loadTopologyFromBackend]);

  // Handle Node Changes (Drag / Position)
  const onNodesChange = useCallback(
    (changes) => {
      if (!isAdmin) return;
      setNodes((nds) => applyNodeChanges(changes, nds));
    },
    [isAdmin]
  );

  // Handle Edge Changes
  const onEdgesChange = useCallback(
    (changes) => {
      if (!isAdmin) return;
      setEdges((eds) => applyEdgeChanges(changes, eds));
    },
    [isAdmin]
  );

  // Handle Connection Creation
  const onConnect = useCallback(
    (params) => {
      if (!isAdmin) return;
      const newEdge = {
        ...params,
        id: `e-${params.source}-${params.target}`,
        label: 'Internal Network',
        style: { stroke: '#3b82f6', strokeWidth: 2 }
      };
      setEdges((eds) => addEdge(newEdge, eds));
    },
    [isAdmin]
  );

  // Handle Node Selection for Inspector
  const onNodeClick = useCallback((_, node) => {
    setSelectedNode(node);
  }, []);

  // Save Topology to POST /api/topology
  const handleSaveTopology = async () => {
    if (!isAdmin || isSaving) return;
    setIsSaving(true);
    setFeedback(null);
    try {
      const result = await apiClient.saveTopology(nodes, edges);
      setUpdatedAt(new Date().toISOString());
      setFeedback({ success: true, message: result.message || 'Topology architecture saved.' });
    } catch (err) {
      setFeedback({ success: false, message: err.message || 'Failed to save topology.' });
    } finally {
      setIsSaving(false);
    }
  };

  // Add Custom Node Submit Handler with Form Validation
  const handleAddNodeSubmit = (e) => {
    e.preventDefault();
    setFormError('');

    if (!newNodeName.trim()) {
      setFormError('Asset name is required.');
      return;
    }

    // IP v4 Validation regex
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (newNodeIp && !ipRegex.test(newNodeIp.trim())) {
      setFormError('Please enter a valid IPv4 address (e.g. 192.168.1.50).');
      return;
    }

    const id = `node-${Date.now()}`;
    const defaultIp = newNodeIp.trim() || `192.168.1.${100 + nodes.length}`;

    const newNode = {
      id,
      type: 'customNode',
      position: { x: 350 + (nodes.length % 3) * 120, y: 200 + (nodes.length % 2) * 100 },
      data: {
        label: newNodeName.trim(),
        category: newNodeCategory,
        ip: defaultIp,
        status: 'online',
        description: 'Dynamically deployed node'
      }
    };

    setNodes((prev) => [...prev, newNode]);
    setNewNodeName('');
    setNewNodeIp('');
    setShowAddModal(false);
  };

  // Delete Node (Admin Only)
  const handleDeleteNode = (nodeId) => {
    if (!isAdmin) return;
    setNodes((prev) => prev.filter((n) => n.id !== nodeId));
    setEdges((prev) => prev.filter((e) => e.source !== nodeId && e.target !== nodeId));
    if (selectedNode?.id === nodeId) setSelectedNode(null);
  };

  // Highlight active threat IP paths if a threat packet arrives
  const recentThreatIp = useMemo(() => {
    const threatPkt = livePackets.find((p) => p.is_threat);
    return threatPkt ? threatPkt.src_ip : null;
  }, [livePackets]);

  // Filter nodes for search
  const filteredNodes = useMemo(() => {
    if (!searchTerm) return nodes;
    const q = searchTerm.toLowerCase();
    return nodes.filter(
      (n) =>
        (n.data?.label || '').toLowerCase().includes(q) ||
        (n.data?.ip || '').toLowerCase().includes(q) ||
        (n.data?.category || '').toLowerCase().includes(q)
    );
  }, [nodes, searchTerm]);

  return (
    <div className="p-4 sm:p-6 space-y-4 flex flex-col h-[calc(100vh-4rem)] max-w-7xl mx-auto">
      {/* Top Controls Bar */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div>
          <h1 className="text-base font-bold text-slate-900 font-sans flex items-center gap-2">
            <Network className="w-5 h-5 text-blue-600" />
            Enterprise Network Architecture Topology
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            {isAdmin ? (
              <span className="text-blue-700 font-bold flex items-center gap-1">
                <Edit3 className="w-3.5 h-3.5" /> Administrator Mode: Full Drag, Node Creation &amp; Edge Editing
              </span>
            ) : (
              <span className="text-slate-500 flex items-center gap-1">
                <Lock className="w-3.5 h-3.5 text-slate-400" /> Read-Only Mode: Architecture modifications restricted to Administrators
              </span>
            )}
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
          <div className="relative">
            <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
            <input
              type="text"
              placeholder="Filter assets..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              className="pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-600 w-44"
            />
          </div>

          <button
            onClick={loadTopologyFromBackend}
            className="px-3 py-1.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold transition-all flex items-center gap-1.5 shadow-2xs"
          >
            <RotateCcw className="w-3.5 h-3.5 text-blue-600" />
            <span>Reload</span>
          </button>

          {isAdmin && (
            <button
              onClick={() => setShowAddModal(true)}
              className="px-3 py-1.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold transition-all flex items-center gap-1.5 shadow-2xs"
            >
              <Plus className="w-3.5 h-3.5 text-blue-600" />
              <span>Add Asset</span>
            </button>
          )}

          {isAdmin && (
            <button
              onClick={handleSaveTopology}
              disabled={isSaving}
              className="px-4 py-1.5 rounded-xl bg-blue-600 hover:bg-blue-500 text-white font-bold transition-all shadow-2xs flex items-center gap-1.5 disabled:opacity-50"
            >
              <Save className="w-3.5 h-3.5" />
              <span>{isSaving ? 'Saving...' : 'Save Topology'}</span>
            </button>
          )}
        </div>
      </div>

      {/* Feedback Banner */}
      {feedback && (
        <div
          className={`p-3 rounded-xl border text-xs font-mono flex items-center justify-between ${
            feedback.success
              ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
              : 'bg-rose-50 border-rose-200 text-rose-700'
          }`}
        >
          <div className="flex items-center gap-2">
            <CheckCircle2 className="w-4 h-4" />
            <span>{feedback.message}</span>
          </div>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-slate-600">
            <X className="w-4 h-4" />
          </button>
        </div>
      )}

      {/* Main Canvas Workspace */}
      <div className="flex-1 w-full rounded-2xl border border-slate-200 bg-slate-50 relative overflow-hidden shadow-2xs flex">
        <ReactFlow
          nodes={filteredNodes}
          edges={edges}
          onNodesChange={onNodesChange}
          onEdgesChange={onEdgesChange}
          onConnect={onConnect}
          onNodeClick={onNodeClick}
          nodeTypes={nodeTypes}
          nodesDraggable={isAdmin}
          nodesConnectable={isAdmin}
          elementsSelectable={true}
          fitView
        >
          {/* Light Grid Background */}
          <Background color="#cbd5e1" gap={24} size={1} />
          
          <Controls className="!bg-white !border-slate-200 !shadow-2xs" />
          
          <MiniMap
            nodeColor={(n) => {
              const cat = (n.data?.category || '').toLowerCase();
              if (cat === 'firewall') return '#ef4444';
              if (cat === 'sensor') return '#14b8a6';
              if (cat === 'database') return '#f59e0b';
              return '#2563eb';
            }}
          />

          {/* Canvas Zone Architecture Overlay Legend */}
          <Panel position="top-left" className="m-4 bg-white/90 backdrop-blur-xs p-3 rounded-xl border border-slate-200 shadow-2xs text-[11px] font-mono space-y-1.5">
            <div className="font-bold text-slate-800 uppercase text-[10px] tracking-wider mb-1">
              Architecture Zones &amp; Connections
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-blue-600"></span>
              <span className="text-slate-600">Internal Traffic</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-blue-400 border-t border-dashed border-blue-600"></span>
              <span className="text-slate-600">WAN Uplink</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-teal-500 border-t border-dotted border-teal-600"></span>
              <span className="text-slate-600">Mirror TAP Connection</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="w-3 h-0.5 bg-rose-500"></span>
              <span className="text-rose-700 font-bold">Threat Path</span>
            </div>
          </Panel>
        </ReactFlow>

        {/* Node Inspector Drawer */}
        {selectedNode && (
          <div className="w-80 bg-white border-l border-slate-200 p-5 z-20 flex flex-col justify-between shadow-xl animate-in slide-in-from-right duration-200">
            <div className="space-y-4">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100">
                <div className="flex items-center gap-2">
                  <Info className="w-4 h-4 text-blue-600" />
                  <h3 className="text-xs font-bold uppercase font-mono text-slate-900">
                    Asset Details
                  </h3>
                </div>
                <button
                  onClick={() => setSelectedNode(null)}
                  className="text-slate-400 hover:text-slate-600 p-1"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-3 font-mono text-xs">
                <div>
                  <span className="text-[10px] text-slate-400 uppercase block">Asset Name</span>
                  <span className="font-bold text-slate-900 text-sm">{selectedNode.data?.label || selectedNode.data?.name}</span>
                </div>

                <div>
                  <span className="text-[10px] text-slate-400 uppercase block">Category / Type</span>
                  <span className="font-semibold text-blue-700 uppercase">{selectedNode.data?.category || selectedNode.data?.type || 'Server'}</span>
                </div>

                <div>
                  <span className="text-[10px] text-slate-400 uppercase block">IPv4 Address</span>
                  <span className="font-bold text-slate-800">{selectedNode.data?.ip || '192.168.1.1'}</span>
                </div>

                <div>
                  <span className="text-[10px] text-slate-400 uppercase block">Current Status</span>
                  <span className="inline-flex px-2 py-0.5 rounded font-bold text-[10px] uppercase bg-emerald-50 text-emerald-700 border border-emerald-200">
                    {selectedNode.data?.status || 'ONLINE'}
                  </span>
                </div>

                {selectedNode.data?.details && (
                  <div>
                    <span className="text-[10px] text-slate-400 uppercase block">Configuration Notes</span>
                    <span className="text-slate-600 leading-snug block mt-0.5">{selectedNode.data.details}</span>
                  </div>
                )}
              </div>
            </div>

            {isAdmin && (
              <button
                onClick={() => handleDeleteNode(selectedNode.id)}
                className="w-full py-2 bg-rose-50 hover:bg-rose-100 border border-rose-200 text-rose-700 font-mono font-bold text-xs rounded-xl transition-all"
              >
                Delete Asset
              </button>
            )}
          </div>
        )}
      </div>

      {/* Add Custom Node Modal (Admin Only) */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="bg-white border border-slate-200 rounded-2xl shadow-xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="text-sm font-bold text-slate-900 font-mono uppercase">
                Add Architecture Asset
              </h3>
              <button onClick={() => setShowAddModal(false)} className="text-slate-400 hover:text-slate-600">
                <X className="w-4 h-4" />
              </button>
            </div>

            {formError && (
              <div className="p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-mono">
                {formError}
              </div>
            )}

            <form onSubmit={handleAddNodeSubmit} className="space-y-3 font-mono text-xs">
              <div>
                <label className="block text-slate-600 font-bold uppercase text-[10px] mb-1">
                  Asset Label / Name *
                </label>
                <input
                  type="text"
                  placeholder="e.g. DMZ Reverse Proxy"
                  value={newNodeName}
                  onChange={(e) => setNewNodeName(e.target.value)}
                  required
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:border-blue-600"
                />
              </div>

              <div>
                <label className="block text-slate-600 font-bold uppercase text-[10px] mb-1">
                  Asset Category *
                </label>
                <select
                  value={newNodeCategory}
                  onChange={(e) => setNewNodeCategory(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:border-blue-600"
                >
                  <option value="router">Edge Router</option>
                  <option value="firewall">Next-Gen Firewall</option>
                  <option value="sensor">NIDS Sensor</option>
                  <option value="server">App / Web Server</option>
                  <option value="database">Database Cluster</option>
                  <option value="workstation">SOC Workstation</option>
                </select>
              </div>

              <div>
                <label className="block text-slate-600 font-bold uppercase text-[10px] mb-1">
                  IPv4 Address
                </label>
                <input
                  type="text"
                  placeholder="e.g. 192.168.1.80"
                  value={newNodeIp}
                  onChange={(e) => setNewNodeIp(e.target.value)}
                  className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 focus:outline-none focus:border-blue-600"
                />
              </div>

              <div className="pt-2 flex justify-end gap-2">
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
                  className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-2 rounded-xl text-xs font-bold text-white bg-blue-600 hover:bg-blue-500 shadow-2xs"
                >
                  Deploy Node
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default Topology;
