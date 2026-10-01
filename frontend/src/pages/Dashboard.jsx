import React, { useState, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import PacketModal from '../components/PacketModal';
import {
  ResponsiveContainer,
  AreaChart,
  Area,
  LineChart,
  Line,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  CartesianGrid
} from 'recharts';
import {
  Activity,
  ShieldAlert,
  ShieldCheck,
  Flame,
  Radio,
  Zap,
  Pause,
  Play,
  Cpu,
  Wifi,
  Terminal,
  Copy,
  Check,
  RotateCcw,
  Filter,
  Eye,
  Lock,
  Layers,
  Server,
  AlertTriangle,
  Clock
} from 'lucide-react';
import { apiClient } from '../api/client';

const PROTO_COLORS = {
  TCP: '#2563eb',     // Blue
  UDP: '#4f46e5',     // Indigo
  HTTP: '#059669',    // Emerald
  HTTPS: '#10b981',   // Teal
  DNS: '#d97706',     // Amber
  ICMP: '#64748b',    // Slate
  OTHER: '#94a3b8'
};

const Dashboard = ({ onInvestigatePacket }) => {
  const { isEmployee } = useAuth();
  const {
    status,
    isBackendOffline,
    connectionState,
    isPaused,
    setIsPaused,
    secondsAgo,
    livePackets,
    threats,
    firewallRules,
    rollingStats,
    protocolCounts,
    setFilterMode,
    resetSession,
    refreshPersistedData
  } = useSOC();

  const [activeProtoFilter, setActiveProtoFilter] = useState('ALL');
  const [injecting, setInjecting] = useState(false);
  const [isResetting, setIsResetting] = useState(false);
  const [showLiveFireModal, setShowLiveFireModal] = useState(false);

  // 1. Core Live Metric Calculations (Strictly from real backend status & packets)
  const totalPackets = status?.total_packets_captured ?? status?.packet_counter ?? 0;
  const totalThreats = status?.total_threats_detected ?? status?.threat_counter ?? 0;
  const activeRulesCount = status?.active_firewall_rules_count ?? firewallRules.length ?? 0;
  const adapterName = status?.adapter?.name || 'NIC Interface';
  const adapterIp = status?.adapter?.ip || '0.0.0.0';
  const snifferRunning = status?.sniffer_running ?? false;
  const currentFilterMode = status?.capture_filter_mode || 'soc_filtered';

  // Current PPS (latest from 60-second rolling time-series)
  const currentPps = rollingStats.length > 0 ? rollingStats[rollingStats.length - 1].pps : 0;

  // Filtered Live Packets for Table
  const displayedPackets = useMemo(() => {
    return livePackets.filter((pkt) => {
      if (activeProtoFilter !== 'ALL') {
        const p = (pkt.protocol || '').toUpperCase();
        if (p !== activeProtoFilter) return false;
      }
      return true;
    }).slice(0, 50);
  }, [livePackets, activeProtoFilter]);

  // Protocol Chart Data derived strictly from real protocolCounts
  const protocolData = useMemo(() => {
    return Object.entries(protocolCounts)
      .filter(([_, count]) => count > 0)
      .map(([name, value]) => ({
        name,
        value,
        color: PROTO_COLORS[name] || PROTO_COLORS.OTHER
      }));
  }, [protocolCounts]);

  // Handle Mode Change
  const handleModeSwitch = async (newMode) => {
    try {
      await setFilterMode(newMode);
    } catch (err) {
      console.error('Filter mode error:', err);
    }
  };

  // Reset Session
  const handleReset = async () => {
    if (isEmployee || isResetting) return;
    setIsResetting(true);
    try {
      await resetSession(true);
    } catch (e) {
      console.error('Reset error:', e);
    } finally {
      setIsResetting(false);
    }
  };

  // Live Fire Attack Test Trigger
  const handleLiveFireTest = async (type) => {
    if (isEmployee) return;
    setInjecting(true);
    try {
      await apiClient.injectThreat(type, '10.0.1.10', '198.51.100.77');
      refreshPersistedData();
    } catch (e) {
      console.error('Test injection error:', e);
    } finally {
      setInjecting(false);
    }
  };

  const hasTrafficData = rollingStats.some((p) => p.pps > 0 || p.inboundMbps > 0 || p.outboundMbps > 0);

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* 1. Concise System Health Summary Bar */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col md:flex-row md:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div className="flex items-center gap-3">
          <div
            className={`p-2.5 rounded-xl border ${
              snifferRunning
                ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                : 'bg-rose-50 border-rose-200 text-rose-700'
            }`}
          >
            <Activity className="w-5 h-5" />
          </div>
          <div>
            <div className="flex items-center gap-2">
              <h2 className="text-sm font-bold text-slate-900 font-sans">
                Sensor: {snifferRunning ? 'Promiscuous Sniffer Active' : 'Sensor Offline'}
              </h2>
              <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-slate-100 text-slate-700 border border-slate-200">
                Mode: {currentFilterMode}
              </span>
            </div>
            <p className="text-xs text-slate-500 font-mono mt-0.5">
              Adapter: <span className="font-semibold text-slate-800">{adapterName}</span> ({adapterIp})
            </p>
          </div>
        </div>

        <div className="flex items-center gap-3 flex-wrap text-xs font-mono">
          {/* Mode Switcher */}
          {!isEmployee && (
            <div className="flex items-center bg-slate-100 p-1 rounded-lg border border-slate-200">
              <Filter className="w-3.5 h-3.5 text-slate-400 ml-1.5 mr-1" />
              {['soc_filtered', 'targeted', 'raw_all'].map((mode) => (
                <button
                  key={mode}
                  onClick={() => handleModeSwitch(mode)}
                  className={`px-2 py-1 rounded text-[10px] font-bold transition-all ${
                    currentFilterMode === mode
                      ? 'bg-white text-blue-700 shadow-2xs border border-slate-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {mode === 'soc_filtered' ? 'Filtered' : mode === 'targeted' ? 'Targeted' : 'Raw'}
                </button>
              ))}
            </div>
          )}

          {/* Reset Session */}
          {!isEmployee && (
            <button
              onClick={handleReset}
              disabled={isResetting}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-semibold transition-all shadow-2xs disabled:opacity-50"
              title="Reset session telemetry counters"
            >
              <RotateCcw className={`w-3.5 h-3.5 text-blue-600 ${isResetting ? 'animate-spin' : ''}`} />
              <span>Reset Session</span>
            </button>
          )}

          {/* Controlled Live Fire Action */}
          {!isEmployee && (
            <button
              onClick={() => setShowLiveFireModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-semibold transition-all shadow-2xs"
            >
              <Terminal className="w-3.5 h-3.5" />
              <span>Live Fire Test</span>
            </button>
          )}
        </div>
      </div>

      {/* 2. Four Live Metric Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="soc-card soc-card-hover rounded-2xl p-5 bg-white">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
              Total Packets Captured
            </span>
            <div className="p-2 rounded-xl bg-blue-50 text-blue-600 border border-blue-200">
              <Activity className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-slate-900 font-mono">
            {totalPackets.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Live raw socket ingress frames</p>
        </div>

        <div className="soc-card soc-card-hover rounded-2xl p-5 bg-white">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
              Current Ingress PPS
            </span>
            <div className="p-2 rounded-xl bg-emerald-50 text-emerald-600 border border-emerald-200">
              <Cpu className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-slate-900 font-mono">
            {currentPps} <span className="text-sm font-normal text-slate-500">pps</span>
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">1-second reception rate</p>
        </div>

        <div className="soc-card soc-card-hover rounded-2xl p-5 bg-white">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
              Threats Detected
            </span>
            <div className="p-2 rounded-xl bg-rose-50 text-rose-600 border border-rose-200">
              <ShieldAlert className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-rose-600 font-mono">
            {totalThreats.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">SQLi / XSS / Probe matches</p>
        </div>

        <div className="soc-card soc-card-hover rounded-2xl p-5 bg-white">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
              Active Firewall Rules
            </span>
            <div className="p-2 rounded-xl bg-amber-50 text-amber-600 border border-amber-200">
              <Flame className="w-4 h-4" />
            </div>
          </div>
          <div className="text-2xl font-extrabold text-slate-900 font-mono">
            {activeRulesCount.toLocaleString()}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">OS kernel drop ACL policies</p>
        </div>
      </div>

      {/* 3. 60-Second Real-Time Time Series Charts Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* 60-Second Packets Per Second Chart */}
        <div className="lg:col-span-2 soc-card rounded-2xl p-5 bg-white flex flex-col justify-between">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-sm font-bold text-slate-900 font-mono uppercase tracking-wider">
                60-Second Ingress Rate (PPS)
              </h3>
              <p className="text-xs text-slate-500 font-mono">Real packet rate captured every second</p>
            </div>
            <span className="text-xs font-mono font-bold text-blue-700 bg-blue-50 px-2.5 py-1 rounded-lg border border-blue-200">
              {currentPps} pps
            </span>
          </div>

          <div className="h-64 w-full relative">
            {!hasTrafficData && (
              <div className="absolute inset-0 flex flex-col items-center justify-center bg-slate-50/80 rounded-xl border border-dashed border-slate-200 z-10 p-4">
                <Radio className="w-6 h-6 text-slate-400 mb-2" />
                <span className="text-xs font-bold text-slate-700 font-mono">Awaiting Live Network Traffic</span>
                <span className="text-[11px] text-slate-500 font-mono text-center mt-0.5">
                  Send traffic or use Live Fire Test to generate real packet ingress.
                </span>
              </div>
            )}
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={rollingStats}>
                <defs>
                  <linearGradient id="ppsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#2563eb" stopOpacity={0.25} />
                    <stop offset="95%" stopColor="#2563eb" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis stroke="#94a3b8" tick={{ fontSize: 10, fill: '#64748b' }} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc', fontSize: '11px' }}
                />
                <Area type="monotone" dataKey="pps" stroke="#2563eb" strokeWidth={2} fillOpacity={1} fill="url(#ppsGradient)" name="PPS" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Live Protocol Breakdown Donut Chart */}
        <div className="soc-card rounded-2xl p-5 bg-white flex flex-col justify-between">
          <div className="mb-4 pb-3 border-b border-slate-100">
            <h3 className="text-sm font-bold text-slate-900 font-mono uppercase tracking-wider">
              Protocol Breakdown
            </h3>
            <p className="text-xs text-slate-500 font-mono">Distribution from live stream</p>
          </div>

          <div className="h-64 flex flex-col items-center justify-center relative">
            {protocolData.length === 0 ? (
              <div className="text-center text-xs text-slate-400 font-mono py-12">
                No packet protocol events recorded yet.
              </div>
            ) : (
              <>
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie
                      data={protocolData}
                      cx="50%"
                      cy="50%"
                      innerRadius={55}
                      outerRadius={80}
                      paddingAngle={4}
                      dataKey="value"
                    >
                      {protocolData.map((entry, index) => (
                        <Cell key={`cell-${index}`} fill={entry.color} />
                      ))}
                    </Pie>
                    <Tooltip
                      contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc', fontSize: '11px' }}
                    />
                  </PieChart>
                </ResponsiveContainer>
                <div className="flex flex-wrap items-center justify-center gap-2.5 mt-2 text-[11px] font-mono text-slate-600">
                  {protocolData.map((item) => (
                    <div key={item.name} className="flex items-center gap-1.5">
                      <span className="w-2.5 h-2.5 rounded-full" style={{ backgroundColor: item.color }}></span>
                      <span className="font-semibold text-slate-800">{item.name}:</span>
                      <span>{item.value}</span>
                    </div>
                  ))}
                </div>
              </>
            )}
          </div>
        </div>
      </div>

      {/* 4. Throughput & Compact Detections Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Real Inbound vs Outbound Throughput (Mbps) */}
        <div className="lg:col-span-2 soc-card rounded-2xl p-5 bg-white">
          <div className="flex items-center justify-between mb-4 pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-sm font-bold text-slate-900 font-mono uppercase tracking-wider">
                Throughput Utilization (Mbps)
              </h3>
              <p className="text-xs text-slate-500 font-mono">Calculated from actual packet payload sizes</p>
            </div>
          </div>
          <div className="h-60 w-full">
            <ResponsiveContainer width="100%" height="100%">
              <LineChart data={rollingStats}>
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="time" stroke="#94a3b8" tick={{ fontSize: 10, fill: '#64748b' }} />
                <YAxis stroke="#94a3b8" tick={{ fontSize: 10, fill: '#64748b' }} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', borderColor: '#334155', borderRadius: '8px', color: '#f8fafc', fontSize: '11px' }}
                />
                <Line type="monotone" dataKey="inboundMbps" stroke="#059669" strokeWidth={2} dot={false} name="Inbound (Mbps)" />
                <Line type="monotone" dataKey="outboundMbps" stroke="#4f46e5" strokeWidth={2} dot={false} name="Outbound (Mbps)" />
              </LineChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Compact "Latest Detections" Panel */}
        <div className="soc-card rounded-2xl p-5 bg-white flex flex-col justify-between">
          <div className="mb-3 pb-3 border-b border-slate-100 flex items-center justify-between">
            <h3 className="text-sm font-bold text-slate-900 font-mono uppercase tracking-wider flex items-center gap-1.5">
              <ShieldAlert className="w-4 h-4 text-rose-600" />
              Latest Detections
            </h3>
            <span className="text-xs font-mono text-slate-500">{threats.length} total</span>
          </div>

          <div className="space-y-2 overflow-y-auto max-h-56 pr-1">
            {threats.length > 0 ? (
              threats.slice(0, 4).map((t) => (
                <div
                  key={t.id || `${t.src_ip}-${t.timestamp}`}
                  className="p-2.5 rounded-xl border border-rose-100 bg-rose-50/50 text-xs font-mono flex items-center justify-between gap-2"
                >
                  <div className="min-w-0 flex-1">
                    <div className="font-bold text-rose-900 truncate">
                      {t.threat_type || 'Malicious Attack Match'}
                    </div>
                    <div className="text-[11px] text-slate-600 truncate mt-0.5">
                      {t.src_ip} &rarr; {t.dst_ip}:{t.dst_port || 'n/a'}
                    </div>
                  </div>
                  <button
                    onClick={() => onInvestigatePacket(t.packet || t)}
                    className="px-2 py-1 rounded bg-white hover:bg-rose-100 border border-rose-200 text-[10px] font-bold text-rose-700 transition-colors shrink-0"
                  >
                    Inspect
                  </button>
                </div>
              ))
            ) : (
              <div className="py-8 text-center text-xs text-slate-400 font-mono">
                Zero threat signature matches recorded.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* 5. Live Packet Activity Table */}
      <div className="soc-card rounded-2xl p-5 bg-white space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 pb-3 border-b border-slate-100">
          <div>
            <h3 className="text-sm font-bold text-slate-900 font-mono uppercase tracking-wider flex items-center gap-2">
              <Radio className={`w-4 h-4 ${isPaused ? 'text-slate-400' : 'text-blue-600'}`} />
              Live Ingress Packet Buffer ({displayedPackets.length})
            </h3>
            <p className="text-xs text-slate-500 font-mono">Real-time NIC packet dissection queue</p>
          </div>

          <div className="flex items-center gap-2 flex-wrap text-xs font-mono">
            {/* Filter Protocol Chips */}
            <div className="flex items-center bg-slate-100 p-1 rounded-lg border border-slate-200">
              {['ALL', 'TCP', 'UDP', 'HTTP', 'HTTPS', 'DNS'].map((proto) => (
                <button
                  key={proto}
                  onClick={() => setActiveProtoFilter(proto)}
                  className={`px-2 py-1 rounded text-[10px] font-bold transition-all ${
                    activeProtoFilter === proto
                      ? 'bg-white text-blue-700 shadow-2xs border border-slate-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {proto}
                </button>
              ))}
            </div>

            {/* Pause / Resume Controls */}
            <button
              onClick={() => setIsPaused(!isPaused)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-lg font-semibold transition-all border border-slate-200"
            >
              {isPaused ? <Play className="w-3.5 h-3.5 text-emerald-600" /> : <Pause className="w-3.5 h-3.5 text-amber-600" />}
              <span>{isPaused ? 'Resume' : 'Pause Display'}</span>
            </button>
          </div>
        </div>

        {/* Packet Table */}
        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[10px]">
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Protocol</th>
                <th className="py-2.5 px-3">Source IP</th>
                <th className="py-2.5 px-3">Destination IP</th>
                <th className="py-2.5 px-3">Target Port</th>
                <th className="py-2.5 px-3">Size</th>
                <th className="py-2.5 px-3">Status</th>
                <th className="py-2.5 px-3 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {displayedPackets.length > 0 ? (
                displayedPackets.map((pkt, idx) => (
                  <tr
                    key={pkt.id || idx}
                    className={`hover:bg-slate-50 transition-colors ${
                      pkt.is_threat ? 'bg-rose-50/70 font-semibold' : ''
                    }`}
                  >
                    <td className="py-2.5 px-3 text-slate-500">
                      {pkt.timestamp ? new Date(pkt.timestamp).toLocaleTimeString() : 'Now'}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-slate-100 text-blue-700 border border-slate-200">
                        {pkt.protocol || 'TCP'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 font-bold text-blue-700">{pkt.src_ip || '127.0.0.1'}</td>
                    <td className="py-2.5 px-3 text-slate-800">{pkt.dst_ip || '127.0.0.1'}</td>
                    <td className="py-2.5 px-3 text-slate-500">{pkt.dst_port ?? 'n/a'}</td>
                    <td className="py-2.5 px-3 text-slate-500">{pkt.length || 64} B</td>
                    <td className="py-2.5 px-3">
                      {pkt.is_threat ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-100 text-rose-800 border border-rose-200">
                          {pkt.threat_type || 'THREAT'}
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200">
                          CLEAN
                        </span>
                      )}
                    </td>
                    <td className="py-2.5 px-3 text-right">
                      <button
                        onClick={() => onInvestigatePacket(pkt)}
                        className="px-2.5 py-1 rounded bg-white hover:bg-slate-100 border border-slate-200 text-[11px] font-bold text-slate-700 transition-all shadow-2xs"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              ) : (
                <tr>
                  <td colSpan={8} className="py-12 text-center text-slate-400 font-mono">
                    <div className="flex flex-col items-center justify-center gap-1.5">
                      <Radio className="w-5 h-5 text-slate-300" />
                      <span className="font-bold text-slate-600">Awaiting Ingress Packets</span>
                      <span className="text-[11px] text-slate-400">
                        Send network traffic to target server or trigger a controlled test attack.
                      </span>
                    </div>
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Controlled Live Fire Attack Test Modal */}
      {showLiveFireModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="bg-white border border-slate-200 rounded-2xl shadow-xl max-w-md w-full p-6 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <div className="flex items-center gap-2">
                <Terminal className="w-5 h-5 text-blue-600" />
                <h3 className="text-sm font-bold text-slate-900 font-mono">
                  Controlled Attack Test Harness
                </h3>
              </div>
              <button
                onClick={() => setShowLiveFireModal(false)}
                className="text-slate-400 hover:text-slate-600"
              >
                &times;
              </button>
            </div>

            <p className="text-xs text-slate-600 font-sans leading-relaxed">
              Dispatches authentic attack signature payloads through Scapy DPI to test NIDS detection and automatic kernel firewall drop rules.
            </p>

            <div className="space-y-3 font-mono text-xs">
              <button
                onClick={() => handleLiveFireTest('sqli')}
                disabled={injecting}
                className="w-full p-3 rounded-xl bg-rose-50 hover:bg-rose-100 border border-rose-200 text-rose-800 font-bold text-left transition-all flex items-center justify-between"
              >
                <div>
                  <div className="text-xs font-bold">1. Dispatch SQL Injection (SQLi)</div>
                  <div className="text-[10px] text-rose-600 font-normal">UNION SELECT payload signature</div>
                </div>
                <Zap className="w-4 h-4 text-rose-600" />
              </button>

              <button
                onClick={() => handleLiveFireTest('xss')}
                disabled={injecting}
                className="w-full p-3 rounded-xl bg-amber-50 hover:bg-amber-100 border border-amber-200 text-amber-800 font-bold text-left transition-all flex items-center justify-between"
              >
                <div>
                  <div className="text-xs font-bold">2. Dispatch Cross-Site Scripting (XSS)</div>
                  <div className="text-[10px] text-amber-600 font-normal">&lt;script&gt; payload signature</div>
                </div>
                <Zap className="w-4 h-4 text-amber-600" />
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default Dashboard;
