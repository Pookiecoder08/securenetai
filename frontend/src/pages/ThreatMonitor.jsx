import React, { useState, useEffect, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import PacketModal from '../components/PacketModal';
import {
  ShieldAlert,
  Flame,
  Zap,
  Filter,
  Search,
  CheckCircle2,
  AlertTriangle,
  Radio,
  FileCode,
  ArrowRight,
  RefreshCw,
  Loader2
} from 'lucide-react';
import { apiClient } from '../api/client';

const ThreatMonitor = () => {
  const { isEmployee } = useAuth();
  const { threats, blockIp, refreshPersistedData } = useSOC();

  const [dbThreats, setDbThreats] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [activeTab, setActiveTab] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFeedback, setActionFeedback] = useState(null);

  // Fetch persisted threats from GET /api/threats
  const loadThreats = async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getThreats(100);
      setDbThreats(data || []);
    } catch (err) {
      console.error('Error fetching threats:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadThreats();
  }, []);

  // Merge live WS threats with persisted threats (deduplicated)
  const combinedThreats = useMemo(() => {
    const map = new Map();
    dbThreats.forEach((t) => map.set(t.id || `${t.src_ip}-${t.timestamp}`, t));
    threats.forEach((t) => map.set(t.id || `${t.src_ip}-${t.timestamp}`, t));
    return Array.from(map.values()).sort(
      (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
    );
  }, [dbThreats, threats]);

  // Filtering
  const filteredThreats = useMemo(() => {
    return combinedThreats.filter((t) => {
      const type = (t.threat_type || '').toLowerCase();
      if (activeTab === 'SQLi' && !type.includes('sql')) return false;
      if (activeTab === 'XSS' && !type.includes('xss')) return false;
      if (activeTab === 'Probe' && !type.includes('probe')) return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          (t.src_ip || '').toLowerCase().includes(q) ||
          (t.dst_ip || '').toLowerCase().includes(q) ||
          type.includes(q)
        );
      }
      return true;
    });
  }, [combinedThreats, activeTab, searchTerm]);

  // Handle Threat Resolution & Block
  const handleResolveThreat = async (threat) => {
    if (isEmployee || !threat.src_ip) return;
    setActionFeedback(null);
    try {
      await blockIp(threat.src_ip, threat.threat_type || 'Threat Monitor Mitigation');
      setActionFeedback({ success: true, message: `Drop rule enforced against ${threat.src_ip}. Threat mitigated.` });
      loadThreats();
    } catch (err) {
      setActionFeedback({ success: false, message: err.message || 'Failed to enforce block.' });
    }
  };

  const sqliCount = combinedThreats.filter((t) => (t.threat_type || '').toLowerCase().includes('sql')).length;
  const xssCount = combinedThreats.filter((t) => (t.threat_type || '').toLowerCase().includes('xss')).length;
  const probeCount = combinedThreats.filter((t) => (t.threat_type || '').toLowerCase().includes('probe')).length;

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div>
          <h1 className="text-base font-bold text-slate-900 font-sans flex items-center gap-2">
            <ShieldAlert className="w-5 h-5 text-rose-600" />
            Threat Signature &amp; Intrusion Monitor
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Real-Time Attack Interception &bull; Persistent SQLite Threat Audit Ledger
          </p>
        </div>

        <button
          onClick={loadThreats}
          className="px-3 py-1.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-mono font-semibold transition-all flex items-center gap-1.5 self-start sm:self-auto shadow-2xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-blue-600 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Refresh Ledger</span>
        </button>
      </div>

      {/* Action Feedback */}
      {actionFeedback && (
        <div
          className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
            actionFeedback.success
              ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
              : 'bg-rose-50 border-rose-200 text-rose-700'
          }`}
        >
          {actionFeedback.success ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <AlertTriangle className="w-4 h-4 text-rose-600" />}
          <span>{actionFeedback.message}</span>
        </div>
      )}

      {/* Threat Summary Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="soc-card rounded-2xl p-5 bg-white border-l-4 border-l-rose-500">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
            SQL Injection (SQLi)
          </span>
          <div className="text-2xl font-extrabold font-mono text-rose-600 mt-2">
            {sqliCount}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">UNION / SELECT / Auth bypass signatures</p>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border-l-4 border-l-amber-500">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
            XSS Injections
          </span>
          <div className="text-2xl font-extrabold font-mono text-amber-600 mt-2">
            {xssCount}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Script tags / Event handler payloads</p>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border-l-4 border-l-blue-500">
          <span className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono">
            Recon Probes
          </span>
          <div className="text-2xl font-extrabold font-mono text-blue-600 mt-2">
            {probeCount}
          </div>
          <p className="text-[11px] text-slate-500 font-mono mt-1">Sensitive port sweeps</p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card rounded-2xl p-3 bg-white flex flex-wrap items-center justify-between gap-3 border border-slate-200">
        <div className="flex items-center gap-1 text-xs font-mono">
          {['ALL', 'SQLi', 'XSS', 'Probe'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
                activeTab === tab
                  ? 'bg-blue-50 text-blue-700 border border-blue-200'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {tab}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Filter IP or Signature..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-600"
          />
        </div>
      </div>

      {/* Incident Ledger Table */}
      <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-3">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono">
            Intercepted Threat Events ({filteredThreats.length})
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            Source: SQLite Packet Ledger
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[10px]">
                <th className="py-2.5 px-3">Event ID</th>
                <th className="py-2.5 px-3">Timestamp</th>
                <th className="py-2.5 px-3">Attacker IP</th>
                <th className="py-2.5 px-3">Target IP:Port</th>
                <th className="py-2.5 px-3">Signature Description</th>
                <th className="py-2.5 px-3">Severity</th>
                <th className="py-2.5 px-3 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 font-mono">
                    No threat signature records found matching filter.
                  </td>
                </tr>
              ) : (
                filteredThreats.map((threat) => (
                  <tr key={threat.id || `${threat.src_ip}-${threat.timestamp}`} className="hover:bg-slate-50 transition-colors">
                    <td className="py-2.5 px-3 font-bold text-slate-400">#{threat.id || 'N/A'}</td>
                    <td className="py-2.5 px-3 text-slate-500">
                      {threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : 'Now'}
                    </td>
                    <td className="py-2.5 px-3 font-bold text-rose-600">{threat.src_ip}</td>
                    <td className="py-2.5 px-3 text-slate-800">
                      {threat.dst_ip}:{threat.dst_port || 'n/a'}
                    </td>
                    <td className="py-2.5 px-3 font-semibold text-slate-900">
                      {threat.threat_type || 'Malicious Payload Match'}
                    </td>
                    <td className="py-2.5 px-3">
                      <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-rose-100 text-rose-800 border border-rose-200">
                        {threat.severity || 'Critical'}
                      </span>
                    </td>
                    <td className="py-2.5 px-3 text-right space-x-2">
                      {!isEmployee && threat.src_ip && (
                        <button
                          onClick={() => handleResolveThreat(threat)}
                          className="px-2.5 py-1 rounded text-[11px] font-bold bg-rose-600 hover:bg-rose-500 text-white transition-all shadow-2xs"
                        >
                          Resolve &amp; Block
                        </button>
                      )}
                      <button
                        onClick={() => setSelectedPacket(threat.packet || threat)}
                        className="px-2.5 py-1 rounded text-[11px] font-bold bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 transition-all shadow-2xs"
                      >
                        Inspect
                      </button>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {selectedPacket && (
        <PacketModal
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
        />
      )}
    </div>
  );
};

export default ThreatMonitor;
