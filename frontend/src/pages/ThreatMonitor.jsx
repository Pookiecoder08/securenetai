import React, { useState, useEffect, useMemo, useCallback } from 'react';
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
  Loader2,
  ShieldCheck
} from 'lucide-react';
import { apiClient } from '../api/client';

const ThreatMonitor = () => {
  const { isEmployee } = useAuth();
  const { threats, resolveThreat, firewallRules } = useSOC();

  const [dbThreats, setDbThreats] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedPacket, setSelectedPacket] = useState(null);
  const [activeTab, setActiveTab] = useState('ACTION REQUIRED');
  const [searchTerm, setSearchTerm] = useState('');
  const [actionFeedback, setActionFeedback] = useState(null);
  const [resolvingId, setResolvingId] = useState(null);

  // Set of actively blocked IPs from firewall rules
  const activeBlockedIpSet = useMemo(() => {
    const set = new Set();
    (firewallRules || []).forEach((r) => {
      if (r.is_active && r.ip_address) set.add(r.ip_address);
    });
    return set;
  }, [firewallRules]);

  // Evaluates whether a threat is eligible for silent automatic blocking or is already restricted
  const canBeAutoBlocked = useCallback((t) => {
    if (!t) return false;
    if (t.auto_blocked || t.can_be_autoblocked) return true;
    if (['EXECUTED', 'AUTO_BLOCKED', 'MITIGATED', 'RESOLVED', 'ALREADY_RESTRICTED'].includes(t.response_status || t.status)) return true;
    const sev = (t.severity || '').toLowerCase();
    if (sev === 'low' || sev === 'medium') return true;
    if (t.risk_score !== undefined && t.risk_score !== null && t.risk_score < 65) return true;
    if (t.src_ip && activeBlockedIpSet.has(t.src_ip)) return true;
    return false;
  }, [activeBlockedIpSet]);

  // Fetch persisted threats from GET /api/threats
  const loadThreats = async (showSpinner = true) => {
    if (showSpinner) setIsLoading(true);
    try {
      // By default fetch only actionable threats
      const data = await apiClient.getThreats(100, false);
      setDbThreats(data || []);
    } catch (err) {
      console.error('Error fetching threats:', err);
    } finally {
      if (showSpinner) setIsLoading(false);
    }
  };

  useEffect(() => {
    loadThreats(true);
  }, []);

  // Merge live WS threats with persisted threats (deduplicated)
  const allCombinedThreats = useMemo(() => {
    const map = new Map();
    dbThreats.forEach((t) => map.set(t.id || `${t.src_ip}-${t.timestamp}`, t));
    threats.forEach((t) => map.set(t.id || `${t.src_ip}-${t.timestamp}`, t));
    return Array.from(map.values()).sort(
      (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
    );
  }, [dbThreats, threats]);

  // Active threats requiring operator review (user requirement: auto-blocked threats are omitted)
  const activeThreats = useMemo(() => {
    return allCombinedThreats.filter((t) => !canBeAutoBlocked(t));
  }, [allCombinedThreats, canBeAutoBlocked]);

  // Auto-blocked / mitigated threats ledger
  const autoBlockedThreats = useMemo(() => {
    return allCombinedThreats.filter((t) => canBeAutoBlocked(t));
  }, [allCombinedThreats, canBeAutoBlocked]);

  // Filtered view based on tab selection
  const filteredThreats = useMemo(() => {
    let list = activeThreats;
    if (activeTab === 'AUTO-BLOCKED / MITIGATED') {
      list = autoBlockedThreats;
    }

    return list.filter((t) => {
      const sev = (t.severity || 'Medium').toUpperCase();
      if (activeTab === 'CRITICAL' && sev !== 'CRITICAL') return false;
      if (activeTab === 'HIGH' && sev !== 'HIGH') return false;
      if (searchTerm) {
        const q = searchTerm.toLowerCase();
        return (
          (t.src_ip || '').toLowerCase().includes(q) ||
          (t.dst_ip || '').toLowerCase().includes(q) ||
          (t.threat_type || '').toLowerCase().includes(q) ||
          (t.attack_category || '').toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [activeThreats, autoBlockedThreats, activeTab, searchTerm]);

  // Handle Threat Resolution & Block (High Performance, Instant UI Update)
  const handleResolveThreat = async (threat) => {
    if (isEmployee || !threat.src_ip) return;
    const threatKey = threat.id || `${threat.src_ip}-${threat.timestamp}`;
    // 1. Instant optimistic feedback notification (0ms delay)
    setActionFeedback({
      success: true,
      message: `Drop rule enforced against ${threat.src_ip}. Threat mitigated.`
    });

    // 2. Instant optimistic local removal from UI
    setDbThreats((prev) =>
      prev.filter((t) => (t.id || `${t.src_ip}-${t.timestamp}`) !== threatKey && t.src_ip !== threat.src_ip)
    );

    try {
      // 3. Enforce active kernel drop via resolveThreat
      await resolveThreat(threat);
      loadThreats(false);
    } catch (err) {
      setActionFeedback({
        success: false,
        message: err.message || 'Failed to enforce block.'
      });
      loadThreats(false);
    } finally {
      setResolvingId(null);
    }
  };

  const actionableCount = activeThreats.length;
  const criticalCount = activeThreats.filter((t) => (t.severity || '').toLowerCase() === 'critical').length;
  const autoBlockedCount = autoBlockedThreats.length;

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Action Feedback Notification */}
      {actionFeedback && (
        <div
          className={`p-3 rounded-xl border text-xs font-mono flex items-center justify-between gap-2 animate-in fade-in ${
            actionFeedback.success
              ? 'bg-emerald-50 border-emerald-200 text-emerald-800'
              : 'bg-rose-50 border-rose-200 text-rose-800'
          }`}
        >
          <div className="flex items-center gap-2">
            {actionFeedback.success ? (
              <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
            ) : (
              <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
            )}
            <span>{actionFeedback.message}</span>
          </div>
          <button
            onClick={() => setActionFeedback(null)}
            className="text-slate-400 hover:text-slate-600 text-xs px-2 py-0.5"
          >
            ×
          </button>
        </div>
      )}

      {/* Threat Summary Stats Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Action Required</span>
            <ShieldAlert className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-rose-600">
            {actionableCount}
          </div>
          <p className="text-[11px] text-slate-400 font-sans mt-1">
            High &amp; Critical threats requiring analyst approval
          </p>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Critical Severity</span>
            <AlertTriangle className="w-4 h-4 text-amber-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-amber-600">
            {criticalCount}
          </div>
          <p className="text-[11px] text-slate-400 font-sans mt-1">
            Zero-tolerance exploits (SQLi, Remote Code Execution)
          </p>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Auto-Mitigated by NIPS</span>
            <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-emerald-600">
            {autoBlockedCount}
          </div>
          <p className="text-[11px] text-slate-400 font-sans mt-1">
            Minor intrusions auto-blocked silently without disturbing admin
          </p>
        </div>
      </div>

      {/* Filter and Search Bar */}
      <div className="soc-card rounded-2xl p-3 bg-white flex flex-wrap items-center justify-between gap-3 border border-slate-200">
        <div className="flex items-center gap-1.5 text-xs font-mono flex-wrap">
          {['ACTION REQUIRED', 'CRITICAL', 'HIGH', 'AUTO-BLOCKED / MITIGATED'].map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-3 py-1.5 rounded-lg font-bold transition-all text-xs ${
                activeTab === tab
                  ? tab === 'AUTO-BLOCKED / MITIGATED'
                    ? 'bg-emerald-50 text-emerald-700 border border-emerald-200'
                    : 'bg-blue-50 text-blue-700 border border-blue-200'
                  : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
              }`}
            >
              {tab === 'AUTO-BLOCKED / MITIGATED' ? `Auto-Mitigated (${autoBlockedCount})` : tab}
            </button>
          ))}
        </div>

        <div className="flex items-center gap-2 w-full sm:w-auto">
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
          <button
            onClick={() => loadThreats(true)}
            className="p-1.5 rounded-xl border border-slate-200 hover:bg-slate-50 text-slate-500 hover:text-slate-900 transition-colors shrink-0"
            title="Refresh Threats"
          >
            <RefreshCw className="w-3.5 h-3.5" />
          </button>
        </div>
      </div>

      {/* Incident Ledger Table */}
      <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
        <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-3">
          <div className="flex items-center gap-2">
            <ShieldAlert className="w-4 h-4 text-rose-600" />
            <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono">
              {activeTab === 'AUTO-BLOCKED / MITIGATED'
                ? `Auto-Mitigated Threats Ledger (${filteredThreats.length})`
                : `Active Threats Requiring Resolution (${filteredThreats.length})`}
            </h3>
          </div>
          <span className="text-[11px] text-slate-400 font-mono">
            {activeTab === 'AUTO-BLOCKED / MITIGATED'
              ? 'Handled automatically by background NIPS policy'
              : 'Requires Operator Discretion & Drop Enforcement'}
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead>
              <tr className="border-b border-slate-200 text-slate-400">
                <th className="py-2.5 px-3 font-semibold">Timestamp</th>
                <th className="py-2.5 px-3 font-semibold">Attacker IP</th>
                <th className="py-2.5 px-3 font-semibold">Target Port</th>
                <th className="py-2.5 px-3 font-semibold">Signature / Category</th>
                <th className="py-2.5 px-3 font-semibold">Severity</th>
                <th className="py-2.5 px-3 font-semibold">Risk Score</th>
                <th className="py-2.5 px-3 font-semibold text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100">
              {isLoading ? (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-400 font-mono">
                    <Loader2 className="w-5 h-5 animate-spin mx-auto mb-2 text-blue-600" />
                    Synchronizing threat ledger...
                  </td>
                </tr>
              ) : filteredThreats.length === 0 ? (
                <tr>
                  <td colSpan="7" className="py-12 text-center text-slate-400 font-mono">
                    <CheckCircle2 className="w-6 h-6 mx-auto mb-2 text-emerald-500" />
                    {activeTab === 'AUTO-BLOCKED / MITIGATED'
                      ? 'No auto-mitigated threats in recent capture session.'
                      : 'No active threats requiring manual action. Network perimeter secure.'}
                  </td>
                </tr>
              ) : (
                filteredThreats.map((threat) => {
                  const threatKey = threat.id || `${threat.src_ip}-${threat.timestamp}`;
                  const isAutoMitigated = canBeAutoBlocked(threat);
                  const isResolvingThis = resolvingId === threatKey;

                  return (
                    <tr key={threatKey} className="hover:bg-slate-50/80 transition-colors">
                      <td className="py-2.5 px-3 text-slate-500 whitespace-nowrap">
                        {threat.timestamp ? new Date(threat.timestamp).toLocaleTimeString() : 'Recent'}
                      </td>
                      <td className="py-2.5 px-3 font-bold text-slate-900 whitespace-nowrap">
                        {threat.src_ip || 'Unknown IP'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-600">
                        {threat.dst_port || '8000'}
                      </td>
                      <td className="py-2.5 px-3 text-slate-800 max-w-xs truncate" title={threat.threat_type || threat.attack_category}>
                        {threat.threat_type || threat.attack_category || 'Exploit Signature Match'}
                      </td>
                      <td className="py-2.5 px-3">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                            (threat.severity || '').toLowerCase() === 'critical'
                              ? 'bg-rose-50 text-rose-700 border-rose-200'
                              : (threat.severity || '').toLowerCase() === 'high'
                              ? 'bg-amber-50 text-amber-700 border-amber-200'
                              : 'bg-blue-50 text-blue-700 border-blue-200'
                          }`}
                        >
                          {(threat.severity || 'Medium').toUpperCase()}
                        </span>
                      </td>
                      <td className="py-2.5 px-3">
                        {threat.risk_score !== undefined && threat.risk_score !== null ? (
                          <span
                            className={`px-2 py-0.5 rounded text-[10px] font-bold border ${
                              threat.risk_score >= 80
                                ? 'bg-rose-50 text-rose-700 border-rose-200'
                                : threat.risk_score >= 50
                                ? 'bg-amber-50 text-amber-700 border-amber-200'
                                : 'bg-blue-50 text-blue-700 border-blue-200'
                            }`}
                          >
                            {threat.risk_score}/100
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                            85/100 (High)
                          </span>
                        )}
                      </td>
                      <td className="py-2.5 px-3 text-right space-x-2 whitespace-nowrap">
                        {!isEmployee && threat.src_ip && !isAutoMitigated && (
                          <button
                            onClick={() => handleResolveThreat(threat)}
                            disabled={isResolvingThis}
                            className="px-2.5 py-1 rounded text-[11px] font-bold bg-rose-600 hover:bg-rose-500 disabled:opacity-60 text-white transition-all shadow-2xs inline-flex items-center gap-1.5"
                          >
                            {isResolvingThis ? (
                              <>
                                <Loader2 className="w-3.5 h-3.5 animate-spin" />
                                <span>Mitigating...</span>
                              </>
                            ) : (
                              <>
                                <ShieldAlert className="w-3.5 h-3.5" />
                                <span>Resolve &amp; Block</span>
                              </>
                            )}
                          </button>
                        )}
                        {!isEmployee && isAutoMitigated && (
                          <span className="px-2.5 py-1 rounded text-[10px] font-bold bg-emerald-50 text-emerald-700 border border-emerald-200 inline-flex items-center gap-1">
                            <ShieldCheck className="w-3 h-3 text-emerald-600" />
                            <span>Auto-Mitigated</span>
                          </span>
                        )}
                        <button
                          onClick={() => setSelectedPacket(threat.packet || threat)}
                          className="px-2.5 py-1 rounded text-[11px] font-bold bg-white hover:bg-slate-100 border border-slate-200 text-slate-700 transition-all shadow-2xs"
                        >
                          Inspect
                        </button>
                      </td>
                    </tr>
                  );
                })
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
