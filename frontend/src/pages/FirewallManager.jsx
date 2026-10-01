import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import { apiClient } from '../api/client';
import {
  Flame,
  ShieldCheck,
  ShieldAlert,
  PlusCircle,
  Trash2,
  RefreshCw,
  Cpu,
  CheckCircle2,
  Clock,
  UserCheck,
  AlertTriangle
} from 'lucide-react';

const FirewallManager = () => {
  const { role, isEmployee } = useAuth();
  const { status, blockIp, unblockIp, refreshPersistedData } = useSOC();

  const [rules, setRules] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [ipAddress, setIpAddress] = useState('');
  const [reason, setReason] = useState('Manual Administrative Isolation');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [feedback, setFeedback] = useState(null);
  const [confirmIpToUnblock, setConfirmIpToUnblock] = useState(null);

  // Fetch firewall rules from GET /api/firewall/rules
  const fetchRules = async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getFirewallRules();
      setRules(data || []);
    } catch (err) {
      setFeedback({ success: false, message: 'Failed to fetch active firewall rules.' });
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchRules();
  }, []);

  // Submit Manual Block
  const handleEnforceBlock = async (e) => {
    e.preventDefault();
    if (!ipAddress.trim() || isEmployee || isSubmitting) return;

    setIsSubmitting(true);
    setFeedback(null);
    try {
      const result = await blockIp(ipAddress.trim(), reason.trim());
      setFeedback({
        success: true,
        message: result.message || `Drop rule enforced against ${ipAddress}. OS Kernel updated.`
      });
      setIpAddress('');
      fetchRules();
    } catch (err) {
      setFeedback({
        success: false,
        message: err.message || 'Failed to enforce firewall rule.'
      });
    } finally {
      setIsSubmitting(false);
    }
  };

  // Unblock Confirmation Trigger
  const handleUnblockConfirm = async () => {
    if (!confirmIpToUnblock || isEmployee) return;
    const targetIp = confirmIpToUnblock;
    setConfirmIpToUnblock(null);
    setFeedback(null);

    try {
      const result = await unblockIp(targetIp);
      setFeedback({
        success: true,
        message: result.message || `Drop rule revoked for ${targetIp}. Traffic restored.`
      });
      fetchRules();
    } catch (err) {
      setFeedback({
        success: false,
        message: err.message || 'Failed to revoke firewall rule.'
      });
    }
  };

  const activeRulesCount = rules.filter((r) => r.is_active !== false).length;

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div>
          <h1 className="text-base font-bold text-slate-900 font-sans flex items-center gap-2">
            <Flame className="w-5 h-5 text-rose-600" />
            Active Host Firewall &amp; Access Control Ledger
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Kernel Packet Filtering &bull; Platform: {status?.firewall_platform || 'Windows WFP / Linux netsh'}
          </p>
        </div>

        <button
          onClick={fetchRules}
          className="px-3 py-1.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-mono font-semibold transition-all flex items-center gap-1.5 self-start sm:self-auto shadow-2xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-blue-600 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Sync Kernel Rules</span>
        </button>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Kernel Hook Platform</span>
            <Cpu className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-base font-bold font-mono text-slate-900">
            {status?.firewall_driver || 'Windows Filtering Platform (WFP)'}
          </div>
          <div className="text-xs text-slate-500 font-mono mt-1">
            Platform: {status?.firewall_platform || 'OS Host Kernel'}
          </div>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Enforced Drop Rules</span>
            <Flame className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-rose-600">
            {activeRulesCount}
          </div>
          <div className="text-xs text-slate-500 font-mono mt-1">
            Active drop entries in OS firewall
          </div>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Privilege Authority</span>
            <UserCheck className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-base font-bold font-mono text-emerald-700 uppercase">
            {role || 'Operator'} Authorized
          </div>
          <div className="text-xs text-slate-500 font-mono mt-1">
            Elevated subprocess command execution
          </div>
        </div>
      </div>

      {/* Feedback Alert */}
      {feedback && (
        <div
          className={`p-3 rounded-xl border text-xs font-mono flex items-center justify-between ${
            feedback.success
              ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
              : 'bg-rose-50 border-rose-200 text-rose-700'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedback.success ? <CheckCircle2 className="w-4 h-4 text-emerald-600" /> : <AlertTriangle className="w-4 h-4 text-rose-600" />}
            <span>{feedback.message}</span>
          </div>
          <button onClick={() => setFeedback(null)} className="text-slate-400 hover:text-slate-600">
            Dismiss
          </button>
        </div>
      )}

      {/* Manual Rule Enforcement Form */}
      {!isEmployee && (
        <div className="soc-card rounded-2xl p-6 bg-white border border-slate-200">
          <h3 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono mb-4 flex items-center gap-2">
            <PlusCircle className="w-4 h-4 text-blue-600" />
            Manual Kernel Drop Rule Enforcement
          </h3>
          <form onSubmit={handleEnforceBlock} className="grid grid-cols-1 md:grid-cols-12 gap-4">
            <div className="md:col-span-4">
              <label className="block text-[10px] font-mono text-slate-600 uppercase mb-1 font-bold">
                Target IP Address (v4) *
              </label>
              <input
                type="text"
                placeholder="e.g. 198.51.100.44"
                value={ipAddress}
                onChange={(e) => setIpAddress(e.target.value)}
                required
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600"
              />
            </div>

            <div className="md:col-span-5">
              <label className="block text-[10px] font-mono text-slate-600 uppercase mb-1 font-bold">
                Threat Rationale / Signature *
              </label>
              <input
                type="text"
                placeholder="e.g. Malicious SQL Injection Payload Source"
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                required
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600"
              />
            </div>

            <div className="md:col-span-3 flex items-end">
              <button
                type="submit"
                disabled={isSubmitting}
                className="w-full py-2 px-4 bg-rose-600 hover:bg-rose-500 text-white rounded-xl text-xs font-mono font-bold transition-all shadow-2xs disabled:opacity-50 flex items-center justify-center gap-2"
              >
                <Flame className="w-4 h-4" />
                <span>{isSubmitting ? 'Enforcing...' : 'Enforce Drop Policy'}</span>
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Rules Table */}
      <div className="soc-card rounded-2xl overflow-hidden bg-white border border-slate-200">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/60">
          <h3 className="text-xs font-bold text-slate-900 uppercase font-mono">
            Active Ingress Drop Ledger
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            Total Entries: {rules.length} ({activeRulesCount} Active)
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[10px]">
                <th className="py-2.5 px-4">Rule #</th>
                <th className="py-2.5 px-4">Target IP</th>
                <th className="py-2.5 px-4">Threat Rationale</th>
                <th className="py-2.5 px-4">Enforcing Authority</th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Status</th>
                <th className="py-2.5 px-4 text-right">Action</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {rules.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-12 text-center text-slate-400 font-mono">
                    No active drop rules recorded in OS firewall.
                  </td>
                </tr>
              ) : (
                rules.map((rule) => (
                  <tr
                    key={rule.id}
                    className={`hover:bg-slate-50 transition-colors ${
                      !rule.is_active ? 'opacity-50' : ''
                    }`}
                  >
                    <td className="py-3 px-4 text-slate-400">#{rule.id}</td>
                    <td className="py-3 px-4 font-bold text-rose-600">
                      {rule.ip_address}
                    </td>
                    <td className="py-3 px-4 text-slate-800">{rule.reason}</td>
                    <td className="py-3 px-4">
                      <span
                        className={`px-2 py-0.5 rounded text-[10px] font-semibold border ${
                          (rule.blocked_by || '').includes('AUTOMATED')
                            ? 'bg-purple-50 text-purple-700 border-purple-200'
                            : 'bg-blue-50 text-blue-700 border-blue-200'
                        }`}
                      >
                        {rule.blocked_by || 'MANUAL'}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-500">
                      {rule.timestamp ? new Date(rule.timestamp).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4">
                      {rule.is_active !== false ? (
                        <span className="px-2 py-0.5 rounded text-[10px] font-bold bg-rose-50 text-rose-700 border border-rose-200">
                          ACTIVE DROP
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] font-semibold bg-slate-100 text-slate-500">
                          REVOKED
                        </span>
                      )}
                    </td>
                    <td className="py-3 px-4 text-right">
                      {!isEmployee && rule.is_active !== false && (
                        <button
                          onClick={() => setConfirmIpToUnblock(rule.ip_address)}
                          className="px-2.5 py-1 text-[11px] font-mono font-bold rounded bg-white hover:bg-rose-50 text-rose-600 border border-slate-200 transition-all shadow-2xs"
                        >
                          Revoke Drop
                        </button>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Unblock Confirmation Modal */}
      {confirmIpToUnblock && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs">
          <div className="bg-white border border-slate-200 rounded-2xl shadow-xl max-w-sm w-full p-6 space-y-4">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-amber-50 border border-amber-200 text-amber-600">
                <AlertTriangle className="w-5 h-5" />
              </div>
              <div>
                <h4 className="text-sm font-bold text-slate-900 font-mono">
                  Confirm Firewall Rule Revocation
                </h4>
                <p className="text-xs text-slate-500 font-mono mt-0.5">
                  Revoke kernel drop rule for <span className="font-bold text-rose-600">{confirmIpToUnblock}</span>?
                </p>
              </div>
            </div>

            <div className="flex justify-end gap-2 pt-2">
              <button
                onClick={() => setConfirmIpToUnblock(null)}
                className="px-3 py-1.5 rounded-xl text-xs font-semibold text-slate-600 hover:bg-slate-100"
              >
                Cancel
              </button>
              <button
                onClick={handleUnblockConfirm}
                className="px-4 py-1.5 rounded-xl text-xs font-bold text-white bg-rose-600 hover:bg-rose-500 shadow-2xs"
              >
                Revoke Rule
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default FirewallManager;
