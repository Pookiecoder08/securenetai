import React, { useState, useEffect, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import { apiClient } from '../api/client';
import {
  Zap,
  Shield,
  ShieldAlert,
  ShieldCheck,
  Flame,
  CheckCircle2,
  XCircle,
  RotateCcw,
  Clock,
  AlertTriangle,
  Lock,
  Layers,
  Settings,
  RefreshCw,
  Search,
  Filter,
  Check,
  X,
  Radio,
  FileText,
  UserCheck
} from 'lucide-react';

const AutomatedResponse = () => {
  const { role, isEmployee } = useAuth();
  const {
    responseActions,
    responseConfig,
    refreshPersistedData,
    approveAction,
    rejectAction,
    rollbackAction,
    executeManualResponse,
    updateResponseConfig
  } = useSOC();

  const [actions, setActions] = useState([]);
  const [policies, setPolicies] = useState([]);
  const [auditLogs, setAuditLogs] = useState([]);
  const [config, setConfig] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [activeTab, setActiveTab] = useState('pending'); // 'pending' | 'active' | 'policies' | 'audit'
  const [feedback, setFeedback] = useState(null);

  // Manual Response Form State
  const [manualIp, setManualIp] = useState('');
  const [manualReason, setManualReason] = useState('Administrative Threat Mitigation');
  const [manualTtl, setManualTtl] = useState(3600);
  const [isSubmittingManual, setIsSubmittingManual] = useState(false);

  // Allowlist & Simulation Toggle Modal State
  const [showConfigModal, setShowConfigModal] = useState(false);
  const [allowlistInput, setAllowlistInput] = useState('');
  const [simModeInput, setSimModeInput] = useState(true);
  const [realAuthInput, setRealAuthInput] = useState(false);

  const loadData = async () => {
    setIsLoading(true);
    try {
      const [acts, pols, logs, cfg] = await Promise.allSettled([
        apiClient.getResponseActions(50),
        apiClient.getResponsePolicies(),
        apiClient.getAuditLogs(30),
        apiClient.getResponseSystemConfig()
      ]);

      if (acts.status === 'fulfilled') setActions(acts.value || []);
      if (pols.status === 'fulfilled') setPolicies(pols.value || []);
      if (logs.status === 'fulfilled') setAuditLogs(logs.value || []);
      if (cfg.status === 'fulfilled' && cfg.value) {
        setConfig(cfg.value);
        setAllowlistInput(cfg.value.allowlist_ips || '');
        setSimModeInput(cfg.value.simulation_mode);
        setRealAuthInput(cfg.value.real_enforcement_authorized);
      }
    } catch (err) {
      console.error('Error loading response center data:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadData();
  }, []);

  // Action counts
  const pendingActions = useMemo(() => actions.filter((a) => a.status === 'PENDING_APPROVAL'), [actions]);
  const activeRestrictions = useMemo(() => actions.filter((a) => ['EXECUTED', 'SIMULATED'].includes(a.status)), [actions]);
  const resolvedActions = useMemo(() => actions.filter((a) => ['REVERSED', 'EXPIRED', 'REJECTED'].includes(a.status)), [actions]);

  // Handle Approve
  const handleApprove = async (actionId) => {
    if (isEmployee) return;
    setFeedback(null);
    try {
      await approveAction(actionId);
      setFeedback({ success: true, message: `Response action #${actionId} approved and executed.` });
      loadData();
    } catch (err) {
      setFeedback({ success: false, message: err.message || 'Failed to approve action.' });
    }
  };

  // Handle Reject
  const handleReject = async (actionId) => {
    if (isEmployee) return;
    setFeedback(null);
    try {
      await rejectAction(actionId);
      setFeedback({ success: true, message: `Response action #${actionId} rejected.` });
      loadData();
    } catch (err) {
      setFeedback({ success: false, message: err.message || 'Failed to reject action.' });
    }
  };

  // Handle Rollback
  const handleRollback = async (actionId) => {
    if (isEmployee) return;
    setFeedback(null);
    try {
      await rollbackAction(actionId);
      setFeedback({ success: true, message: `Action #${actionId} reversed. Target unblocked.` });
      loadData();
    } catch (err) {
      setFeedback({ success: false, message: err.message || 'Failed to rollback action.' });
    }
  };

  // Handle Manual Response
  const handleManualSubmit = async (e) => {
    e.preventDefault();
    if (!manualIp.trim() || isEmployee || isSubmittingManual) return;
    setIsSubmittingManual(true);
    setFeedback(null);
    try {
      await executeManualResponse(manualIp.trim(), manualReason.trim(), Number(manualTtl));
      setFeedback({ success: true, message: `Manual defense command executed for ${manualIp}.` });
      setManualIp('');
      loadData();
    } catch (err) {
      setFeedback({ success: false, message: err.message || 'Failed to execute manual response.' });
    } finally {
      setIsSubmittingManual(false);
    }
  };

  // Handle Save System Config
  const handleSaveConfig = async (e) => {
    e.preventDefault();
    if (role !== 'admin') return;
    try {
      await updateResponseConfig({
        simulation_mode: String(simModeInput),
        real_enforcement_authorized: String(realAuthInput),
        allowlist_ips: allowlistInput
      });
      setFeedback({ success: true, message: 'Response policy configurations saved successfully.' });
      setShowConfigModal(false);
      loadData();
    } catch (err) {
      setFeedback({ success: false, message: err.message || 'Failed to update system config.' });
    }
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div>
          <h1 className="text-base font-bold text-slate-900 font-sans flex items-center gap-2">
            <Zap className="w-5 h-5 text-amber-500" /> Automated Response Centre
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Risk-gated defense execution, administrative approval pipelines, and OS firewall state verification.
          </p>
        </div>

        <div className="flex items-center gap-2 flex-wrap">
          {/* Mode Badge */}
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-xl border bg-slate-50 text-xs font-mono">
            <span className="text-slate-500">Mode:</span>
            {config?.simulation_mode ? (
              <span className="font-bold text-amber-700 bg-amber-100/70 px-2 py-0.5 rounded-lg border border-amber-300">
                SIMULATION (Safe)
              </span>
            ) : (
              <span className="font-bold text-rose-700 bg-rose-100 px-2 py-0.5 rounded-lg border border-rose-300 flex items-center gap-1">
                <Flame className="w-3 h-3 text-rose-600" /> REAL ENFORCEMENT
              </span>
            )}
          </div>

          {role === 'admin' && (
            <button
              onClick={() => setShowConfigModal(true)}
              className="px-3 py-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 font-mono font-semibold text-xs rounded-xl transition-all shadow-2xs flex items-center gap-1.5"
            >
              <Settings className="w-3.5 h-3.5 text-slate-500" /> Configure Engine
            </button>
          )}

          <button
            onClick={loadData}
            disabled={isLoading}
            className="p-1.5 bg-white hover:bg-slate-50 text-slate-700 border border-slate-200 rounded-xl transition-all shadow-2xs"
            title="Refresh Response Center"
          >
            <RefreshCw className={`w-4 h-4 text-slate-600 ${isLoading ? 'animate-spin' : ''}`} />
          </button>
        </div>
      </div>

      {/* Operational Feedback Toast */}
      {feedback && (
        <div
          className={`p-3.5 rounded-xl border text-xs font-mono flex items-center justify-between ${
            feedback.success ? 'bg-emerald-50 border-emerald-200 text-emerald-800' : 'bg-rose-50 border-rose-200 text-rose-800'
          }`}
        >
          <div className="flex items-center gap-2">
            {feedback.success ? <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" /> : <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />}
            <span>{feedback.message}</span>
          </div>
          <button onClick={() => setFeedback(null)} className="p-1 text-slate-400 hover:text-slate-600">
            <X className="w-3.5 h-3.5" />
          </button>
        </div>
      )}

      {/* Telemetry Metric Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 font-mono">
        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider flex items-center justify-between">
            <span>Pending Approvals</span>
            <AlertTriangle className="w-4 h-4 text-amber-500" />
          </div>
          <div className="text-2xl font-black text-slate-900">{pendingActions.length}</div>
          <div className="text-[11px] text-slate-400">Requires SOC Administrator Review</div>
        </div>

        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider flex items-center justify-between">
            <span>Active Restrictions</span>
            <ShieldCheck className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-black text-slate-900">{activeRestrictions.length}</div>
          <div className="text-[11px] text-slate-400">Enforced & temporary ACL drops</div>
        </div>

        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider flex items-center justify-between">
            <span>Active Policies</span>
            <Layers className="w-4 h-4 text-indigo-600" />
          </div>
          <div className="text-2xl font-black text-slate-900">{policies.filter((p) => p.is_enabled).length}</div>
          <div className="text-[11px] text-slate-400">Automated evaluation rules</div>
        </div>

        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs space-y-1">
          <div className="text-[11px] font-bold text-slate-500 uppercase tracking-wider flex items-center justify-between">
            <span>Firewall Platform</span>
            <Flame className="w-4 h-4 text-rose-500" />
          </div>
          <div className="text-sm font-bold text-slate-900 truncate">{config?.firewall_platform || 'Windows / WFP'}</div>
          <div className="text-[10px] text-slate-400 truncate">{config?.firewall_driver || 'netsh advfirewall'}</div>
        </div>
      </div>

      {/* Manual Defense Trigger (Authorized Admin/Analyst) */}
      {!isEmployee && (
        <div className="soc-card rounded-2xl p-4 bg-white border border-slate-200 shadow-2xs">
          <h2 className="text-xs font-bold text-slate-800 uppercase tracking-wider font-mono mb-3 flex items-center gap-1.5">
            <Lock className="w-3.5 h-3.5 text-blue-600" /> Authorized Manual Response Enforcement
          </h2>
          <form onSubmit={handleManualSubmit} className="grid grid-cols-1 sm:grid-cols-4 gap-3 items-end font-mono">
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">Target IP Address</label>
              <input
                type="text"
                placeholder="e.g. 10.82.132.150"
                value={manualIp}
                onChange={(e) => setManualIp(e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono focus:bg-white focus:outline-blue-500"
                required
              />
            </div>
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">Mitigation Reason</label>
              <input
                type="text"
                placeholder="Manual operator containment"
                value={manualReason}
                onChange={(e) => setManualReason(e.target.value)}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono focus:bg-white focus:outline-blue-500"
                required
              />
            </div>
            <div>
              <label className="block text-[11px] font-semibold text-slate-600 mb-1">Restriction Duration (TTL)</label>
              <select
                value={manualTtl}
                onChange={(e) => setManualTtl(Number(e.target.value))}
                className="w-full px-3 py-2 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono focus:bg-white focus:outline-blue-500"
              >
                <option value={1800}>30 Minutes (1,800s)</option>
                <option value={3600}>1 Hour (3,600s)</option>
                <option value={21600}>6 Hours (21,600s)</option>
                <option value={86400}>24 Hours (86,400s)</option>
                <option value={0}>Permanent Drop (0s TTL)</option>
              </select>
            </div>
            <div>
              <button
                type="submit"
                disabled={isSubmittingManual || !manualIp.trim()}
                className="w-full py-2 bg-rose-600 hover:bg-rose-700 text-white font-bold text-xs rounded-xl transition-all shadow-2xs flex items-center justify-center gap-1.5 disabled:opacity-50"
              >
                <Flame className="w-3.5 h-3.5" /> Enforce Isolation
              </button>
            </div>
          </form>
        </div>
      )}

      {/* Tabs Bar */}
      <div className="flex border-b border-slate-200 gap-2 font-mono text-xs">
        <button
          onClick={() => setActiveTab('pending')}
          className={`pb-2.5 px-3 font-semibold transition-all border-b-2 flex items-center gap-1.5 ${
            activeTab === 'pending'
              ? 'border-blue-600 text-blue-700 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <span>Pending Approvals</span>
          {pendingActions.length > 0 && (
            <span className="bg-amber-100 text-amber-800 text-[10px] font-bold px-1.5 py-0.5 rounded-full border border-amber-300">
              {pendingActions.length}
            </span>
          )}
        </button>

        <button
          onClick={() => setActiveTab('active')}
          className={`pb-2.5 px-3 font-semibold transition-all border-b-2 flex items-center gap-1.5 ${
            activeTab === 'active'
              ? 'border-blue-600 text-blue-700 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <span>Active Restrictions & History</span>
          <span className="bg-slate-100 text-slate-600 text-[10px] font-bold px-1.5 py-0.5 rounded-full">
            {actions.length}
          </span>
        </button>

        <button
          onClick={() => setActiveTab('policies')}
          className={`pb-2.5 px-3 font-semibold transition-all border-b-2 flex items-center gap-1.5 ${
            activeTab === 'policies'
              ? 'border-blue-600 text-blue-700 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <span>Policy Rules ({policies.length})</span>
        </button>

        <button
          onClick={() => setActiveTab('audit')}
          className={`pb-2.5 px-3 font-semibold transition-all border-b-2 flex items-center gap-1.5 ${
            activeTab === 'audit'
              ? 'border-blue-600 text-blue-700 font-bold'
              : 'border-transparent text-slate-500 hover:text-slate-800'
          }`}
        >
          <span>Audit Ledger ({auditLogs.length})</span>
        </button>
      </div>

      {/* TAB 1: Pending Approvals */}
      {activeTab === 'pending' && (
        <div className="soc-card rounded-2xl bg-white border border-slate-200 overflow-hidden shadow-2xs font-mono">
          <div className="p-3.5 bg-slate-50/80 border-b border-slate-200 text-xs font-bold text-slate-700 flex items-center justify-between">
            <span>Actions Awaiting Administrative Approval</span>
            <span className="text-[11px] text-slate-500 font-normal">Risk policy escalation gates</span>
          </div>

          {pendingActions.length === 0 ? (
            <div className="p-12 text-center text-slate-400 space-y-2">
              <CheckCircle2 className="w-8 h-8 text-emerald-500 mx-auto" />
              <p className="text-xs font-semibold text-slate-700">No Pending Approvals Required</p>
              <p className="text-[11px] text-slate-500">All automated intrusion events have either completed or are within operational tolerance.</p>
            </div>
          ) : (
            <div className="divide-y divide-slate-100">
              {pendingActions.map((action) => (
                <div key={action.id} className="p-4 hover:bg-slate-50/70 transition-all flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
                  <div className="space-y-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-bold text-sm text-slate-900">{action.target_ip}</span>
                      <span className="px-2 py-0.5 rounded-md text-[10px] font-bold bg-amber-50 text-amber-800 border border-amber-200">
                        {action.action_type} REQUEST
                      </span>
                      <span className="text-[11px] text-slate-400">Initiated by: {action.initiated_by}</span>
                    </div>
                    <p className="text-xs text-slate-600">{action.reason}</p>
                    <div className="text-[10px] text-slate-400">
                      Triggered at: {new Date(action.created_at).toLocaleString()} • Policy: {action.policy_name}
                    </div>
                  </div>

                  {!isEmployee && (
                    <div className="flex items-center gap-2 shrink-0">
                      <button
                        onClick={() => handleApprove(action.id)}
                        className="px-3 py-1.5 bg-emerald-600 hover:bg-emerald-700 text-white font-bold text-xs rounded-xl transition-all shadow-2xs flex items-center gap-1"
                      >
                        <Check className="w-3.5 h-3.5" /> Approve & Execute
                      </button>
                      <button
                        onClick={() => handleReject(action.id)}
                        className="px-3 py-1.5 bg-white hover:bg-rose-50 text-rose-700 border border-rose-200 font-bold text-xs rounded-xl transition-all shadow-2xs flex items-center gap-1"
                      >
                        <X className="w-3.5 h-3.5" /> Reject
                      </button>
                    </div>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Active Restrictions & History */}
      {activeTab === 'active' && (
        <div className="soc-card rounded-2xl bg-white border border-slate-200 overflow-hidden shadow-2xs font-mono">
          <div className="overflow-x-auto">
            <table className="w-full text-left text-xs">
              <thead className="bg-slate-50 border-b border-slate-200 text-slate-600 uppercase text-[10px] font-bold">
                <tr>
                  <th className="p-3">ID / Target</th>
                  <th className="p-3">Action</th>
                  <th className="p-3">Status</th>
                  <th className="p-3">Mode</th>
                  <th className="p-3">Reason</th>
                  <th className="p-3">Timestamps</th>
                  <th className="p-3 text-right">Controls</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-100">
                {actions.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="p-8 text-center text-slate-400">
                      No response actions recorded.
                    </td>
                  </tr>
                ) : (
                  actions.map((act) => {
                    const isActive = ['EXECUTED', 'SIMULATED'].includes(act.status);
                    return (
                      <tr key={act.id} className="hover:bg-slate-50/60 transition-all">
                        <td className="p-3 font-bold text-slate-900">
                          #{act.id} <span className="ml-1 text-blue-700">{act.target_ip}</span>
                        </td>
                        <td className="p-3">
                          <span className="font-semibold text-slate-800">{act.action_type}</span>
                        </td>
                        <td className="p-3">
                          <span
                            className={`px-2 py-0.5 rounded-md text-[10px] font-bold border ${
                              act.status === 'EXECUTED'
                                ? 'bg-emerald-50 text-emerald-800 border-emerald-200'
                                : act.status === 'SIMULATED'
                                ? 'bg-amber-50 text-amber-800 border-amber-200'
                                : act.status === 'PENDING_APPROVAL'
                                ? 'bg-indigo-50 text-indigo-800 border-indigo-200'
                                : 'bg-slate-50 text-slate-600 border-slate-200'
                            }`}
                          >
                            {act.status}
                          </span>
                        </td>
                        <td className="p-3">
                          {act.is_simulated ? (
                            <span className="text-amber-700 font-semibold text-[11px]">Simulated</span>
                          ) : (
                            <span className="text-rose-700 font-bold text-[11px] flex items-center gap-1">
                              <Flame className="w-3 h-3" /> Real Kernel
                            </span>
                          )}
                        </td>
                        <td className="p-3 max-w-xs truncate text-slate-600" title={act.reason}>
                          {act.reason}
                        </td>
                        <td className="p-3 text-[10px] text-slate-400">
                          <div>Created: {new Date(act.created_at).toLocaleTimeString()}</div>
                          {act.expires_at && <div>Expires: {new Date(act.expires_at).toLocaleTimeString()}</div>}
                        </td>
                        <td className="p-3 text-right">
                          {isActive && !isEmployee && (
                            <button
                              onClick={() => handleRollback(act.id)}
                              className="px-2.5 py-1 bg-white hover:bg-slate-100 text-slate-700 border border-slate-200 rounded-lg text-[11px] font-bold transition-all shadow-2xs flex items-center gap-1 ml-auto"
                            >
                              <RotateCcw className="w-3 h-3 text-slate-500" /> Rollback
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* TAB 3: Policy Rules */}
      {activeTab === 'policies' && (
        <div className="soc-card rounded-2xl bg-white border border-slate-200 p-4 space-y-4 font-mono">
          <div className="flex items-center justify-between pb-3 border-b border-slate-100">
            <div>
              <h3 className="text-xs font-bold text-slate-800 uppercase tracking-wider">Automated Decision Policies</h3>
              <p className="text-[11px] text-slate-500">Thresholds governing autonomous mitigation vs analyst escalation.</p>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {policies.map((pol) => (
              <div key={pol.id} className="p-4 rounded-xl border border-slate-200 bg-slate-50/50 space-y-3">
                <div className="flex items-center justify-between">
                  <span className="font-bold text-xs text-slate-900">{pol.name}</span>
                  <span
                    className={`w-2 h-2 rounded-full ${pol.is_enabled ? 'bg-emerald-500' : 'bg-slate-300'}`}
                    title={pol.is_enabled ? 'Active Policy' : 'Disabled'}
                  ></span>
                </div>
                <p className="text-[11px] text-slate-600 line-clamp-2">{pol.description}</p>
                <div className="space-y-1 text-[11px] text-slate-500 pt-2 border-t border-slate-200/60">
                  <div>Min Risk Score: <span className="font-bold text-slate-800">{pol.min_risk_score}/100</span></div>
                  <div>Severity Gate: <span className="font-bold text-slate-800">{pol.severity_threshold}</span></div>
                  <div>Outcome Action: <span className="font-bold text-blue-700">{pol.action_type}</span></div>
                  <div>Default Duration: <span className="font-bold text-slate-800">{pol.duration_seconds}s</span></div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* TAB 4: Audit Ledger */}
      {activeTab === 'audit' && (
        <div className="soc-card rounded-2xl bg-white border border-slate-200 overflow-hidden shadow-2xs font-mono">
          <div className="p-3.5 bg-slate-50 border-b border-slate-200 text-xs font-bold text-slate-700">
            Immutable Security Audit Ledger
          </div>
          <div className="divide-y divide-slate-100 text-xs">
            {auditLogs.length === 0 ? (
              <div className="p-8 text-center text-slate-400">No audit logs recorded yet.</div>
            ) : (
              auditLogs.map((log) => (
                <div key={log.id} className="p-3 hover:bg-slate-50/50 flex items-start justify-between gap-4">
                  <div className="space-y-0.5">
                    <div className="flex items-center gap-2">
                      <span className="font-bold text-slate-900">{log.action}</span>
                      <span className="text-[10px] text-slate-400">by {log.actor}</span>
                      {log.target && <span className="text-[10px] bg-slate-100 px-1.5 py-0.5 rounded text-slate-600">{log.target}</span>}
                    </div>
                    <p className="text-[11px] text-slate-600">{log.details}</p>
                  </div>
                  <div className="text-[10px] text-slate-400 shrink-0">
                    {new Date(log.timestamp).toLocaleString()}
                  </div>
                </div>
              ))
            )}
          </div>
        </div>
      )}

      {/* Admin Engine Configuration Modal */}
      {showConfigModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/40 backdrop-blur-xs font-mono">
          <div className="bg-white rounded-2xl max-w-lg w-full border border-slate-200 shadow-xl p-5 space-y-4">
            <div className="flex items-center justify-between pb-3 border-b border-slate-100">
              <h3 className="font-bold text-sm text-slate-900 flex items-center gap-2">
                <Settings className="w-4 h-4 text-blue-600" /> Response Engine Settings
              </h3>
              <button onClick={() => setShowConfigModal(false)} className="p-1 text-slate-400 hover:text-slate-600">
                <X className="w-4 h-4" />
              </button>
            </div>

            <form onSubmit={handleSaveConfig} className="space-y-4 text-xs">
              {/* Simulation Mode Toggle */}
              <div className="p-3 rounded-xl border border-slate-200 bg-slate-50 space-y-2">
                <label className="flex items-center justify-between cursor-pointer">
                  <span className="font-bold text-slate-800">Simulation Mode</span>
                  <input
                    type="checkbox"
                    checked={simModeInput}
                    onChange={(e) => setSimModeInput(e.target.checked)}
                    className="w-4 h-4 text-blue-600 rounded"
                  />
                </label>
                <p className="text-[11px] text-slate-500">
                  When enabled, defense decisions are safely recorded in the ledger without altering kernel firewall rules.
                </p>
              </div>

              {/* Real Enforcement Authorized Toggle */}
              <div className="p-3 rounded-xl border border-rose-200 bg-rose-50/50 space-y-2">
                <label className="flex items-center justify-between cursor-pointer">
                  <span className="font-bold text-rose-800 flex items-center gap-1.5">
                    <Flame className="w-3.5 h-3.5 text-rose-600" /> Authorize Real OS Kernel Enforcement
                  </span>
                  <input
                    type="checkbox"
                    checked={realAuthInput}
                    onChange={(e) => setRealAuthInput(e.target.checked)}
                    className="w-4 h-4 text-rose-600 rounded"
                  />
                </label>
                <p className="text-[11px] text-rose-700/80">
                  CRITICAL: Allows backend to invoke platform firewall drop commands (Windows Filtering Platform / iptables).
                </p>
              </div>

              {/* Protected Infrastructure Allowlists */}
              <div className="space-y-1">
                <label className="block font-bold text-slate-700">Protected Infrastructure Allowlists</label>
                <textarea
                  rows={3}
                  value={allowlistInput}
                  onChange={(e) => setAllowlistInput(e.target.value)}
                  placeholder="127.0.0.1, 10.0.0.1, 192.168.1.1..."
                  className="w-full p-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono focus:bg-white focus:outline-blue-500"
                ></textarea>
                <p className="text-[10px] text-slate-400">Comma-separated IPv4 addresses immune to automated blocking.</p>
              </div>

              <div className="flex justify-end gap-2 pt-2 border-t border-slate-100">
                <button
                  type="button"
                  onClick={() => setShowConfigModal(false)}
                  className="px-3 py-1.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded-xl font-bold"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  className="px-4 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-xl font-bold shadow-2xs"
                >
                  Save Settings
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  );
};

export default AutomatedResponse;
