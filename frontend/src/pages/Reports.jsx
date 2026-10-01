import React, { useState, useEffect } from 'react';
import { useAuth } from '../context/AuthContext';
import { apiClient } from '../api/client';
import {
  FileSpreadsheet,
  Download,
  Calendar,
  ShieldAlert,
  ShieldCheck,
  Flame,
  Activity,
  CheckCircle2,
  FileText,
  Layers,
  RefreshCw,
  AlertTriangle
} from 'lucide-react';

const Reports = () => {
  const { role } = useAuth();
  const [timeframe, setTimeframe] = useState('daily');
  const [summary, setSummary] = useState(null);
  const [isLoading, setIsLoading] = useState(true);
  const [isDownloading, setIsDownloading] = useState(false);
  const [downloadSuccess, setDownloadSuccess] = useState(false);
  const [downloadError, setDownloadError] = useState(null);

  const fetchSummary = async (range = timeframe) => {
    setIsLoading(true);
    try {
      const data = await apiClient.getReportSummary(range);
      setSummary(data);
    } catch (e) {
      console.error('Failed to fetch reports summary:', e);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    fetchSummary(timeframe);
  }, [timeframe]);

  const handleDownloadPdf = async () => {
    setIsDownloading(true);
    setDownloadSuccess(false);
    setDownloadError(null);
    try {
      const blob = await apiClient.downloadReportPdf(timeframe);
      const url = window.URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = `SecureNet_Audit_Report_${timeframe}_${new Date().toISOString().slice(0, 10)}.pdf`;
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);
      window.URL.revokeObjectURL(url);

      setDownloadSuccess(true);
      setTimeout(() => setDownloadSuccess(false), 4000);
    } catch (err) {
      setDownloadError(err.message || 'Failed to download PDF report.');
    } finally {
      setIsDownloading(false);
    }
  };

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header Bar */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div>
          <h1 className="text-base font-bold text-slate-900 font-sans flex items-center gap-2">
            <FileSpreadsheet className="w-5 h-5 text-blue-600" />
            Executive SIEM Cybersecurity Audit Reports
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            Automated ReportLab PDF Compiler &bull; Persistent Threat Audit Ledger
          </p>
        </div>

        <button
          onClick={handleDownloadPdf}
          disabled={isDownloading}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white font-mono font-bold text-xs rounded-xl shadow-2xs disabled:opacity-50 transition-all self-start sm:self-auto"
        >
          <Download className={`w-4 h-4 ${isDownloading ? 'animate-bounce' : ''}`} />
          <span>{isDownloading ? 'Compiling PDF Stream...' : 'Download Executive PDF Report'}</span>
        </button>
      </div>

      {/* Download Alerts */}
      {downloadSuccess && (
        <div className="p-3.5 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-mono flex items-center gap-2">
          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
          <span>Official audit document compiled and downloaded to your local machine.</span>
        </div>
      )}

      {downloadError && (
        <div className="p-3.5 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-mono flex items-center gap-2">
          <AlertTriangle className="w-4 h-4 text-rose-600" />
          <span>{downloadError}</span>
        </div>
      )}

      {/* Audit Scope Window Bar */}
      <div className="soc-card p-3.5 bg-white rounded-2xl flex items-center justify-between border border-slate-200">
        <div className="flex items-center gap-2 text-xs font-mono text-slate-700">
          <Calendar className="w-4 h-4 text-blue-600" />
          <span className="uppercase font-bold">Audit Scope Window:</span>
        </div>

        <div className="flex items-center gap-1 bg-slate-100 p-1 rounded-xl border border-slate-200 text-xs font-mono">
          {[
            { id: 'daily', label: 'Daily (24h)' },
            { id: 'weekly', label: 'Weekly (7d)' },
            { id: 'monthly', label: 'Monthly (30d)' },
          ].map((scope) => (
            <button
              key={scope.id}
              onClick={() => setTimeframe(scope.id)}
              className={`px-3 py-1.5 rounded-lg transition-all font-bold ${
                timeframe === scope.id
                  ? 'bg-white text-blue-700 shadow-2xs border border-slate-200'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {scope.label}
            </button>
          ))}
        </div>
      </div>

      {/* Executive Telemetry Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Inspected Traffic</span>
            <Activity className="w-4 h-4 text-blue-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-slate-900">
            {summary?.total_packets?.toLocaleString() ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            Promiscuous NIC ingress frames
          </div>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Intrusions Intercepted</span>
            <ShieldAlert className="w-4 h-4 text-rose-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-rose-600">
            {summary?.total_threats ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            Signature matches (SQLi/XSS/Probes)
          </div>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Prevention Efficiency</span>
            <ShieldCheck className="w-4 h-4 text-emerald-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-emerald-600">
            {summary?.prevention_rate ?? 100}%
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            Host kernel drop enforcement
          </div>
        </div>

        <div className="soc-card rounded-2xl p-5 bg-white border border-slate-200">
          <div className="flex items-center justify-between text-xs font-mono text-slate-500 mb-1">
            <span>Unique Offender IPs</span>
            <Flame className="w-4 h-4 text-purple-600" />
          </div>
          <div className="text-2xl font-extrabold font-mono text-purple-700">
            {summary?.unique_blocked_ips ?? 0}
          </div>
          <div className="text-[11px] text-slate-500 font-mono mt-1">
            Threat actors isolated at firewall
          </div>
        </div>
      </div>

      {/* Incident Audit Log Preview Table */}
      <div className="soc-card rounded-2xl overflow-hidden bg-white border border-slate-200">
        <div className="p-4 border-b border-slate-100 flex items-center justify-between bg-slate-50/60">
          <h3 className="text-xs font-bold text-slate-900 flex items-center gap-2 uppercase font-mono">
            <FileText className="w-4 h-4 text-blue-600" />
            Incident Audit Log Preview (Last 15 Incidents)
          </h3>
          <span className="text-xs text-slate-500 font-mono">
            Included in PDF Export Ledger
          </span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono border-collapse">
            <thead>
              <tr className="bg-slate-50 border-b border-slate-200 text-slate-500 uppercase text-[10px]">
                <th className="py-2.5 px-4">Event ID</th>
                <th className="py-2.5 px-4">Timestamp</th>
                <th className="py-2.5 px-4">Attacker IP</th>
                <th className="py-2.5 px-4">Target IP</th>
                <th className="py-2.5 px-4">Proto</th>
                <th className="py-2.5 px-4">Signature Description</th>
                <th className="py-2.5 px-4">Payload Extract</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-100 text-slate-700">
              {!summary?.recent_incidents || summary.recent_incidents.length === 0 ? (
                <tr>
                  <td colSpan={7} className="py-10 text-center text-slate-400 font-mono">
                    No threat incidents recorded in current audit window.
                  </td>
                </tr>
              ) : (
                summary.recent_incidents.map((inc) => (
                  <tr key={inc.id} className="hover:bg-slate-50 transition-colors">
                    <td className="py-3 px-4 text-slate-400">#{inc.id}</td>
                    <td className="py-3 px-4 text-slate-500">
                      {inc.timestamp ? new Date(inc.timestamp).toLocaleString() : 'N/A'}
                    </td>
                    <td className="py-3 px-4 font-bold text-rose-600">{inc.src_ip}</td>
                    <td className="py-3 px-4 text-emerald-700">{inc.dst_ip}</td>
                    <td className="py-3 px-4">
                      <span className="px-2 py-0.5 rounded text-[10px] bg-slate-100 text-slate-700 border border-slate-200 font-bold">
                        {inc.protocol}
                      </span>
                    </td>
                    <td className="py-3 px-4 text-slate-900 font-semibold">{inc.threat_type}</td>
                    <td className="py-3 px-4 text-slate-500 font-mono text-[11px] truncate max-w-xs">
                      {inc.payload_sample}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
};

export default Reports;
