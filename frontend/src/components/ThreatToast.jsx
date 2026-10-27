import React, { useState } from 'react';
import { ShieldAlert, X, ArrowRight, Flame, CheckCircle2 } from 'lucide-react';

const ThreatToast = ({
  threat,
  onInvestigate,
  onDismiss,
  onResolve
}) => {
  const [resolveSuccess, setResolveSuccess] = useState(false);

  const srcIp = threat?.src_ip || threat?.source_ip || '';
  if (!threat || !srcIp || srcIp === 'Unknown IP') return null;

  const handleResolveClick = (e) => {
    e?.stopPropagation();
    if (resolveSuccess) return;

    // 1. Instant optimistic visual feedback (0ms delay)
    setResolveSuccess(true);

    // 2. Fire backend resolution asynchronously
    if (onResolve) {
      Promise.resolve(onResolve(threat)).catch(() => {});
    }

    // 3. Auto dismiss after quick confirmation
    setTimeout(() => {
      if (onDismiss) onDismiss();
    }, 800);
  };

  const threatTitle = threat.threat_type || threat.title || 'Security Signature Match';
  const severity = (threat.severity || threat.threat_severity || 'Critical').toUpperCase();
  const timeStr = threat.timestamp
    ? new Date(threat.threat_timestamp || threat.timestamp).toLocaleTimeString([], {
        hour: '2-digit',
        minute: '2-digit',
        second: '2-digit'
      })
    : 'Now';

  return (
    <div className="w-full animate-in slide-in-from-right-4 duration-200">
      <div className="bg-white/95 backdrop-blur-md border border-rose-300 rounded-xl shadow-md p-2.5 overflow-hidden relative transition-all">
        {/* Instant Success Banner Overlay */}
        {resolveSuccess && (
          <div className="absolute inset-0 bg-emerald-600 text-white flex items-center justify-center gap-1.5 px-3 z-20 animate-in fade-in duration-150">
            <CheckCircle2 className="w-3.5 h-3.5 shrink-0" />
            <span className="text-xs font-mono font-bold truncate">Blocked {srcIp} &amp; Mitigated!</span>
          </div>
        )}

        {/* Compact Content */}
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-start gap-2 min-w-0 flex-1">
            <div className="p-1 rounded-md bg-rose-50 border border-rose-200 text-rose-600 shrink-0 mt-0.5">
              <ShieldAlert className="w-3.5 h-3.5" />
            </div>

            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-1.5 flex-wrap">
                <span className="text-[9px] font-bold font-mono px-1.5 py-0.2 rounded bg-rose-100 text-rose-800 border border-rose-200">
                  {severity}
                </span>
                <span className="text-[10px] font-bold text-slate-800 truncate font-sans">
                  {threatTitle}
                </span>
                <span className="text-[9px] text-slate-400 font-mono ml-auto">
                  {timeStr}
                </span>
              </div>

              <div className="text-[11px] font-mono text-slate-600 mt-1 flex items-center gap-1.5">
                <span className="text-slate-400">Target:</span>
                <span className="font-bold text-rose-600">{srcIp}</span>
                {threat.dst_port && (
                  <span className="text-slate-400 text-[10px]">:{threat.dst_port}</span>
                )}
              </div>

              {/* Action Buttons */}
              <div className="mt-2 flex items-center gap-1.5">
                <button
                  onClick={handleResolveClick}
                  disabled={resolveSuccess}
                  className="px-2 py-0.5 bg-rose-600 hover:bg-rose-500 text-white rounded text-[10px] font-bold inline-flex items-center gap-1 transition-all shadow-2xs"
                >
                  <Flame className="w-3 h-3" />
                  <span>Resolve &amp; Block</span>
                </button>

                {onInvestigate && (
                  <button
                    onClick={(e) => {
                      e.stopPropagation();
                      onInvestigate(threat);
                    }}
                    disabled={resolveSuccess}
                    className="px-2 py-0.5 bg-slate-100 hover:bg-slate-200 text-slate-700 rounded text-[10px] font-semibold inline-flex items-center gap-0.5 transition-all"
                  >
                    <span>Inspect</span>
                    <ArrowRight className="w-2.5 h-2.5 text-slate-500" />
                  </button>
                )}

                <button
                  onClick={(e) => {
                    e.stopPropagation();
                    if (onDismiss) onDismiss();
                  }}
                  disabled={resolveSuccess}
                  className="px-1.5 py-0.5 text-[10px] text-slate-400 hover:text-slate-700 font-medium ml-auto"
                >
                  Dismiss
                </button>
              </div>
            </div>
          </div>

          <button
            onClick={(e) => {
              e.stopPropagation();
              if (onDismiss) onDismiss();
            }}
            className="text-slate-400 hover:text-slate-600 p-0.5 rounded shrink-0 -mt-0.5 -mr-0.5"
            title="Dismiss notification"
          >
            <X className="w-3 h-3" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default ThreatToast;
