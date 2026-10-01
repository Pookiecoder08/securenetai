import React, { useState } from 'react';
import { ShieldAlert, X, ArrowRight, Flame, Loader2, CheckCircle2 } from 'lucide-react';

const ThreatToast = ({
  threat,
  onInvestigate,
  onDismiss,
  onResolve
}) => {
  const [isResolving, setIsResolving] = useState(false);
  const [resolveSuccess, setResolveSuccess] = useState(false);

  if (!threat) return null;

  const handleResolveClick = async () => {
    if (isResolving) return;
    setIsResolving(true);
    try {
      if (onResolve) {
        await onResolve(threat);
      }
      setResolveSuccess(true);
      setTimeout(() => {
        if (onDismiss) onDismiss();
      }, 1200);
    } catch (e) {
      setIsResolving(false);
    }
  };

  const threatTitle = threat.threat_type || threat.title || 'Security Signature Match';
  const srcIp = threat.src_ip || threat.source_ip || 'Unknown IP';
  const severity = (threat.severity || threat.threat_severity || 'Critical').toUpperCase();

  return (
    <div className="w-full animate-in slide-in-from-bottom-4 duration-200">
      <div className="bg-white border-2 border-rose-500 rounded-2xl shadow-xl p-4 overflow-hidden relative">
        {/* Buffering Overlay */}
        {isResolving && !resolveSuccess && (
          <div className="absolute inset-0 bg-white/95 backdrop-blur-xs flex flex-col items-center justify-center p-4 z-20">
            <div className="flex items-center gap-2 text-rose-700 font-mono font-bold text-xs mb-1">
              <Loader2 className="w-4 h-4 animate-spin text-rose-600" />
              <span>Enforcing Firewall Drop Rule...</span>
            </div>
            <p className="text-[11px] text-slate-500 font-mono">
              Isolating <span className="font-bold text-rose-700">{srcIp}</span>
            </p>
          </div>
        )}

        {/* Success Overlay */}
        {resolveSuccess && (
          <div className="absolute inset-0 bg-emerald-50/95 backdrop-blur-xs flex flex-col items-center justify-center p-4 z-20">
            <div className="flex items-center gap-2 text-emerald-800 font-mono font-bold text-xs mb-1">
              <CheckCircle2 className="w-4 h-4 text-emerald-600" />
              <span>Host Mitigated &amp; Blocked!</span>
            </div>
          </div>
        )}

        <div className="flex items-start justify-between gap-3">
          <div className="p-2 rounded-xl bg-rose-50 border border-rose-200 text-rose-600 shrink-0">
            <ShieldAlert className="w-5 h-5 text-rose-600" />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] font-bold font-mono px-2 py-0.5 rounded bg-rose-100 text-rose-800 border border-rose-200">
                {severity}
              </span>
              <span className="text-[10px] text-slate-400 font-mono">
                {threat.timestamp ? new Date(threat.threat_timestamp || threat.timestamp).toLocaleTimeString() : 'Now'}
              </span>
            </div>

            <h4 className="text-xs font-bold text-slate-900 leading-snug">
              {threatTitle}
            </h4>

            <div className="mt-2 text-xs font-mono text-slate-600 bg-slate-50 p-2 rounded-lg border border-slate-200 space-y-0.5">
              <div className="flex justify-between">
                <span className="text-slate-500">Offender:</span>
                <span className="font-bold text-rose-600">{srcIp}</span>
              </div>
              <div className="flex justify-between">
                <span className="text-slate-500">Target Port:</span>
                <span className="font-bold text-slate-800">{threat.dst_port || '8000'}</span>
              </div>
            </div>

            {/* Actions */}
            <div className="mt-3 flex items-center justify-end gap-2 flex-wrap">
              <button
                onClick={onDismiss}
                disabled={isResolving}
                className="px-2.5 py-1.5 rounded-lg text-xs font-semibold text-slate-500 hover:text-slate-800 hover:bg-slate-100 transition-colors"
              >
                Dismiss
              </button>

              <button
                onClick={handleResolveClick}
                disabled={isResolving}
                className="flex items-center gap-1 px-3 py-1.5 bg-rose-600 hover:bg-rose-500 text-white rounded-lg text-xs font-bold shadow-2xs transition-all"
              >
                <Flame className="w-3.5 h-3.5" />
                <span>Resolve &amp; Block</span>
              </button>

              {onInvestigate && (
                <button
                  onClick={() => onInvestigate(threat)}
                  disabled={isResolving}
                  className="flex items-center gap-1 px-2.5 py-1.5 bg-slate-900 hover:bg-slate-800 text-white rounded-lg text-xs font-bold shadow-2xs transition-all"
                >
                  <span>Dissect</span>
                  <ArrowRight className="w-3 h-3" />
                </button>
              )}
            </div>
          </div>

          <button
            onClick={onDismiss}
            disabled={isResolving}
            className="text-slate-400 hover:text-slate-600 p-1 rounded-lg hover:bg-slate-100"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
    </div>
  );
};

export default ThreatToast;
