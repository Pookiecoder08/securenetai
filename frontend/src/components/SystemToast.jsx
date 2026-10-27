import React from 'react';
import { CheckCircle2, Info, AlertTriangle, X } from 'lucide-react';

const SystemToast = ({ toast, onDismiss }) => {
  if (!toast) return null;

  const severity = (toast.severity || 'info').toLowerCase();
  const isSuccess = severity === 'success';
  const isWarning = severity === 'warning' || severity === 'warn';
  const isError = severity === 'error' || severity === 'danger';

  let borderColor = 'border-blue-200';
  let iconBg = 'bg-blue-50 text-blue-600';
  let IconComponent = Info;

  if (isSuccess) {
    borderColor = 'border-emerald-200';
    iconBg = 'bg-emerald-50 text-emerald-600';
    IconComponent = CheckCircle2;
  } else if (isWarning) {
    borderColor = 'border-amber-200';
    iconBg = 'bg-amber-50 text-amber-600';
    IconComponent = AlertTriangle;
  } else if (isError) {
    borderColor = 'border-rose-200';
    iconBg = 'bg-rose-50 text-rose-600';
    IconComponent = AlertTriangle;
  }

  return (
    <div className="w-full animate-in slide-in-from-bottom-4 duration-200">
      <div className={`bg-white rounded-2xl shadow-lg p-3.5 border flex items-start gap-3 relative ${borderColor}`}>
        <div className={`p-2 rounded-xl shrink-0 ${iconBg}`}>
          <IconComponent className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0 pr-6">
          <div className="flex items-center gap-2 mb-0.5">
            <h4 className="text-xs font-bold text-slate-900 font-sans">{toast.title}</h4>
            <span className="text-[10px] text-slate-400 font-mono">{toast.timestamp || 'Just now'}</span>
          </div>
          {toast.description && (
            <p className="text-[11px] text-slate-600 font-sans leading-relaxed">{toast.description}</p>
          )}
        </div>
        <button
          onClick={onDismiss}
          className="absolute top-3 right-3 text-slate-400 hover:text-slate-600 transition-colors p-1 rounded-md"
          title="Dismiss notification"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  );
};

export default SystemToast;
