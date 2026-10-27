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
    <div className="w-full animate-in slide-in-from-right-4 duration-200">
      <div className={`bg-white/95 backdrop-blur-md rounded-xl shadow-md p-2.5 border flex items-start gap-2 relative transition-all ${borderColor}`}>
        <div className={`p-1 rounded-md shrink-0 mt-0.5 ${iconBg}`}>
          <IconComponent className="w-3.5 h-3.5" />
        </div>
        <div className="flex-1 min-w-0 pr-5">
          <div className="flex items-center gap-1.5 flex-wrap">
            <h4 className="text-[11px] font-bold text-slate-900 font-sans">{toast.title}</h4>
            <span className="text-[9px] text-slate-400 font-mono ml-auto">{toast.timestamp || 'Just now'}</span>
          </div>
          {toast.description && (
            <p className="text-[10px] text-slate-600 font-sans mt-0.5 leading-snug">{toast.description}</p>
          )}
        </div>
        <button
          onClick={onDismiss}
          className="text-slate-400 hover:text-slate-600 p-0.5 rounded shrink-0 -mt-0.5 -mr-0.5"
          title="Dismiss notification"
        >
          <X className="w-3 h-3" />
        </button>
      </div>
    </div>
  );
};

export default SystemToast;
