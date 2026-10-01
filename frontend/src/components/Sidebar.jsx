import React from 'react';
import { NavLink } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import {
  LayoutDashboard,
  Network,
  ShieldAlert,
  Binary,
  Flame,
  FileSpreadsheet,
  Shield,
  X,
  Activity
} from 'lucide-react';

const Sidebar = ({ isOpen, onClose }) => {
  const { isEmployee } = useAuth();
  const { status, connectionState } = useSOC();

  const navItems = [
    {
      to: '/dashboard',
      label: 'Dashboard',
      icon: LayoutDashboard,
      show: true
    },
    {
      to: '/topology',
      label: 'Network Topology',
      icon: Network,
      show: true
    },
    {
      to: '/threats',
      label: 'Threat Monitor',
      icon: ShieldAlert,
      show: true
    },
    {
      to: '/packets',
      label: 'Packet Analysis',
      icon: Binary,
      show: !isEmployee
    },
    {
      to: '/firewall',
      label: 'Firewall ACLs',
      icon: Flame,
      show: !isEmployee
    },
    {
      to: '/reports',
      label: 'SIEM Reports',
      icon: FileSpreadsheet,
      show: !isEmployee
    }
  ];

  return (
    <>
      {/* Mobile Backdrop */}
      {isOpen && (
        <div
          onClick={onClose}
          className="fixed inset-0 bg-slate-900/40 z-40 lg:hidden backdrop-blur-xs"
        ></div>
      )}

      {/* Sidebar Shell */}
      <aside
        className={`fixed lg:sticky top-0 lg:top-16 left-0 z-50 lg:z-20 w-64 bg-white border-r border-slate-200 flex flex-col justify-between shrink-0 h-screen lg:h-[calc(100vh-4rem)] transition-transform duration-200 ease-in-out ${
          isOpen ? 'translate-x-0' : '-translate-x-full lg:translate-x-0'
        }`}
      >
        <div className="p-4 space-y-4">
          {/* Mobile Header Brand */}
          <div className="flex items-center justify-between lg:hidden pb-3 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-lg bg-blue-600 text-white">
                <Shield className="w-4 h-4" />
              </div>
              <span className="font-extrabold text-sm text-slate-900">SecureNet AI</span>
            </div>
            <button
              onClick={onClose}
              className="p-1 text-slate-400 hover:text-slate-700 rounded-lg"
            >
              <X className="w-5 h-5" />
            </button>
          </div>

          <div className="px-3 text-[11px] font-bold uppercase tracking-wider text-slate-400 font-mono">
            Navigation Menu
          </div>

          <nav className="space-y-1">
            {navItems
              .filter((item) => item.show)
              .map((item) => {
                const Icon = item.icon;
                return (
                  <NavLink
                    key={item.to}
                    to={item.to}
                    onClick={() => {
                      if (onClose) onClose();
                    }}
                    className={({ isActive }) =>
                      `flex items-center gap-3 px-3.5 py-2.5 rounded-xl text-xs font-semibold transition-all ${
                        isActive
                          ? 'bg-blue-50 text-blue-700 font-bold border-l-4 border-l-blue-600 shadow-2xs'
                          : 'text-slate-600 hover:text-slate-900 hover:bg-slate-50'
                      }`
                    }
                  >
                    <Icon className="w-4 h-4 shrink-0" />
                    <span>{item.label}</span>
                  </NavLink>
                );
              })}
          </nav>
        </div>

        {/* System Health Summary Footer */}
        <div className="p-4 border-t border-slate-100 bg-slate-50/60">
          <div className="p-3 rounded-xl bg-white border border-slate-200 shadow-2xs space-y-1.5">
            <div className="flex items-center justify-between text-xs font-mono">
              <span className="font-bold text-slate-700 flex items-center gap-1.5">
                <Activity className="w-3.5 h-3.5 text-blue-600" /> Sensor Status
              </span>
              <span
                className={`w-2 h-2 rounded-full ${
                  status?.sniffer_running ? 'bg-emerald-500' : 'bg-rose-500'
                }`}
              ></span>
            </div>
            <div className="text-[11px] text-slate-500 font-mono">
              Mode:{' '}
              <span className="font-semibold text-slate-800">
                {status?.capture_filter_mode || 'soc_filtered'}
              </span>
            </div>
          </div>
        </div>
      </aside>
    </>
  );
};

export default Sidebar;
