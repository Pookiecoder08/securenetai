import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import {
  Shield,
  Radio,
  Bell,
  LogOut,
  X,
  Wifi,
  Clock,
  RefreshCw,
  RotateCcw,
  Filter,
  Menu,
  ChevronRight,
  AlertTriangle,
  UserCheck
} from 'lucide-react';

const Navbar = ({ onToggleSidebar, activePageName = 'Dashboard' }) => {
  const { user, role, logout, isEmployee } = useAuth();
  const {
    status,
    connectionState,
    secondsAgo,
    alerts,
    isPaused,
    setIsPaused,
    retryConnection,
    isBackendOffline,
    refreshPersistedData,
    fetchTelemetry,
    setFilterMode,
    resetSession
  } = useSOC();

  const [showAlertDrawer, setShowAlertDrawer] = useState(false);
  const [isRefreshing, setIsRefreshing] = useState(false);
  const [isResetting, setIsResetting] = useState(false);

  const handleRefresh = async () => {
    setIsRefreshing(true);
    try {
      if (refreshPersistedData) await refreshPersistedData();
      if (fetchTelemetry) await fetchTelemetry();
      window.dispatchEvent(new CustomEvent('soc:refresh'));
    } catch (e) {
      console.error('Refresh error:', e);
    } finally {
      setTimeout(() => setIsRefreshing(false), 500);
    }
  };

  const handleResetSession = async () => {
    if (isEmployee || isResetting || !resetSession) return;
    setIsResetting(true);
    try {
      await resetSession(true);
    } catch (e) {
      console.error('Reset error:', e);
    } finally {
      setIsResetting(false);
    }
  };

  const getDisplayName = () => {
    if (user === 'admin') return 'Alex Vance';
    if (user === 'analyst') return 'Sarah Chen';
    if (user === 'employee') return 'Mark Miller';
    return user || 'Operator';
  };

  const getRoleTitle = () => {
    if (role === 'admin') return 'Administrator';
    if (role === 'analyst') return 'Security Analyst';
    if (role === 'employee') return 'Employee (Read-Only)';
    return role ? role.toUpperCase() : 'Operator';
  };

  const adapterName = status?.adapter?.name || 'Network Adapter';
  const adapterIp = status?.adapter?.ip || '0.0.0.0';
  const alertCount = alerts.length;

  return (
    <header className="h-16 bg-white border-b border-slate-200 px-4 sm:px-6 flex items-center justify-between sticky top-0 z-30 shadow-xs">
      {/* Left: Mobile Sidebar Toggle + Title Breadcrumb */}
      <div className="flex items-center gap-3">
        <button
          onClick={onToggleSidebar}
          className="lg:hidden p-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors"
          title="Toggle Navigation Menu"
        >
          <Menu className="w-5 h-5" />
        </button>

        <div className="flex items-center gap-2 text-xs font-mono text-slate-500">
          <span className="font-semibold text-slate-700 flex items-center gap-1.5">
            <Shield className="w-4 h-4 text-blue-600" />
            SecureNet AI
          </span>
          <ChevronRight className="w-3.5 h-3.5 text-slate-300" />
          <span className="font-bold text-slate-900 font-sans text-sm">{activePageName}</span>
        </div>

        {/* Dashboard Quick Mode Switcher & Reset */}
        {activePageName === 'Dashboard' && !isEmployee && (
          <div className="hidden lg:flex items-center gap-2 ml-2 pl-3 border-l border-slate-200">
            <div className="flex items-center bg-slate-100 p-0.5 rounded-lg border border-slate-200">
              <Filter className="w-3 h-3 text-slate-400 ml-1.5 mr-1" />
              {['soc_filtered', 'targeted', 'raw_all'].map((mode) => (
                <button
                  key={mode}
                  onClick={() => setFilterMode(mode)}
                  className={`px-2 py-0.5 rounded text-[10px] font-bold font-mono transition-all ${
                    (status?.capture_filter_mode || 'soc_filtered') === mode
                      ? 'bg-white text-blue-700 shadow-2xs border border-slate-200'
                      : 'text-slate-600 hover:text-slate-900'
                  }`}
                >
                  {mode === 'soc_filtered' ? 'Filtered' : mode === 'targeted' ? 'Targeted' : 'Raw'}
                </button>
              ))}
            </div>
            <button
              onClick={handleResetSession}
              disabled={isResetting}
              className="flex items-center gap-1 px-2 py-1 rounded-lg bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 font-mono font-semibold text-[11px] transition-all shadow-2xs disabled:opacity-50"
              title="Reset session telemetry counters"
            >
              <RotateCcw className={`w-3 h-3 text-blue-600 ${isResetting ? 'animate-spin' : ''}`} />
              <span>Reset</span>
            </button>
          </div>
        )}
      </div>

      {/* Center / Right: Connection Badge, Clock, Refresh, Adapter, User Profile */}
      <div className="flex items-center gap-3 sm:gap-4">
        {/* Universal Refresh Button */}
        <button
          onClick={handleRefresh}
          disabled={isRefreshing}
          className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 text-xs font-mono font-semibold transition-all border border-slate-200 shadow-2xs"
          title="Refresh All Telemetry & Kernel Records"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-blue-600 ${isRefreshing ? 'animate-spin' : ''}`} />
          <span className="hidden sm:inline">Refresh</span>
        </button>

        {/* Adapter & IP Info */}
        <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-100/80 border border-slate-200 text-xs font-mono text-slate-600">
          <Wifi className="w-3.5 h-3.5 text-slate-500" />
          <span className="truncate max-w-[140px] font-medium" title={adapterName}>{adapterName}</span>
          <span className="font-bold text-blue-700 bg-white px-1.5 py-0.5 rounded border border-slate-200">{adapterIp}</span>
        </div>

        {/* Live Clock / Last Update Counter */}
        <div className="hidden sm:flex items-center gap-1.5 text-xs font-mono text-slate-500">
          <Clock className="w-3.5 h-3.5 text-slate-400" />
          <span>Updated {secondsAgo}s ago</span>
        </div>

        {/* Connection State Indicator */}
        <div className="flex items-center gap-2">
          {connectionState === 'Live' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-xs font-mono font-semibold">
              <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
              Live
            </span>
          )}

          {connectionState === 'Reconnecting' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-amber-50 text-amber-700 border border-amber-200 text-xs font-mono font-semibold">
              <RefreshCw className="w-3 h-3 animate-spin text-amber-600" />
              Reconnecting
            </span>
          )}

          {connectionState === 'Offline' && (
            <button
              onClick={retryConnection}
              className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-rose-50 hover:bg-rose-100 text-rose-700 border border-rose-200 text-xs font-mono font-semibold transition-colors"
              title="Click to retry backend connection"
            >
              <AlertTriangle className="w-3 h-3 text-rose-600" />
              Offline (Retry)
            </button>
          )}

          {connectionState === 'Paused' && (
            <span className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full bg-slate-100 text-slate-600 border border-slate-200 text-xs font-mono font-semibold">
              <Radio className="w-3 h-3 text-slate-400" />
              Paused
            </span>
          )}
        </div>

        {/* SIEM Notifications Bell Drawer */}
        <div className="relative">
          <button
            onClick={() => setShowAlertDrawer(!showAlertDrawer)}
            className="p-2 rounded-lg text-slate-500 hover:text-slate-900 hover:bg-slate-100 transition-colors relative"
            title="SIEM Notifications Feed"
          >
            <Bell className="w-4 h-4" />
            {alertCount > 0 && (
              <span className="absolute top-1 right-1 flex h-4 w-4 items-center justify-center rounded-full bg-rose-600 text-[10px] font-bold text-white">
                {alertCount > 99 ? '99+' : alertCount}
              </span>
            )}
          </button>

          {/* Notifications Drawer */}
          {showAlertDrawer && (
            <div className="absolute right-0 mt-3 w-80 sm:w-96 bg-white rounded-2xl shadow-xl border border-slate-200 p-4 z-50 animate-in fade-in">
              <div className="flex items-center justify-between pb-3 border-b border-slate-100 mb-3">
                <div className="flex items-center gap-2">
                  <Bell className="w-4 h-4 text-blue-600" />
                  <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono">
                    SIEM Alert Feed ({alertCount})
                  </h4>
                </div>
                <button
                  onClick={() => setShowAlertDrawer(false)}
                  className="text-slate-400 hover:text-slate-600"
                >
                  <X className="w-4 h-4" />
                </button>
              </div>

              <div className="space-y-2 max-h-72 overflow-y-auto pr-1">
                {alerts.length > 0 ? (
                  alerts.map((alt) => (
                    <div
                      key={alt.id}
                      className={`p-2.5 rounded-xl border text-xs font-mono ${
                        alt.severity === 'critical'
                          ? 'bg-rose-50 border-rose-200 text-rose-800'
                          : alt.severity === 'high'
                          ? 'bg-amber-50 border-amber-200 text-amber-800'
                          : 'bg-slate-50 border-slate-200 text-slate-700'
                      }`}
                    >
                      <div className="flex items-center justify-between font-bold mb-1">
                        <span className="truncate pr-2">{alt.title}</span>
                        <span className="text-[10px] text-slate-400">
                          {alt.timestamp ? new Date(alt.timestamp).toLocaleTimeString() : 'Now'}
                        </span>
                      </div>
                      <p className="text-[11px] opacity-90 leading-relaxed font-sans">{alt.description}</p>
                    </div>
                  ))
                ) : (
                  <p className="text-xs text-slate-400 py-6 text-center font-mono">
                    No active threat alerts in current session feed.
                  </p>
                )}
              </div>
            </div>
          )}
        </div>

        <div className="h-5 w-[1px] bg-slate-200"></div>

        {/* User Profile Menu */}
        <div className="flex items-center gap-2.5">
          <div className="w-8 h-8 rounded-full bg-blue-600 text-white flex items-center justify-center font-bold text-xs shadow-xs">
            {getDisplayName().charAt(0)}
          </div>
          <div className="hidden sm:block text-left">
            <div className="text-xs font-bold text-slate-900 leading-tight">
              {getDisplayName()}
            </div>
            <div className="text-[10px] text-blue-600 font-mono font-semibold">
              {getRoleTitle()}
            </div>
          </div>

          <button
            onClick={logout}
            className="p-1.5 rounded-lg text-slate-400 hover:text-rose-600 hover:bg-rose-50 transition-colors ml-1"
            title="Sign Out"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  );
};

export default Navbar;
