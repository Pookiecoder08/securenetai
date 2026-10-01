import React, { useState } from 'react';
import { BrowserRouter, Routes, Route, Navigate, useLocation } from 'react-router-dom';
import { AuthProvider, useAuth } from './context/AuthContext';
import { SOCProvider, useSOC } from './context/SOCContext';
import ProtectedRoute from './components/ProtectedRoute';
import Navbar from './components/Navbar';
import Sidebar from './components/Sidebar';
import ThreatToast from './components/ThreatToast';
import PacketModal from './components/PacketModal';

import Login from './pages/Login';
import Dashboard from './pages/Dashboard';
import FirewallManager from './pages/FirewallManager';
import Topology from './pages/Topology';
import Reports from './pages/Reports';
import ThreatMonitor from './pages/ThreatMonitor';
import PacketAnalysis from './pages/PacketAnalysis';
import { AlertTriangle, RefreshCw } from 'lucide-react';

const PAGE_NAMES = {
  '/dashboard': 'Dashboard',
  '/topology': 'Network Topology',
  '/threats': 'Threat Monitor',
  '/packets': 'Packet Analysis',
  '/firewall': 'Firewall ACLs',
  '/reports': 'SIEM Reports'
};

const AppLayout = ({ children }) => {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const location = useLocation();
  const { isBackendOffline, retryConnection } = useSOC();
  const activePageName = PAGE_NAMES[location.pathname] || 'Operations';

  return (
    <div className="min-h-screen flex flex-col bg-slate-50 font-sans text-slate-800">
      <Navbar
        onToggleSidebar={() => setSidebarOpen(!sidebarOpen)}
        activePageName={activePageName}
      />
      <div className="flex flex-1 min-h-0">
        <Sidebar
          isOpen={sidebarOpen}
          onClose={() => setSidebarOpen(false)}
        />
        <main className="flex-1 min-w-0 overflow-y-auto bg-slate-50">
          {/* Offline Banner */}
          {isBackendOffline && (
            <div className="bg-rose-50 border-b border-rose-200 px-6 py-3 flex items-center justify-between text-xs font-mono text-rose-800">
              <div className="flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                <span>Backend FastAPI service unavailable. Reconnecting...</span>
              </div>
              <button
                onClick={retryConnection}
                className="px-3 py-1 bg-white hover:bg-rose-100 text-rose-700 border border-rose-200 font-bold rounded-lg transition-all shadow-2xs flex items-center gap-1"
              >
                <RefreshCw className="w-3 h-3" />
                Retry Now
              </button>
            </div>
          )}

          {children}
        </main>
      </div>
    </div>
  );
};

function AppContent() {
  const { token } = useAuth();
  const {
    toasts,
    removeToast,
    blockIp,
    activeModalPacket,
    setActiveModalPacket
  } = useSOC();

  return (
    <>
      <Routes>
        <Route
          path="/login"
          element={token ? <Navigate to="/dashboard" replace /> : <Login />}
        />

        <Route
          path="/dashboard"
          element={
            <ProtectedRoute>
              <AppLayout>
                <Dashboard
                  onInvestigatePacket={(p) => setActiveModalPacket(p)}
                />
              </AppLayout>
            </ProtectedRoute>
          }
        />

        <Route
          path="/topology"
          element={
            <ProtectedRoute>
              <AppLayout>
                <Topology />
              </AppLayout>
            </ProtectedRoute>
          }
        />

        <Route
          path="/threats"
          element={
            <ProtectedRoute>
              <AppLayout>
                <ThreatMonitor />
              </AppLayout>
            </ProtectedRoute>
          }
        />

        <Route
          path="/packets"
          element={
            <ProtectedRoute allowedRoles={['admin', 'analyst']}>
              <AppLayout>
                <PacketAnalysis />
              </AppLayout>
            </ProtectedRoute>
          }
        />

        <Route
          path="/firewall"
          element={
            <ProtectedRoute allowedRoles={['admin', 'analyst']}>
              <AppLayout>
                <FirewallManager />
              </AppLayout>
            </ProtectedRoute>
          }
        />

        <Route
          path="/reports"
          element={
            <ProtectedRoute allowedRoles={['admin', 'analyst']}>
              <AppLayout>
                <Reports />
              </AppLayout>
            </ProtectedRoute>
          }
        />

        <Route path="/" element={<Navigate to="/dashboard" replace />} />
        <Route path="*" element={<Navigate to="/dashboard" replace />} />
      </Routes>

      {/* Floating Right Threat Alert Toasts */}
      <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-3 max-w-md w-full pointer-events-none">
        <div className="pointer-events-auto space-y-3">
          {toasts.map((toast) => (
            <ThreatToast
              key={toast.id}
              threat={toast.packet || toast}
              onInvestigate={(pkt) => {
                setActiveModalPacket(pkt || toast.packet);
                removeToast(toast.id);
              }}
              onDismiss={() => removeToast(toast.id)}
              onResolve={(t) => {
                blockIp(t.src_ip || t.source_ip, t.threat_type || 'Alert Toast Quick Resolution');
                removeToast(toast.id);
              }}
            />
          ))}
        </div>
      </div>

      {/* Deep Packet Inspection Modal */}
      {activeModalPacket && (
        <PacketModal
          packet={activeModalPacket}
          onClose={() => setActiveModalPacket(null)}
        />
      )}
    </>
  );
}

export default function App() {
  return (
    <BrowserRouter>
      <AuthProvider>
        <SOCProvider>
          <AppContent />
        </SOCProvider>
      </AuthProvider>
    </BrowserRouter>
  );
}
