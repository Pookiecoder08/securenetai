import React from 'react';
import { Navigate, Link } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { ShieldAlert, Shield } from 'lucide-react';

const ProtectedRoute = ({ children, allowedRoles }) => {
  const { token, role, isLoading } = useAuth();

  if (isLoading) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-slate-50 text-slate-700">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-blue-600 border-t-transparent rounded-full animate-spin"></div>
          <span className="text-xs uppercase tracking-widest font-mono text-slate-500">Verifying session credentials...</span>
        </div>
      </div>
    );
  }

  if (!token) {
    return <Navigate to="/login" replace />;
  }

  if (allowedRoles && !allowedRoles.includes(role)) {
    return (
      <div className="min-h-[80vh] flex flex-col items-center justify-center p-6 text-center">
        <div className="p-4 rounded-2xl bg-rose-50 border border-rose-200 text-rose-600 mb-4">
          <ShieldAlert className="w-10 h-10" />
        </div>
        <h2 className="text-xl font-bold text-slate-900 mb-2 font-sans">Restricted Access Clearance</h2>
        <p className="text-slate-600 max-w-md mb-6 text-xs font-mono">
          Access to this module requires <span className="font-bold text-blue-700">{allowedRoles.join(' or ')}</span> privileges. 
          Your session is authorized at the <span className="font-bold text-slate-900 uppercase">{role}</span> level.
        </p>
        <Link
          to="/dashboard"
          className="px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white rounded-xl text-xs font-bold transition-all shadow-2xs"
        >
          Return to Operations Dashboard
        </Link>
      </div>
    );
  }

  return children;
};

export default ProtectedRoute;
