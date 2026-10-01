import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import {
  Shield,
  Lock,
  User,
  ArrowRight,
  ShieldAlert,
  KeyRound,
  Terminal
} from 'lucide-react';

const Login = () => {
  const [username, setUsername] = useState('admin');
  const [password, setPassword] = useState('admin123');
  const [error, setError] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const { login } = useAuth();
  const navigate = useNavigate();

  const handleLogin = async (e) => {
    e.preventDefault();
    setError('');
    setIsLoading(true);

    try {
      await login(username, password);
      navigate('/dashboard');
    } catch (err) {
      setError(
        err.response?.data?.detail || err.message || 'Authentication failed. Please check credentials or verify backend server is running.'
      );
    } finally {
      setIsLoading(false);
    }
  };

  const handleQuickFill = (u, p) => {
    setUsername(u);
    setPassword(p);
    setError('');
  };

  return (
    <div className="min-h-screen bg-slate-50 flex items-center justify-center p-6 relative">
      <div className="w-full max-w-md relative z-10">
        {/* Brand Header */}
        <div className="text-center mb-8">
          <div className="inline-flex p-3 rounded-2xl bg-blue-600 shadow-lg shadow-blue-500/20 text-white mb-4">
            <Shield className="w-8 h-8" />
          </div>
          <h1 className="text-2xl font-extrabold tracking-tight text-slate-900 font-sans">
            SecureNet <span className="text-blue-600">AI</span>
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-1">
            Enterprise Network Intrusion Detection &amp; Prevention System
          </p>
        </div>

        {/* Login Card */}
        <div className="bg-white border border-slate-200 shadow-xl rounded-2xl p-8">
          <div className="flex items-center justify-between mb-6 pb-4 border-b border-slate-100">
            <div className="flex items-center gap-2">
              <KeyRound className="w-4 h-4 text-blue-600" />
              <h2 className="text-xs font-bold uppercase tracking-wider text-slate-900 font-mono">
                Operator Security Access
              </h2>
            </div>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-bold">
              NIDS ONLINE
            </span>
          </div>

          {error && (
            <div className="mb-5 p-3 rounded-xl bg-rose-50 border border-rose-200 text-rose-700 text-xs font-mono flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 shrink-0 text-rose-600" />
              <span>{error}</span>
            </div>
          )}

          <form onSubmit={handleLogin} className="space-y-4">
            <div>
              <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider font-mono mb-1.5">
                Username Identifier
              </label>
              <div className="relative">
                <User className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="text"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="admin / analyst / employee"
                  required
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 font-mono"
                />
              </div>
            </div>

            <div>
              <label className="block text-xs font-bold text-slate-700 uppercase tracking-wider font-mono mb-1.5">
                Operator Passkey
              </label>
              <div className="relative">
                <Lock className="w-4 h-4 text-slate-400 absolute left-3.5 top-1/2 -translate-y-1/2" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••••••"
                  required
                  className="w-full pl-10 pr-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-xs text-slate-900 placeholder-slate-400 focus:outline-none focus:border-blue-600 font-mono"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={isLoading}
              className="w-full mt-3 py-3 px-4 bg-blue-600 hover:bg-blue-500 text-white font-bold rounded-xl text-xs transition-all shadow-2xs flex items-center justify-center gap-2 group disabled:opacity-50"
            >
              <span>{isLoading ? 'Authenticating with Backend...' : 'Authenticate Session'}</span>
              <ArrowRight className="w-4 h-4 group-hover:translate-x-0.5 transition-transform" />
            </button>
          </form>

          {/* Quick Credential Fill (Fills inputs, authenticates via real backend) */}
          <div className="mt-8 pt-5 border-t border-slate-100">
            <div className="flex items-center gap-1.5 text-[11px] text-slate-500 uppercase font-mono mb-3">
              <Terminal className="w-3.5 h-3.5 text-blue-600" />
              <span>Role Presets (Fills Credentials):</span>
            </div>

            <div className="grid grid-cols-3 gap-2">
              <button
                type="button"
                onClick={() => handleQuickFill('admin', 'admin123')}
                className={`p-2.5 rounded-xl text-left border transition-all ${
                  username === 'admin'
                    ? 'bg-blue-50 border-blue-300 shadow-2xs'
                    : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                }`}
              >
                <span className="text-[11px] font-mono font-bold block text-slate-900">
                  Alex Vance
                </span>
                <span className="text-[10px] text-blue-700 font-semibold block uppercase">Admin</span>
              </button>

              <button
                type="button"
                onClick={() => handleQuickFill('analyst', 'analyst123')}
                className={`p-2.5 rounded-xl text-left border transition-all ${
                  username === 'analyst'
                    ? 'bg-blue-50 border-blue-300 shadow-2xs'
                    : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                }`}
              >
                <span className="text-[11px] font-mono font-bold block text-slate-900">
                  Sarah Chen
                </span>
                <span className="text-[10px] text-indigo-700 font-semibold block uppercase">Analyst</span>
              </button>

              <button
                type="button"
                onClick={() => handleQuickFill('employee', 'employee123')}
                className={`p-2.5 rounded-xl text-left border transition-all ${
                  username === 'employee'
                    ? 'bg-blue-50 border-blue-300 shadow-2xs'
                    : 'bg-slate-50 border-slate-200 hover:border-slate-300'
                }`}
              >
                <span className="text-[11px] font-mono font-bold block text-slate-900">
                  Mark Miller
                </span>
                <span className="text-[10px] text-slate-500 font-semibold block uppercase">Employee</span>
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Login;
