import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';
import { supabase } from '../utils/supabaseClient';

const AuthContext = createContext(null);

const isTokenValid = (tokenStr) => {
  if (!tokenStr || typeof tokenStr !== 'string') return false;
  try {
    const parts = tokenStr.split('.');
    if (parts.length < 2) return false;
    let base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/');
    while (base64.length % 4 !== 0) {
      base64 += '=';
    }
    const jsonPayload = atob(base64);
    const { exp } = JSON.parse(jsonPayload);
    if (exp && exp * 1000 < Date.now()) {
      return false; // Expired
    }
    return true;
  } catch (e) {
    return false;
  }
};

// Global Axios Request Interceptor: Guarantees Authorization header is ALWAYS attached
axios.interceptors.request.use((config) => {
  const savedToken = localStorage.getItem('securenet_token');
  if (savedToken && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${savedToken}`;
  }
  return config;
});

export const AuthProvider = ({ children }) => {
  const [session, setSession] = useState(null);
  const [token, setToken] = useState(() => {
    const saved = localStorage.getItem('securenet_token');
    if (saved && isTokenValid(saved)) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${saved}`;
      return saved;
    }
    return null;
  });

  const [user, setUser] = useState(() => localStorage.getItem('securenet_username') || null);
  const [role, setRole] = useState(() => localStorage.getItem('securenet_role') || null);
  const [isLoading, setIsLoading] = useState(true);

  const handleSessionUpdate = useCallback((sess) => {
    setSession(sess);
    const accessToken = sess.access_token;
    const authUser = sess.user;

    const userRole =
      authUser?.user_metadata?.role ||
      authUser?.app_metadata?.role ||
      (authUser?.email?.includes('analyst')
        ? 'analyst'
        : authUser?.email?.includes('employee')
        ? 'employee'
        : 'admin');

    const username =
      authUser?.user_metadata?.username ||
      authUser?.user_metadata?.full_name ||
      authUser?.email?.split('@')[0] ||
      authUser?.email ||
      'Operator';

    setToken(accessToken);
    setUser(username);
    setRole(userRole);

    localStorage.setItem('securenet_token', accessToken);
    localStorage.setItem('securenet_username', username);
    localStorage.setItem('securenet_role', userRole);
    axios.defaults.headers.common['Authorization'] = `Bearer ${accessToken}`;
  }, []);

  const clearAuthState = useCallback(() => {
    localStorage.removeItem('securenet_token');
    localStorage.removeItem('securenet_username');
    localStorage.removeItem('securenet_role');
    delete axios.defaults.headers.common['Authorization'];
    setToken(null);
    setUser(null);
    setRole(null);
    setSession(null);
  }, []);

  // Initialize and subscribe to Supabase GoTrue Auth state
  useEffect(() => {
    let mounted = true;

    // 1. Check current Supabase session
    supabase.auth.getSession().then(({ data: { session: activeSession } }) => {
      if (!mounted) return;
      if (activeSession && activeSession.access_token) {
        handleSessionUpdate(activeSession);
      } else {
        const saved = localStorage.getItem('securenet_token');
        if (!saved || !isTokenValid(saved)) {
          clearAuthState();
        }
      }
      setIsLoading(false);
    }).catch(() => {
      if (mounted) setIsLoading(false);
    });

    // 2. Real-time auth listener for login/logout/token-refresh events
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, currentSession) => {
      if (!mounted) return;
      if (currentSession && (event === 'SIGNED_IN' || event === 'TOKEN_REFRESHED' || event === 'INITIAL_SESSION')) {
        handleSessionUpdate(currentSession);
      } else if (event === 'SIGNED_OUT') {
        clearAuthState();
      }
    });

    return () => {
      mounted = false;
      subscription?.unsubscribe();
    };
  }, [handleSessionUpdate, clearAuthState]);

  // Intercept 401 Unauthorized responses
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        const url = error.config?.url || '';
        if (error.response?.status === 401 && !url.includes('/api/auth/login')) {
          console.warn('[AuthContext] 401 Unauthorized on protected route.');
        }
        return Promise.reject(error);
      }
    );
    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, []);

  const logout = useCallback(async () => {
    try {
      await supabase.auth.signOut();
    } catch (e) {
      console.warn('[Supabase Auth] SignOut exception:', e);
    }
    clearAuthState();
  }, [clearAuthState]);

  const login = async (identifier, password) => {
    setIsLoading(true);

    // If identifier is a username (e.g., 'admin'), normalize to email format
    let email = identifier.trim();
    if (!email.includes('@')) {
      email = `${email.toLowerCase()}@securenet.ai`;
    }

    // 1. Authenticate against Supabase GoTrue Auth
    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    if (error) {
      setIsLoading(false);
      throw new Error(error.message || 'Supabase authentication failed. Please check credentials.');
    }

    if (data?.session) {
      handleSessionUpdate(data.session);
      setIsLoading(false);
      return data;
    }

    setIsLoading(false);
    throw new Error('Supabase did not return an active session.');
  };

  const value = {
    session,
    token,
    user,
    role,
    isLoading,
    login,
    logout,
    isAdmin: role === 'admin',
    isAnalyst: role === 'analyst',
    isEmployee: role === 'employee',
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};

export default AuthContext;
