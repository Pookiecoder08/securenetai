import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import axios from 'axios';

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
      return false; // Expired!
    }
    return true;
  } catch (e) {
    return false;
  }
};

// Global Axios Request Interceptor: Guarantees Authorization header is ALWAYS attached synchronously
axios.interceptors.request.use((config) => {
  const savedToken = localStorage.getItem('securenet_token');
  if (savedToken && !config.headers.Authorization) {
    config.headers.Authorization = `Bearer ${savedToken}`;
  }
  return config;
});

export const AuthProvider = ({ children }) => {
  const [token, setToken] = useState(() => {
    const saved = localStorage.getItem('securenet_token');
    if (saved && isTokenValid(saved)) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${saved}`;
      return saved;
    }
    // Expired or invalid
    localStorage.removeItem('securenet_token');
    localStorage.removeItem('securenet_username');
    localStorage.removeItem('securenet_role');
    delete axios.defaults.headers.common['Authorization'];
    return null;
  });

  const [user, setUser] = useState(() => localStorage.getItem('securenet_username') || null);
  const [role, setRole] = useState(() => localStorage.getItem('securenet_role') || null);
  const [isLoading, setIsLoading] = useState(false);

  const logout = useCallback(() => {
    localStorage.removeItem('securenet_token');
    localStorage.removeItem('securenet_username');
    localStorage.removeItem('securenet_role');
    delete axios.defaults.headers.common['Authorization'];
    setToken(null);
    setUser(null);
    setRole(null);
  }, []);

  // Sync token state changes with axios and localStorage
  useEffect(() => {
    if (token && isTokenValid(token)) {
      axios.defaults.headers.common['Authorization'] = `Bearer ${token}`;
      localStorage.setItem('securenet_token', token);
      if (user) localStorage.setItem('securenet_username', user);
      if (role) localStorage.setItem('securenet_role', role);
    }
    setIsLoading(false);
  }, [token, user, role]);

  // Response Interceptor: Catch 401s on protected endpoints (excluding login attempts)
  useEffect(() => {
    const interceptor = axios.interceptors.response.use(
      (response) => response,
      (error) => {
        const url = error.config?.url || '';
        if (error.response?.status === 401 && !url.includes('/api/auth/login')) {
          console.warn('[AuthContext] 401 Unauthorized received on protected route. Logging out.');
          logout();
        }
        return Promise.reject(error);
      }
    );
    return () => {
      axios.interceptors.response.eject(interceptor);
    };
  }, [logout]);

  const login = async (username, password) => {
    const params = new URLSearchParams();
    params.append('username', username);
    params.append('password', password);

    const response = await axios.post('/api/auth/login', params, {
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
      },
    });

    const data = response.data;

    // 1. Immediately set Authorization header on Axios synchronously
    axios.defaults.headers.common['Authorization'] = `Bearer ${data.access_token}`;

    // 2. Immediately save to localStorage synchronously
    localStorage.setItem('securenet_token', data.access_token);
    localStorage.setItem('securenet_username', data.username);
    localStorage.setItem('securenet_role', data.role);

    // 3. Update React state
    setToken(data.access_token);
    setUser(data.username);
    setRole(data.role);

    return data;
  };

  const value = {
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
