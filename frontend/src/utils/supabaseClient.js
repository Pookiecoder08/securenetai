import { createClient } from '@supabase/supabase-js';

/**
 * SecureNet AI — Supabase Client Initializer
 * Authenticates against Supabase GoTrue Auth and PostgreSQL Database.
 * Configuration is injected via Vite environment variables:
 * - VITE_SUPABASE_URL: Project URL (e.g., https://xyz.supabase.co)
 * - VITE_SUPABASE_ANON_KEY: Public Anon Key
 */

const supabaseUrl = import.meta.env.VITE_SUPABASE_URL || '';
const supabaseAnonKey = import.meta.env.VITE_SUPABASE_ANON_KEY || '';

if (!supabaseUrl || !supabaseAnonKey) {
  console.warn(
    '[SecureNet AI / Supabase] Missing VITE_SUPABASE_URL or VITE_SUPABASE_ANON_KEY in environment. ' +
    'Please verify your Vercel / local .env settings.'
  );
}

// Fallback dummy credentials to allow offline UI boot without uncaught fatal exception
const resolvedUrl = supabaseUrl && supabaseUrl.startsWith('http')
  ? supabaseUrl
  : 'https://placeholder.supabase.co';

const resolvedKey = supabaseAnonKey || 'placeholder-anon-key';

export const supabase = createClient(resolvedUrl, resolvedKey, {
  auth: {
    persistSession: true,
    autoRefreshToken: true,
    detectSessionInUrl: true,
    storage: window.localStorage,
  },
});

export default supabase;
