/**
 * SecureNet AI — Dynamic Sensor Routing & WebSocket Utility (Hybrid Cloud-Local Architecture)
 * 
 * Routes frontend API calls and live telemetry WebSockets from Vercel to the local NIDS sensor
 * running on the operator's PC via an Ngrok tunnel.
 */

/**
 * Returns the resolved sensor base URL from environment variables.
 * Falls back in priority:
 * 1. VITE_SENSOR_API_URL (Ngrok HTTPS URL, e.g. https://xyz.ngrok-free.app)
 * 2. VITE_API_BASE_URL (legacy/local dev)
 * 3. Localhost fallback http://127.0.0.1:8000
 */
export function getSensorApiUrl() {
  const envUrl =
    import.meta.env.VITE_SENSOR_API_URL ||
    import.meta.env.VITE_API_BASE_URL ||
    '';

  if (envUrl && typeof envUrl === 'string') {
    return envUrl.trim().replace(/\/+$/, '');
  }

  // Fallback for development if no env var is provided
  if (typeof window !== 'undefined' && window.location.hostname === 'localhost') {
    return 'http://127.0.0.1:8000';
  }

  return '';
}

/**
 * Utility Function: Converts an HTTP/HTTPS URL into a WS/WSS WebSocket URL.
 * Handles Ngrok tunnels (e.g., https://xxxx.ngrok-free.app -> wss://xxxx.ngrok-free.app)
 * 
 * @param {string} httpUrl - Input URL (http://... or https://...)
 * @returns {string} WebSocket URL with ws:// or wss:// protocol
 */
export function convertHttpToWs(httpUrl) {
  if (!httpUrl || typeof httpUrl !== 'string') {
    return '';
  }

  const trimmed = httpUrl.trim().replace(/\/+$/, '');

  if (trimmed.startsWith('https://')) {
    return trimmed.replace(/^https:\/\//i, 'wss://');
  }

  if (trimmed.startsWith('http://')) {
    return trimmed.replace(/^http:\/\//i, 'ws://');
  }

  if (trimmed.startsWith('wss://') || trimmed.startsWith('ws://')) {
    return trimmed;
  }

  // Relative or protocol-less URL fallback
  if (typeof window !== 'undefined') {
    const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${proto}//${trimmed.replace(/^\/+/, '')}`;
  }

  return `wss://${trimmed}`;
}

/**
 * Constructs the fully-qualified WebSocket URL for real-time packet stream ingestion.
 * Automatically injects the operator Bearer session token if present.
 * 
 * @param {string|null} token - Optional Supabase JWT token
 * @param {string} endpointPath - WebSocket route path (default: '/ws/stream')
 * @returns {string} Completed WebSocket stream URL
 */
export function getWebSocketUrl(token = null, endpointPath = '/ws/stream') {
  // 1. Direct explicit WS URL override if configured
  const explicitWs = import.meta.env.VITE_WS_URL;
  if (explicitWs) {
    const cleanWs = explicitWs.trim().replace(/\/+$/, '');
    const separator = cleanWs.includes('?') ? '&' : '?';
    return token ? `${cleanWs}${separator}token=${encodeURIComponent(token)}` : cleanWs;
  }

  // 2. Convert Ngrok Sensor API URL dynamically to wss://
  const sensorHttpUrl = getSensorApiUrl();
  const wsBase = convertHttpToWs(sensorHttpUrl);
  const cleanPath = endpointPath.startsWith('/') ? endpointPath : `/${endpointPath}`;

  if (wsBase) {
    const fullWs = `${wsBase}${cleanPath}`;
    return token ? `${fullWs}?token=${encodeURIComponent(token)}` : fullWs;
  }

  // 3. Fallback to current browser host
  const proto = typeof window !== 'undefined' && window.location.protocol === 'https:' ? 'wss:' : 'ws:';
  const host = typeof window !== 'undefined' ? window.location.host : '127.0.0.1:8000';
  const fallbackWs = `${proto}//${host}${cleanPath}`;
  return token ? `${fallbackWs}?token=${encodeURIComponent(token)}` : fallbackWs;
}

/**
 * Enterprise API Client for SecureNet AI Sensor & Defense Services.
 * Routes requests dynamically through the Ngrok tunnel, handles Supabase Bearer Auth,
 * and bypasses Ngrok free tier browser warning interstitials.
 */
export class APIClient {
  getBaseUrl() {
    return getSensorApiUrl();
  }

  getWsUrl(token = null) {
    return getWebSocketUrl(token);
  }

  async request(endpoint, options = {}) {
    const baseUrl = this.getBaseUrl();
    const savedToken = typeof localStorage !== 'undefined' ? localStorage.getItem('securenet_token') : null;

    const headers = {
      'Content-Type': 'application/json',
      // CRITICAL: Bypasses Ngrok free tier interstitial redirect page
      'ngrok-skip-browser-warning': 'true',
      ...(options.headers || {})
    };

    if (savedToken && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${savedToken}`;
    }

    const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
    const targetUrl = `${baseUrl}${cleanEndpoint}`;

    const response = await fetch(targetUrl, {
      ...options,
      headers
    });

    if (!response.ok) {
      let errorDetail = `Sensor API Error: ${response.status} ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorDetail = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
        } else if (errorJson.message) {
          errorDetail = errorJson.message;
        }
      } catch (e) {
        // Response was not JSON
      }
      const error = new Error(errorDetail);
      error.status = response.status;
      throw error;
    }

    if (response.status === 204) return null;
    return await response.json();
  }

  // --------------------------------------------------------------------------
  // System Telemetry & Status
  // --------------------------------------------------------------------------
  async getSystemStatus() {
    return await this.request('/api/system/status');
  }

  // --------------------------------------------------------------------------
  // Network Topology Architecture (Preserved in full)
  // --------------------------------------------------------------------------
  async getTopology() {
    return await this.request('/api/topology');
  }

  async saveTopology(nodes, edges) {
    return await this.request('/api/topology', {
      method: 'POST',
      body: JSON.stringify({ nodes, edges })
    });
  }

  // --------------------------------------------------------------------------
  // Threats & Anomalies
  // --------------------------------------------------------------------------
  async getThreats(limit = 100) {
    return await this.request(`/api/threats?limit=${limit}`);
  }

  // --------------------------------------------------------------------------
  // Packet Inspection Telemetry
  // --------------------------------------------------------------------------
  async getPackets(limit = 100) {
    return await this.request(`/api/packets?limit=${limit}`);
  }

  // --------------------------------------------------------------------------
  // SOC Security Alerts
  // --------------------------------------------------------------------------
  async getAlerts(limit = 20) {
    return await this.request(`/api/alerts?limit=${limit}`);
  }

  // --------------------------------------------------------------------------
  // System Audit Logs
  // --------------------------------------------------------------------------
  async getSystemLogs(limit = 50) {
    return await this.request(`/api/system/logs?limit=${limit}`);
  }

  async getAuditLogs(limit = 50) {
    return await this.request(`/api/system/audit-logs?limit=${limit}`);
  }

  // --------------------------------------------------------------------------
  // Active Defense Firewall ACLs
  // --------------------------------------------------------------------------
  async getFirewallRules() {
    return await this.request('/api/firewall/rules');
  }

  async blockFirewallIp(ip_address, reason) {
    return await this.request('/api/firewall/block', {
      method: 'POST',
      body: JSON.stringify({ ip_address, reason })
    });
  }

  async unblockFirewallIp(ip_address) {
    return await this.request('/api/firewall/unblock', {
      method: 'POST',
      body: JSON.stringify({ ip_address })
    });
  }

  // --------------------------------------------------------------------------
  // SIEM Reports & Executive Exports
  // --------------------------------------------------------------------------
  async getReportSummary(range = 'daily') {
    return await this.request(`/api/reports/summary?range=${range}`);
  }

  async downloadReportPdf(range = 'daily') {
    const baseUrl = this.getBaseUrl();
    const savedToken = typeof localStorage !== 'undefined' ? localStorage.getItem('securenet_token') : null;
    const headers = { 'ngrok-skip-browser-warning': 'true' };
    if (savedToken) headers['Authorization'] = `Bearer ${savedToken}`;

    const response = await fetch(`${baseUrl}/api/reports/download?range=${range}`, { headers });
    if (!response.ok) {
      throw new Error(`Report Download Error: ${response.status} ${response.statusText}`);
    }
    return await response.blob();
  }

  async downloadReportCsv(range = 'daily') {
    const baseUrl = this.getBaseUrl();
    const savedToken = typeof localStorage !== 'undefined' ? localStorage.getItem('securenet_token') : null;
    const headers = { 'ngrok-skip-browser-warning': 'true' };
    if (savedToken) headers['Authorization'] = `Bearer ${savedToken}`;

    const response = await fetch(`${baseUrl}/api/reports/download/csv?range=${range}`, { headers });
    if (!response.ok) {
      throw new Error(`CSV Report Download Error: ${response.status} ${response.statusText}`);
    }
    return await response.blob();
  }

  // --------------------------------------------------------------------------
  // NIDS Sensor Telemetry Ingestion
  // --------------------------------------------------------------------------
  async getNidsEvents(limit = 50, event_type = null, severity = null) {
    let url = `/api/nids/events?limit=${limit}`;
    if (event_type) url += `&event_type=${encodeURIComponent(event_type)}`;
    if (severity !== null && severity !== undefined) url += `&severity=${severity}`;
    return await this.request(url);
  }

  async ingestNidsEvents(events, sensor_id = 'suricata-sensor-01') {
    return await this.request('/api/nids/events/ingest', {
      method: 'POST',
      body: JSON.stringify({ events, sensor_id })
    });
  }

  async uploadEveFile(file) {
    const baseUrl = this.getBaseUrl();
    const savedToken = typeof localStorage !== 'undefined' ? localStorage.getItem('securenet_token') : null;
    const headers = { 'ngrok-skip-browser-warning': 'true' };
    if (savedToken) headers['Authorization'] = `Bearer ${savedToken}`;

    const formData = new FormData();
    formData.append('file', file);

    const response = await fetch(`${baseUrl}/api/nids/eve/upload`, {
      method: 'POST',
      headers,
      body: formData
    });

    if (!response.ok) {
      const err = await response.json().catch(() => ({}));
      throw new Error(err.detail || 'Failed to upload EVE JSON file');
    }
    return await response.json();
  }

  async getNidsSensorStatus() {
    return await this.request('/api/nids/sensor/status');
  }

  // --------------------------------------------------------------------------
  // Threat Detections
  // --------------------------------------------------------------------------
  async getThreatDetections(limit = 50, status = null, category = null) {
    let url = `/api/threats/detections?limit=${limit}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    if (category) url += `&category=${encodeURIComponent(category)}`;
    return await this.request(url);
  }

  async updateThreatStatus(threatId, status, notes = null) {
    return await this.request(`/api/threats/${threatId}/status`, {
      method: 'PATCH',
      body: JSON.stringify({ status, notes })
    });
  }

  // --------------------------------------------------------------------------
  // AI Behavioral Analysis
  // --------------------------------------------------------------------------
  async getAiModelStatus() {
    return await this.request('/api/ai/status');
  }

  async analyzeHostAi(target_ip) {
    return await this.request('/api/ai/analyze-host', {
      method: 'POST',
      body: JSON.stringify({ target_ip })
    });
  }

  // --------------------------------------------------------------------------
  // Risk Scoring
  // --------------------------------------------------------------------------
  async getRiskAssessments(limit = 30) {
    return await this.request(`/api/risk/assessments?limit=${limit}`);
  }

  // --------------------------------------------------------------------------
  // Automated Response Centre
  // --------------------------------------------------------------------------
  async getResponsePolicies() {
    return await this.request('/api/response/policies');
  }

  async saveResponsePolicy(policy) {
    return await this.request('/api/response/policies', {
      method: 'POST',
      body: JSON.stringify(policy)
    });
  }

  async getResponseActions(limit = 50, status = null) {
    let url = `/api/response/actions?limit=${limit}`;
    if (status) url += `&status=${encodeURIComponent(status)}`;
    return await this.request(url);
  }

  async approveResponseAction(actionId) {
    return await this.request(`/api/response/actions/${actionId}/approve`, {
      method: 'POST'
    });
  }

  async rejectResponseAction(actionId) {
    return await this.request(`/api/response/actions/${actionId}/reject`, {
      method: 'POST'
    });
  }

  async rollbackResponseAction(actionId) {
    return await this.request(`/api/response/actions/${actionId}/rollback`, {
      method: 'POST'
    });
  }

  async executeManualResponse(target_ip, reason, duration_seconds = 3600) {
    return await this.request('/api/response/execute-manual', {
      method: 'POST',
      body: JSON.stringify({ target_ip, reason, duration_seconds })
    });
  }

  async getResponseSystemConfig() {
    return await this.request('/api/response/system-config');
  }

  async updateResponseSystemConfig(configs) {
    return await this.request('/api/response/system-config', {
      method: 'POST',
      body: JSON.stringify({ configs })
    });
  }

  // --------------------------------------------------------------------------
  // Sensor Controls & Test Harness
  // --------------------------------------------------------------------------
  async setFilterMode(mode) {
    return await this.request('/api/system/filter-mode', {
      method: 'POST',
      body: JSON.stringify({ mode })
    });
  }

  async resetSession(purgeDb = true) {
    return await this.request(`/api/system/reset-session?purge_db=${purgeDb}`, {
      method: 'POST'
    });
  }
}

export const apiClient = new APIClient();
export default apiClient;
