const BASE_URL = import.meta.env.VITE_API_BASE_URL || '';
const WS_URL_ENV = import.meta.env.VITE_WS_URL || '';

class APIClient {
  getBaseUrl() {
    return BASE_URL;
  }

  getWsUrl(token = null) {
    if (WS_URL_ENV) {
      const separator = WS_URL_ENV.includes('?') ? '&' : '?';
      return token ? `${WS_URL_ENV}${separator}token=${token}` : WS_URL_ENV;
    }
    const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
    const host = window.location.host || '127.0.0.1:8000';
    return `${protocol}//${host}/ws/stream${token ? `?token=${token}` : ''}`;
  }

  async request(endpoint, options = {}) {
    const savedToken = localStorage.getItem('securenet_token');
    const headers = {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    };
    if (savedToken && !headers['Authorization']) {
      headers['Authorization'] = `Bearer ${savedToken}`;
    }

    const response = await fetch(`${BASE_URL}${endpoint}`, {
      ...options,
      headers
    });

    if (!response.ok) {
      let errorDetail = `API Error: ${response.status} ${response.statusText}`;
      try {
        const errorJson = await response.json();
        if (errorJson.detail) {
          errorDetail = typeof errorJson.detail === 'string' ? errorJson.detail : JSON.stringify(errorJson.detail);
        } else if (errorJson.message) {
          errorDetail = errorJson.message;
        }
      } catch (e) {
        // Response wasn't JSON
      }
      const error = new Error(errorDetail);
      error.status = response.status;
      throw error;
    }

    if (response.status === 204) return null;
    return await response.json();
  }

  // System Status & Telemetry
  async getSystemStatus() {
    return await this.request('/api/system/status');
  }

  // Topology Architecture
  async getTopology() {
    return await this.request('/api/topology');
  }

  async saveTopology(nodes, edges) {
    return await this.request('/api/topology', {
      method: 'POST',
      body: JSON.stringify({ nodes, edges })
    });
  }

  // Threats & Anomalies
  async getThreats(limit = 100) {
    return await this.request(`/api/threats?limit=${limit}`);
  }

  // Packets
  async getPackets(limit = 100) {
    return await this.request(`/api/packets?limit=${limit}`);
  }

  // Alerts
  async getAlerts(limit = 20) {
    return await this.request(`/api/alerts?limit=${limit}`);
  }

  // System Logs
  async getSystemLogs(limit = 50) {
    return await this.request(`/api/system/logs?limit=${limit}`);
  }

  // Active Defense Firewall
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

  // Reports
  async getReportSummary(range = 'daily') {
    return await this.request(`/api/reports/summary?range=${range}`);
  }

  async downloadReportPdf(range = 'daily') {
    const savedToken = localStorage.getItem('securenet_token');
    const headers = {};
    if (savedToken) {
      headers['Authorization'] = `Bearer ${savedToken}`;
    }

    const response = await fetch(`${BASE_URL}/api/reports/download?range=${range}`, {
      headers
    });

    if (!response.ok) {
      throw new Error(`Report Download Error: ${response.status} ${response.statusText}`);
    }

    return await response.blob();
  }

  // Controls & Test Harness
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

  async injectThreat(threat_type, target_ip = '10.0.1.10', attacker_ip = '198.51.100.77') {
    return await this.request('/api/test/inject-threat', {
      method: 'POST',
      body: JSON.stringify({ threat_type, target_ip, attacker_ip })
    });
  }
}

export const apiClient = new APIClient();
