import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef
} from 'react';

import { apiClient, getWebSocketUrl } from '../utils/api';

const SOCContext = createContext(null);

export const SOCProvider = ({ children }) => {
  // ============================================================
  // SYSTEM TELEMETRY STATE
  // ============================================================

  const [status, setStatus] = useState(null);
  const [isBackendOffline, setIsBackendOffline] = useState(false);
  const [isInitializing, setIsInitializing] = useState(true);

  // Connection State:
  // 'Live' | 'Connecting' | 'Reconnecting' | 'Offline' | 'Paused'
  const [connectionState, setConnectionState] = useState('Offline');
  const [isPaused, setIsPaused] = useState(false);

  // ============================================================
  // TIME / LAST UPDATE
  // ============================================================

  const [lastUpdatedTimestamp, setLastUpdatedTimestamp] = useState(
    Date.now()
  );

  const [secondsAgo, setSecondsAgo] = useState(0);

  // ============================================================
  // LIVE DATA
  // ============================================================

  const [livePackets, setLivePackets] = useState([]);
  const [threats, setThreats] = useState([]);
  const [alerts, setAlerts] = useState([]);
  const [firewallRules, setFirewallRules] = useState([]);
  const [systemLogs, setSystemLogs] = useState([]);
  const [responseActions, setResponseActions] = useState([]);
  const [riskAssessments, setRiskAssessments] = useState([]);
  const [responseConfig, setResponseConfig] = useState(null);
  const [aiModelStatus, setAiModelStatus] = useState(null);


  // ============================================================
  // TOASTS
  // ============================================================

  const [toasts, setToasts] = useState([]);

  // ============================================================
  // ACTIVE PACKET MODAL
  // ============================================================

  const [activeModalPacket, setActiveModalPacket] = useState(null);

  // ============================================================
  // 60-SECOND ROLLING STATISTICS
  // ============================================================

  const generateInitialRollingStats = () => {
    const now = Date.now();
    const arr = [];
    for (let i = 59; i >= 0; i--) {
      const t = new Date(now - i * 1000);
      arr.push({
        time: t.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
        timestamp: t.toISOString(),
        pps: 0,
        inboundMbps: 0.0,
        outboundMbps: 0.0
      });
    }
    return arr;
  };

  const [rollingStats, setRollingStats] = useState(generateInitialRollingStats);

  // ============================================================
  // PROTOCOL COUNTERS
  // ============================================================

  const [protocolCounts, setProtocolCounts] = useState({
    TCP: 0,
    UDP: 0,
    HTTP: 0,
    HTTPS: 0,
    DNS: 0,
    ICMP: 0,
    OTHER: 0
  });

  // ============================================================
  // WEBSOCKET / RATE TRACKERS
  // ============================================================

  const wsRef = useRef(null);
  const reconnectTimeoutRef = useRef(null);
  const reconnectAttemptRef = useRef(0);
  const toastCounterRef = useRef(0);
  const packetBufferRef = useRef([]);
  const protocolDeltaRef = useRef({});
  const lastHeartbeatTimeRef = useRef(0);

  const packetsThisSecondRef = useRef(0);
  const inboundBytesThisSecondRef = useRef(0);
  const outboundBytesThisSecondRef = useRef(0);
  const lastPacketCounterRef = useRef(0);
  const firewallRulesRef = useRef(firewallRules);
  useEffect(() => {
    firewallRulesRef.current = firewallRules;
  }, [firewallRules]);

  const addToast = useCallback((toast) => {
    toastCounterRef.current += 1;
    const id = `toast-${Date.now()}-${toastCounterRef.current}`;

    const newToast = {
      id,
      timestamp: new Date().toLocaleTimeString(),
      ...toast
    };

    setToasts((prev) => [
      newToast,
      ...prev.slice(0, 1)
    ]);

    setTimeout(() => {
      setToasts((prev) =>
        prev.filter((t) => t.id !== id)
      );
    }, 5000);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) =>
      prev.filter((t) => t.id !== id)
    );
  }, []);

  // Batch flush packets and protocol counters every 200ms (eliminates React UI thread lag)
  useEffect(() => {
    const flushInterval = setInterval(() => {
      if (packetBufferRef.current.length > 0) {
        const batch = packetBufferRef.current;
        packetBufferRef.current = [];
        setLivePackets((prev) => [...batch.reverse(), ...prev].slice(0, 20));
      }

      const deltas = protocolDeltaRef.current;
      const protoKeys = Object.keys(deltas);
      if (protoKeys.length > 0) {
        protocolDeltaRef.current = {};
        setProtocolCounts((prev) => {
          const next = { ...prev };
          for (const k of protoKeys) {
            next[k] = (next[k] || 0) + deltas[k];
          }
          return next;
        });
      }
    }, 200);
    return () => clearInterval(flushInterval);
  }, []);

  // ============================================================
  // 1. TELEMETRY STATUS POLLER
  // ============================================================

  const fetchTelemetry = useCallback(async () => {
    try {
      const data = await apiClient.getSystemStatus();

      setStatus(data);
      setIsBackendOffline(false);
      setIsInitializing(false);

      setLastUpdatedTimestamp(Date.now());
      setSecondsAgo(0);

      // Hydrate server-calculated 60s continuous rate series
      if (data?.rolling_stats && Array.isArray(data.rolling_stats) && data.rolling_stats.length > 0) {
        setRollingStats((prev) => {
          if (data.rolling_stats.length >= 60) {
            return data.rolling_stats.slice(-60);
          }
          const missingCount = 60 - data.rolling_stats.length;
          return [...prev.slice(0, missingCount), ...data.rolling_stats];
        });
      }

      // Calculate packets per second from packet counter
      const totalPackets =
        data.total_packets_captured ??
        data.packet_counter ??
        0;

      if (lastPacketCounterRef.current > 0) {
        const delta = Math.max(
          0,
          totalPackets - lastPacketCounterRef.current
        );

        if (
          delta > 0 &&
          packetsThisSecondRef.current === 0
        ) {
          packetsThisSecondRef.current = delta;
        }
      }

      lastPacketCounterRef.current = totalPackets;
    } catch (err) {
      console.error(
        '[SecureNet AI] Failed to fetch telemetry:',
        err
      );

      setIsBackendOffline(true);
      setIsInitializing(false);

      if (connectionState !== 'Reconnecting') {
        setConnectionState('Offline');
      }
    }
  }, [connectionState]);

  // Hydrate initial system telemetry once on mount; real-time updates flow strictly via WebSocket events
  useEffect(() => {
    fetchTelemetry();
  }, [fetchTelemetry]);

  // ============================================================
  // 1 SECOND CLOCK + ROLLING STATISTICS
  // ============================================================

  useEffect(() => {
    const clockTimer = setInterval(() => {
      setSecondsAgo((prev) => prev + 1);

      // If server RATE_HEARTBEAT is active, rely strictly on server ground truth
      if (Date.now() - lastHeartbeatTimeRef.current > 2000) {
        const now = new Date();
        const timeLabel = now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        const currentPps = packetsThisSecondRef.current;
        const inboundMbps = Number(
          ((inboundBytesThisSecondRef.current * 8) / 1_000_000).toFixed(2)
        );
        const outboundMbps = Number(
          ((outboundBytesThisSecondRef.current * 8) / 1_000_000).toFixed(2)
        );

        // Reset counters
        packetsThisSecondRef.current = 0;
        inboundBytesThisSecondRef.current = 0;
        outboundBytesThisSecondRef.current = 0;

        setRollingStats((prev) => {
          const nextPoint = {
            time: timeLabel,
            timestamp: now.toISOString(),
            pps: currentPps,
            inboundMbps,
            outboundMbps
          };
          return [...prev.slice(-59), nextPoint];
        });
      }
    }, 1000);

    return () => {
      clearInterval(clockTimer);
    };
  }, []);

  // ============================================================
  // 2. FETCH PERSISTED DATABASE DATA
  // ============================================================

  const refreshPersistedData = useCallback(async () => {
    const savedToken =
      localStorage.getItem('securenet_token');

    if (!savedToken) {
      return;
    }

    try {
      const [
        threatsData,
        fwData,
        alertsData,
        logsData,
        packetsData,
        actionsData,
        cfgData,
        aiData,
        risksData
      ] = await Promise.allSettled([
        apiClient.getThreats(100),
        apiClient.getFirewallRules(),
        apiClient.getAlerts(20),
        apiClient.getSystemLogs(50),
        apiClient.getPackets(100),
        apiClient.getResponseActions(50),
        apiClient.getResponseSystemConfig(),
        apiClient.getAiModelStatus(),
        apiClient.getRiskAssessments(30)
      ]);

      if (threatsData.status === 'fulfilled' && threatsData.value) {
        setThreats(threatsData.value);
      }

      if (fwData.status === 'fulfilled' && fwData.value) {
        setFirewallRules(fwData.value);
      }

      if (alertsData.status === 'fulfilled' && alertsData.value) {
        setAlerts(alertsData.value);
      }

      if (logsData.status === 'fulfilled' && logsData.value) {
        setSystemLogs(logsData.value);
      }

      if (packetsData.status === 'fulfilled' && packetsData.value) {
        setLivePackets((prev) =>
          prev.length === 0 ? packetsData.value : prev
        );
      }

      if (actionsData.status === 'fulfilled' && actionsData.value) {
        setResponseActions(actionsData.value);
      }

      if (cfgData.status === 'fulfilled' && cfgData.value) {
        setResponseConfig(cfgData.value);
      }

      if (aiData.status === 'fulfilled' && aiData.value) {
        setAiModelStatus(aiData.value);
      }

      if (risksData.status === 'fulfilled' && risksData.value) {
        setRiskAssessments(risksData.value);
      }
    } catch (error) {
      console.error(
        '[SecureNet AI] Failed to refresh persisted data:',
        error
      );

    }
  }, []);

  useEffect(() => {
    refreshPersistedData();
  }, [refreshPersistedData]);

  // ============================================================
  // 3. WEBSOCKET REAL-TIME STREAM
  // ============================================================

  const connectWebSocket = useCallback(() => {
    // ----------------------------------------------------------
    // PAUSED
    // ----------------------------------------------------------

    if (isPaused) {
      setConnectionState('Paused');
      return;
    }

    // ----------------------------------------------------------
    // ALREADY CONNECTED / CONNECTING
    // ----------------------------------------------------------

    if (
      wsRef.current &&
      (
        wsRef.current.readyState === WebSocket.OPEN ||
        wsRef.current.readyState === WebSocket.CONNECTING
      )
    ) {
      return;
    }

    // ----------------------------------------------------------
    // CONNECTION STATE
    // ----------------------------------------------------------

    setConnectionState(
      reconnectAttemptRef.current > 0
        ? 'Reconnecting'
        : 'Connecting'
    );

    // ----------------------------------------------------------
    // WEBSOCKET URL
    //
    // Frontend:
    // http://localhost:5173
    //
    // Backend:
    // http://127.0.0.1:8000
    //
    // WebSocket:
    // ws://localhost:8000/ws/stream
    // ----------------------------------------------------------

    const savedToken = typeof localStorage !== 'undefined' ? localStorage.getItem('securenet_token') : null;
    const wsUrl = getWebSocketUrl(savedToken, '/ws/stream');

    console.log(
      '[SecureNet AI] Connecting WebSocket:',
      wsUrl
    );

    // ----------------------------------------------------------
    // CREATE NATIVE BROWSER WEBSOCKET
    // ----------------------------------------------------------

    const ws = new WebSocket(wsUrl);

    // ----------------------------------------------------------
    // ON MESSAGE
    // ----------------------------------------------------------

    ws.onmessage = (event) => {
      try {
        const msg = JSON.parse(event.data);

        // ------------------------------------------------------
        // SESSION RESET
        // ------------------------------------------------------

        if (msg.type === 'SESSION_RESET') {
          setLivePackets([]);
          setToasts([]);
          setRollingStats([]);

          setProtocolCounts({
            TCP: 0,
            UDP: 0,
            HTTP: 0,
            HTTPS: 0,
            DNS: 0,
            ICMP: 0,
            OTHER: 0
          });

          fetchTelemetry();
          refreshPersistedData();

          return;
        }

        // ------------------------------------------------------
        // SERVER RATE HEARTBEAT (1-Second Continuous Updates)
        // ------------------------------------------------------
        if (msg.type === 'RATE_HEARTBEAT') {
          lastHeartbeatTimeRef.current = Date.now();
          setSecondsAgo(0);

          // Instant telemetry synchronization on millisecond 0 (no HTTP delay)
          if (msg.total_packets !== undefined) {
            setStatus((prev) => ({
              ...prev,
              total_packets_captured: msg.total_packets,
              packet_counter: msg.total_packets,
              total_threats_detected: msg.total_threats ?? prev?.total_threats_detected ?? 0,
              threat_counter: msg.total_threats ?? prev?.threat_counter ?? 0,
              critical_threats_detected: msg.critical_threats ?? prev?.critical_threats_detected ?? 0,
              current_pps: msg.pps ?? prev?.current_pps ?? 0,
              current_inbound_mbps: msg.inboundMbps ?? prev?.current_inbound_mbps ?? 0,
              current_outbound_mbps: msg.outboundMbps ?? prev?.current_outbound_mbps ?? 0
            }));
          }

          setRollingStats((prev) => {
            const nextPoint = {
              time: msg.time || new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }),
              timestamp: msg.timestamp || new Date().toISOString(),
              pps: msg.pps || 0,
              inboundMbps: msg.inboundMbps || 0.0,
              outboundMbps: msg.outboundMbps || 0.0
            };
            return [...prev.slice(-59), nextPoint];
          });
          return;
        }

        // ------------------------------------------------------
        // LIVE PACKET
        // ------------------------------------------------------

        if (msg.src_ip || msg.protocol) {
          setSecondsAgo(0);
          packetsThisSecondRef.current += 1;

          const pktLength =
            msg.length || 64;

          // ----------------------------------------------------
          // INBOUND / OUTBOUND
          // ----------------------------------------------------

          if (msg.direction === 'outbound') {
            outboundBytesThisSecondRef.current +=
              pktLength;
          } else {
            inboundBytesThisSecondRef.current +=
              pktLength;
          }

          // Buffer packet for smooth 200ms batch UI update
          packetBufferRef.current.push(msg);

          // ----------------------------------------------------
          // PROTOCOL COUNTER (BATTERED FOR 0ms UI THREAD LAG)
          // ----------------------------------------------------

          const proto =
            (msg.protocol || 'OTHER').toUpperCase();

          protocolDeltaRef.current[proto] = (protocolDeltaRef.current[proto] || 0) + 1;

          // ----------------------------------------------------
          // THREAT DETECTION
          // ----------------------------------------------------

          if (msg.is_threat) {
            const rawSev = (msg.severity || 'Medium').toLowerCase();
            const srcIp = msg.src_ip || msg.source_ip;

            // Check if IP is already restricted in active firewall rules
            const isAlreadyBlocked = srcIp && firewallRulesRef.current?.some(
              (r) => r.ip_address === srcIp && r.is_active
            );

            // User requirement: "if a threat can be aurtoblocked then dont show it in threat and dont just put in some fake notification about threats"
            const isAutoBlockedOrEligible =
              isAlreadyBlocked ||
              msg.auto_blocked ||
              msg.can_be_autoblocked ||
              msg.response_status === 'EXECUTED' ||
              rawSev === 'low' ||
              rawSev === 'medium' ||
              (msg.risk_score !== undefined && msg.risk_score !== null && msg.risk_score < 65);

            if (!isAutoBlockedOrEligible && srcIp && srcIp !== 'Unknown IP') {
              // Only pop up high-priority toasts for Critical and High severity intrusions requiring operator action
              if (rawSev === 'critical' || rawSev === 'high') {
                addToast({
                  type: 'threat',
                  title:
                    msg.threat_type ||
                    'Malicious Intrusion Detected',
                  severity: rawSev,
                  description:
                    `${srcIp} targeted ` +
                    `${msg.dst_ip}:` +
                    `${msg.dst_port || 'n/a'} ` +
                    `via ${msg.protocol}.`,
                  source_ip: srcIp,
                  packet: msg
                });
              }

              // Add threat to threat list ONLY if it cannot be auto-blocked and is not already blocked
              setThreats((prev) => {
                const alreadyExists =
                  prev.some(
                    (t) =>
                      t.id === msg.id ||
                      (
                        t.src_ip === srcIp &&
                        t.threat_type === msg.threat_type
                      )
                  );

                if (alreadyExists) {
                  return prev;
                }

                return [
                  msg,
                  ...prev
                ];
              });
            }

            // REFRESH TELEMETRY
            fetchTelemetry();
          }
        }
      } catch (error) {
        console.error(
          '[SecureNet AI] WebSocket message parsing error:',
          error
        );
      }
    };

    // ----------------------------------------------------------
    // ON OPEN
    // ----------------------------------------------------------

    ws.onopen = () => {
      console.log(
        '[SecureNet AI] WebSocket connected successfully'
      );

      setConnectionState('Live');

      reconnectAttemptRef.current = 0;

      setIsBackendOffline(false);
    };

    // ----------------------------------------------------------
    // ON CLOSE
    // ----------------------------------------------------------

    ws.onclose = (event) => {
      console.log(
        '[SecureNet AI] WebSocket disconnected:',
        event.code,
        event.reason
      );

      wsRef.current = null;

      if (isPaused) {
        setConnectionState('Paused');
        return;
      }

      setConnectionState('Reconnecting');

      const delay = Math.min(
        1000 *
          Math.pow(
            2,
            reconnectAttemptRef.current
          ),
        10000
      );

      reconnectAttemptRef.current += 1;

      if (reconnectTimeoutRef.current) {
        clearTimeout(
          reconnectTimeoutRef.current
        );
      }

      reconnectTimeoutRef.current =
        setTimeout(() => {
          connectWebSocket();
        }, delay);
    };

    // ----------------------------------------------------------
    // ON ERROR
    // ----------------------------------------------------------

    ws.onerror = (error) => {
      console.error(
        '[SecureNet AI] WebSocket error:',
        error
      );
    };

    // ----------------------------------------------------------
    // SAVE WEBSOCKET REFERENCE
    // ----------------------------------------------------------

    wsRef.current = ws;

  }, [
    addToast,
    fetchTelemetry,
    isPaused,
    refreshPersistedData
  ]);

  // ============================================================
  // START / STOP WEBSOCKET
  // ============================================================

  useEffect(() => {
    const savedToken =
      localStorage.getItem('securenet_token');

    if (savedToken && !isPaused) {
      connectWebSocket();
    } else if (isPaused) {
      setConnectionState('Paused');

      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    }

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(
          reconnectTimeoutRef.current
        );

        reconnectTimeoutRef.current = null;
      }

      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [
    connectWebSocket,
    isPaused
  ]);

  // ============================================================
  // 4. FIREWALL ACTIONS
  // ============================================================

  const handleBlockIp = async (
    ipAddress,
    reason = 'Operator Enforcement'
  ) => {
    if (!ipAddress || ipAddress === 'Unknown IP') return;

    // 1. Optimistic local state update for instantaneous UI feedback
    setFirewallRules((prev) => {
      if (prev.some((r) => r.ip_address === ipAddress && r.is_active)) return prev;
      return [
        {
          id: Date.now(),
          ip_address: ipAddress,
          reason,
          blocked_by: 'OPERATOR',
          timestamp: new Date().toISOString(),
          is_active: true
        },
        ...prev
      ];
    });

    // 2. Optimistic removal of threats matching this IP
    setThreats((prev) => prev.filter((t) => t.src_ip !== ipAddress && t.source_ip !== ipAddress));

    // 3. Fast backend call
    const result = await apiClient.blockFirewallIp(ipAddress, reason);

    // 4. Non-intrusive system notification (NOT a fake threat alert)
    addToast({
      type: 'system',
      title: 'Firewall Rule Enforced',
      severity: 'success',
      description: `Drop policy active for ${ipAddress}.`
    });

    // 5. Non-blocking background sync
    Promise.allSettled([
      apiClient.getFirewallRules().then((rules) => rules && setFirewallRules(rules)),
      fetchTelemetry()
    ]).catch(() => {});

    return result;
  };

  const handleResolveThreat = async (
    threat,
    reason = 'Operator Threat Mitigation'
  ) => {
    const ipAddress = threat.src_ip || threat.source_ip;
    if (!ipAddress || ipAddress === 'Unknown IP') return;
    const threatId = threat.id;

    // 1. Optimistic removal from threats list instantly
    setThreats((prev) => prev.filter((t) => (t.id !== threatId && t.src_ip !== ipAddress)));

    // 2. Optimistic firewall rule addition
    setFirewallRules((prev) => {
      if (prev.some((r) => r.ip_address === ipAddress && r.is_active)) return prev;
      return [
        {
          id: Date.now(),
          ip_address: ipAddress,
          reason: threat.threat_type || reason,
          blocked_by: 'OPERATOR_RESOLVE',
          timestamp: new Date().toISOString(),
          is_active: true
        },
        ...prev
      ];
    });

    // 3. Fast call to resolve endpoint
    let result;
    try {
      result = await apiClient.resolveThreat(ipAddress, threat.threat_type || reason, typeof threatId === 'number' ? threatId : null);
    } catch {
      result = await apiClient.blockFirewallIp(ipAddress, threat.threat_type || reason);
    }

    // 4. Clean system toast feedback
    addToast({
      type: 'system',
      title: 'Threat Mitigated & Blocked',
      severity: 'success',
      description: `Drop rule enforced against ${ipAddress}. Threat mitigated.`
    });

    // 5. Background sync
    Promise.allSettled([
      apiClient.getFirewallRules().then((rules) => rules && setFirewallRules(rules)),
      fetchTelemetry()
    ]).catch(() => {});

    return result;
  };

  const handleUnblockIp = async (
    ipAddress
  ) => {
    if (!ipAddress) return;

    // Optimistic removal from firewall rules
    setFirewallRules((prev) => prev.filter((r) => r.ip_address !== ipAddress));

    const result = await apiClient.unblockFirewallIp(ipAddress);

    addToast({
      type: 'system',
      title: 'Firewall Rule Revoked',
      severity: 'info',
      description: `Drop rule removed for ${ipAddress}.`
    });

    Promise.allSettled([
      apiClient.getFirewallRules().then((rules) => rules && setFirewallRules(rules)),
      fetchTelemetry()
    ]).catch(() => {});

    return result;
  };

  // ============================================================
  // 5. FILTER MODE
  // ============================================================

  const handleSetFilterMode = async (
    mode
  ) => {
    const result =
      await apiClient.setFilterMode(mode);

    fetchTelemetry();

    return result;
  };

  // ============================================================
  // 6. RESET SESSION
  // ============================================================

  const handleResetSession = async (
    purgeDb = true
  ) => {
    const result =
      await apiClient.resetSession(
        purgeDb
      );

    setLivePackets([]);
    setToasts([]);
    setRollingStats([]);

    setProtocolCounts({
      TCP: 0,
      UDP: 0,
      HTTP: 0,
      HTTPS: 0,
      DNS: 0,
      ICMP: 0,
      OTHER: 0
    });

    fetchTelemetry();
    refreshPersistedData();

    return result;
  };

  // ============================================================
  // 7. RETRY CONNECTION
  // ============================================================

  const retryConnection = () => {
    reconnectAttemptRef.current = 0;

    fetchTelemetry();

    connectWebSocket();

    refreshPersistedData();
  };

  // ============================================================
  // CONTEXT VALUE
  // ============================================================

  const value = {
    // System
    status,
    isBackendOffline,
    isInitializing,

    // Connection
    connectionState,
    isPaused,
    setIsPaused,

    // Time
    lastUpdatedTimestamp,
    secondsAgo,

    // Data
    livePackets,
    threats,
    alerts,
    firewallRules,
    systemLogs,
    responseActions,
    riskAssessments,
    responseConfig,
    aiModelStatus,

    // Toasts
    toasts,
    addToast,
    removeToast,

    // Modal
    activeModalPacket,
    setActiveModalPacket,

    // Charts
    rollingStats,
    protocolCounts,

    // Actions
    blockIp: handleBlockIp,
    resolveThreat: handleResolveThreat,
    unblockIp: handleUnblockIp,
    setFilterMode: handleSetFilterMode,
    resetSession: handleResetSession,
    approveAction: async (id) => {
      const res = await apiClient.approveResponseAction(id);
      await refreshPersistedData();
      return res;
    },
    rejectAction: async (id) => {
      const res = await apiClient.rejectResponseAction(id);
      await refreshPersistedData();
      return res;
    },
    rollbackAction: async (id) => {
      const res = await apiClient.rollbackResponseAction(id);
      await refreshPersistedData();
      return res;
    },
    executeManualResponse: async (target_ip, reason, duration = 3600) => {
      const res = await apiClient.executeManualResponse(target_ip, reason, duration);
      await refreshPersistedData();
      return res;
    },
    updateResponseConfig: async (configs) => {
      const res = await apiClient.updateResponseSystemConfig(configs);
      await refreshPersistedData();
      return res;
    },

    // Refresh
    refreshPersistedData,
    fetchTelemetry,
    retryConnection
  };


  // ============================================================
  // PROVIDER
  // ============================================================

  return (
    <SOCContext.Provider value={value}>
      {children}
    </SOCContext.Provider>
  );
};

// ============================================================
// useSOC HOOK
// ============================================================

export const useSOC = () => {
  const context = useContext(SOCContext);

  if (!context) {
    throw new Error(
      'useSOC must be used within a SOCProvider'
    );
  }

  return context;
};