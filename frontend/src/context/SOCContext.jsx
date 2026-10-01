import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef
} from 'react';

import { apiClient } from '../api/client';

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

  const [rollingStats, setRollingStats] = useState([]);

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

  const packetsThisSecondRef = useRef(0);
  const inboundBytesThisSecondRef = useRef(0);
  const outboundBytesThisSecondRef = useRef(0);

  const lastPacketCounterRef = useRef(0);

  // ============================================================
  // TOAST MANAGEMENT
  // ============================================================

  const addToast = useCallback((toast) => {
    const id =
      Date.now() +
      Math.random().toString(36).substring(2, 5);

    const newToast = {
      id,
      timestamp: new Date().toLocaleTimeString(),
      ...toast
    };

    setToasts((prev) => [
      newToast,
      ...prev.slice(0, 4)
    ]);

    setTimeout(() => {
      setToasts((prev) =>
        prev.filter((t) => t.id !== id)
      );
    }, 7000);
  }, []);

  const removeToast = useCallback((id) => {
    setToasts((prev) =>
      prev.filter((t) => t.id !== id)
    );
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

  // ============================================================
  // INITIAL LOAD + 1 SECOND TELEMETRY INTERVAL
  // ============================================================

  useEffect(() => {
    fetchTelemetry();

    const interval = setInterval(() => {
      fetchTelemetry();
    }, 1000);

    return () => {
      clearInterval(interval);
    };
  }, [fetchTelemetry]);

  // ============================================================
  // 1 SECOND CLOCK + ROLLING STATISTICS
  // ============================================================

  useEffect(() => {
    const clockTimer = setInterval(() => {
      setSecondsAgo((prev) => prev + 1);

      const now = new Date();

      const timeLabel =
        now.toLocaleTimeString();

      const currentPps =
        packetsThisSecondRef.current;

      const inboundMbps = Number(
        (
          (inboundBytesThisSecondRef.current * 8) /
          1_000_000
        ).toFixed(2)
      );

      const outboundMbps = Number(
        (
          (outboundBytesThisSecondRef.current * 8) /
          1_000_000
        ).toFixed(2)
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

        const updated = [
          ...prev,
          nextPoint
        ];

        return updated.slice(-60);
      });
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
        packetsData
      ] = await Promise.allSettled([
        apiClient.getThreats(100),
        apiClient.getFirewallRules(),
        apiClient.getAlerts(20),
        apiClient.getSystemLogs(50),
        apiClient.getPackets(100)
      ]);

      if (
        threatsData.status === 'fulfilled' &&
        threatsData.value
      ) {
        setThreats(threatsData.value);
      }

      if (
        fwData.status === 'fulfilled' &&
        fwData.value
      ) {
        setFirewallRules(fwData.value);
      }

      if (
        alertsData.status === 'fulfilled' &&
        alertsData.value
      ) {
        setAlerts(alertsData.value);
      }

      if (
        logsData.status === 'fulfilled' &&
        logsData.value
      ) {
        setSystemLogs(logsData.value);
      }

      if (
        packetsData.status === 'fulfilled' &&
        packetsData.value
      ) {
        setLivePackets((prev) =>
          prev.length === 0
            ? packetsData.value
            : prev
        );
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

    const wsUrl =
      `ws://${window.location.hostname}:8000/ws/stream`;

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

        console.log(
          '[SecureNet AI] WebSocket message:',
          msg
        );

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
        // LIVE PACKET
        // ------------------------------------------------------

        if (msg.src_ip || msg.protocol) {
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

          // ----------------------------------------------------
          // LIVE PACKET BUFFER
          // ----------------------------------------------------

          setLivePackets((prev) => [
            msg,
            ...prev.slice(0, 99)
          ]);

          // ----------------------------------------------------
          // PROTOCOL COUNTER
          // ----------------------------------------------------

          const proto =
            (msg.protocol || 'OTHER').toUpperCase();

          setProtocolCounts((prev) => ({
            ...prev,
            [proto]:
              (prev[proto] || 0) + 1
          }));

          // ----------------------------------------------------
          // THREAT DETECTION
          // ----------------------------------------------------

          if (msg.is_threat) {
            addToast({
              title:
                msg.threat_type ||
                'Malicious Intrusion Detected',

              severity:
                (
                  msg.severity ||
                  'Critical'
                ).toLowerCase(),

              description:
                `${msg.src_ip} targeted ` +
                `${msg.dst_ip}:` +
                `${msg.dst_port || 'n/a'} ` +
                `via ${msg.protocol}.`,

              source_ip: msg.src_ip,
              packet: msg
            });

            // -----------------------------------------------
            // ADD THREAT TO THREAT LIST
            // -----------------------------------------------

            setThreats((prev) => {
              const alreadyExists =
                prev.some(
                  (t) =>
                    t.id === msg.id ||
                    (
                      t.src_ip === msg.src_ip &&
                      t.threat_type ===
                        msg.threat_type
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

            // -----------------------------------------------
            // REFRESH TELEMETRY
            // -----------------------------------------------

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
    const result =
      await apiClient.blockFirewallIp(
        ipAddress,
        reason
      );

    await Promise.all([
      refreshPersistedData(),
      fetchTelemetry()
    ]);

    addToast({
      title: 'Firewall Rule Enforced',
      severity: 'info',
      description:
        `Drop policy active for ${ipAddress}.`
    });

    return result;
  };

  const handleUnblockIp = async (
    ipAddress
  ) => {
    const result =
      await apiClient.unblockFirewallIp(
        ipAddress
      );

    await Promise.all([
      refreshPersistedData(),
      fetchTelemetry()
    ]);

    addToast({
      title: 'Firewall Rule Revoked',
      severity: 'info',
      description:
        `Drop rule removed for ${ipAddress}.`
    });

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
    unblockIp: handleUnblockIp,
    setFilterMode: handleSetFilterMode,
    resetSession: handleResetSession,

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