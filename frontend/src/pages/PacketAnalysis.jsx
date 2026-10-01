import React, { useState, useEffect, useMemo } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import { apiClient } from '../api/client';
import {
  Binary,
  Filter,
  Search,
  FileCode,
  ShieldAlert,
  Flame,
  ArrowRight,
  RefreshCw,
  Lock
} from 'lucide-react';

const PacketAnalysis = () => {
  const { isEmployee } = useAuth();
  const { livePackets, blockIp } = useSOC();

  const [dbPackets, setDbPackets] = useState([]);
  const [isLoading, setIsLoading] = useState(true);
  const [selectedPkt, setSelectedPkt] = useState(null);
  const [filterProto, setFilterProto] = useState('ALL');
  const [searchQuery, setSearchQuery] = useState('');
  const [blockFeedback, setBlockFeedback] = useState(null);
  const [activeTab, setActiveTab] = useState('hex'); // 'hex' | 'ascii'

  // Fetch persisted packets from GET /api/packets
  const loadPackets = async () => {
    setIsLoading(true);
    try {
      const data = await apiClient.getPackets(100);
      setDbPackets(data || []);
    } catch (err) {
      console.error('Error fetching packets:', err);
    } finally {
      setIsLoading(false);
    }
  };

  useEffect(() => {
    loadPackets();
  }, []);

  // Deduplicated combined packets array
  const combinedPackets = useMemo(() => {
    const map = new Map();
    dbPackets.forEach((p) => map.set(p.id || `${p.src_ip}-${p.timestamp}`, p));
    livePackets.forEach((p) => map.set(p.id || `${p.src_ip}-${p.timestamp}`, p));
    return Array.from(map.values()).sort(
      (a, b) => new Date(b.timestamp || 0) - new Date(a.timestamp || 0)
    );
  }, [dbPackets, livePackets]);

  const filtered = useMemo(() => {
    return combinedPackets.filter((p) => {
      if (filterProto !== 'ALL') {
        const proto = (p.protocol || '').toUpperCase();
        if (proto !== filterProto) return false;
      }
      if (searchQuery) {
        const q = searchQuery.toLowerCase();
        return (
          (p.src_ip || '').toLowerCase().includes(q) ||
          (p.dst_ip || '').toLowerCase().includes(q) ||
          (p.protocol || '').toLowerCase().includes(q)
        );
      }
      return true;
    });
  }, [combinedPackets, filterProto, searchQuery]);

  const activePacket = selectedPkt || filtered[0] || null;

  const handleBlock = async (ip, reason) => {
    if (isEmployee || !ip) return;
    try {
      await blockIp(ip, reason || 'Packet Analysis Manual Block');
      setBlockFeedback(`Firewall drop rule enforced against ${ip}`);
      setTimeout(() => setBlockFeedback(null), 4000);
    } catch (e) {
      setBlockFeedback('Failed to enforce block.');
    }
  };

  const payloadHex = isEmployee ? '[REDACTED - EMPLOYEE CLEARANCE]' : (activePacket?.payload_hex || 'No hex dump available');
  const payloadAscii = isEmployee ? '[REDACTED - EMPLOYEE CLEARANCE]' : (activePacket?.payload_ascii || activePacket?.payload_snippet || 'No ASCII payload decoded');

  return (
    <div className="p-4 sm:p-6 space-y-6 max-w-7xl mx-auto">
      {/* Header */}
      <div className="soc-card rounded-2xl p-4 bg-white flex flex-col sm:flex-row sm:items-center justify-between gap-4 border border-slate-200 shadow-2xs">
        <div>
          <h1 className="text-base font-bold text-slate-900 font-sans flex items-center gap-2">
            <Binary className="w-5 h-5 text-blue-600" />
            Deep Packet Dissection &amp; Byte Analysis
          </h1>
          <p className="text-xs text-slate-500 font-mono mt-0.5">
            L2/L3/L4 Raw Octet Hex Dumps &bull; Decoded Layer-7 ASCII Payloads
          </p>
        </div>

        <button
          onClick={loadPackets}
          className="px-3 py-1.5 rounded-xl bg-white border border-slate-200 hover:bg-slate-50 text-slate-700 text-xs font-mono font-semibold transition-all flex items-center gap-1.5 shadow-2xs"
        >
          <RefreshCw className={`w-3.5 h-3.5 text-blue-600 ${isLoading ? 'animate-spin' : ''}`} />
          <span>Reload Buffer</span>
        </button>
      </div>

      {/* Filter Toolbar */}
      <div className="soc-card rounded-2xl p-3 bg-white flex flex-wrap items-center justify-between gap-3 border border-slate-200">
        <div className="flex items-center gap-1 text-xs font-mono">
          {['ALL', 'TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS'].map((proto) => (
            <button
              key={proto}
              onClick={() => setFilterProto(proto)}
              className={`px-3 py-1.5 rounded-lg font-bold transition-all ${
                filterProto === proto
                  ? 'bg-blue-50 text-blue-700 border border-blue-200'
                  : 'text-slate-600 hover:text-slate-900'
              }`}
            >
              {proto}
            </button>
          ))}
        </div>

        <div className="relative w-full sm:w-64">
          <Search className="w-3.5 h-3.5 text-slate-400 absolute left-3 top-1/2 -translate-y-1/2" />
          <input
            type="text"
            placeholder="Search Frame IP, Proto..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-8 pr-3 py-1.5 bg-slate-50 border border-slate-200 rounded-xl text-xs font-mono text-slate-800 focus:outline-none focus:border-blue-600"
          />
        </div>
      </div>

      {/* Split View Dissection Workspace */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6 items-start">
        {/* Left Column: Frame Buffer List (5 Cols) */}
        <div className="lg:col-span-5 soc-card rounded-2xl overflow-hidden max-h-[680px] flex flex-col bg-white border border-slate-200">
          <div className="p-3.5 border-b border-slate-100 bg-slate-50/60 flex items-center justify-between">
            <span className="text-xs font-bold text-slate-900 uppercase font-mono">
              Frame Buffer ({filtered.length})
            </span>
            <span className="text-[10px] text-slate-500 font-mono">Select frame to inspect</span>
          </div>

          <div className="overflow-y-auto divide-y divide-slate-100 flex-1">
            {filtered.length === 0 ? (
              <div className="p-8 text-center text-slate-400 text-xs font-mono">
                No frames match filter criteria.
              </div>
            ) : (
              filtered.map((pkt, idx) => {
                const isSelected = activePacket?.id === pkt.id || activePacket === pkt;
                return (
                  <div
                    key={pkt.id || idx}
                    onClick={() => setSelectedPkt(pkt)}
                    className={`p-3 text-xs font-mono cursor-pointer transition-all ${
                      isSelected
                        ? 'bg-blue-50/90 border-l-4 border-l-blue-600'
                        : 'hover:bg-slate-50'
                    }`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <span className="font-bold text-slate-500">#{pkt.id || idx + 1}</span>
                      <span className="text-[10px] text-slate-400">
                        {pkt.timestamp ? new Date(pkt.timestamp).toLocaleTimeString() : 'Now'}
                      </span>
                    </div>

                    <div className="flex items-center justify-between text-slate-800">
                      <span className="font-bold text-blue-700 truncate max-w-[140px]">
                        {pkt.src_ip || '127.0.0.1'}
                      </span>
                      <ArrowRight className="w-3 h-3 text-slate-400 shrink-0" />
                      <span className="font-bold text-emerald-700 truncate max-w-[140px]">
                        {pkt.dst_ip || '127.0.0.1'}
                      </span>
                    </div>

                    <div className="mt-1.5 flex items-center justify-between text-[10px]">
                      <span className="px-2 py-0.5 rounded bg-slate-100 text-slate-700 font-bold border border-slate-200">
                        {pkt.protocol || 'TCP'} &bull; {pkt.length || 64} B
                      </span>
                      {pkt.is_threat && (
                        <span className="text-rose-600 font-bold uppercase">
                          {pkt.severity || 'THREAT'}
                        </span>
                      )}
                    </div>
                  </div>
                );
              })
            )}
          </div>
        </div>

        {/* Right Column: Deep Dissection Detail (7 Cols) */}
        <div className="lg:col-span-7 soc-card rounded-2xl p-6 space-y-5 bg-white border border-slate-200">
          {!activePacket ? (
            <div className="py-20 text-center text-slate-400 font-mono text-xs">
              No packet selected for deep dissection.
            </div>
          ) : (
            <>
              {/* Header Info */}
              <div className="flex items-start justify-between gap-4 pb-4 border-b border-slate-100">
                <div>
                  <div className="flex items-center gap-2">
                    <h3 className="text-base font-bold text-slate-900 font-sans">
                      Frame #{activePacket.id || 'LIVE'} Dissection
                    </h3>
                    <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-blue-50 text-blue-700 border border-blue-200">
                      {activePacket.protocol || 'TCP'}
                    </span>
                    {activePacket.is_threat && (
                      <span className="px-2 py-0.5 rounded text-[10px] font-mono font-bold bg-rose-100 text-rose-800 border border-rose-200">
                        {activePacket.threat_type || 'INTRUSION'}
                      </span>
                    )}
                  </div>
                  <p className="text-xs text-slate-500 font-mono mt-0.5">
                    Frame Size: {activePacket.length || 64} bytes | Promiscuous Ingress Frame
                  </p>
                </div>

                {!isEmployee && activePacket.src_ip && (
                  <button
                    onClick={() => handleBlock(activePacket.src_ip, activePacket.threat_type)}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl bg-rose-600 hover:bg-rose-500 text-white font-mono text-xs font-bold shadow-2xs transition-all shrink-0"
                  >
                    <Flame className="w-3.5 h-3.5" />
                    <span>Block {activePacket.src_ip}</span>
                  </button>
                )}
              </div>

              {blockFeedback && (
                <div className="p-3 rounded-xl bg-emerald-50 border border-emerald-200 text-emerald-700 text-xs font-mono">
                  {blockFeedback}
                </div>
              )}

              {/* 5-Tuple Summary */}
              <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-mono">
                  <span className="text-[10px] text-slate-500 uppercase block mb-1">
                    Source Endpoint (Transmitter)
                  </span>
                  <div className="font-bold text-blue-700 text-sm">{activePacket.src_ip || '127.0.0.1'}</div>
                  <div className="text-slate-500 text-[11px]">Port: {activePacket.src_port ?? 'n/a'}</div>
                </div>

                <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200 text-xs font-mono">
                  <span className="text-[10px] text-slate-500 uppercase block mb-1">
                    Destination Target (Receiver)
                  </span>
                  <div className="font-bold text-emerald-700 text-sm">{activePacket.dst_ip || '127.0.0.1'}</div>
                  <div className="text-slate-500 text-[11px]">Port: {activePacket.dst_port ?? 'n/a'}</div>
                </div>
              </div>

              {/* Payload View Tabs */}
              <div>
                <div className="flex items-center justify-between border-b border-slate-200 mb-3">
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setActiveTab('hex')}
                      className={`px-3 py-2 text-xs font-mono font-bold border-b-2 transition-all ${
                        activeTab === 'hex'
                          ? 'border-blue-600 text-blue-700'
                          : 'border-transparent text-slate-500 hover:text-slate-800'
                      }`}
                    >
                      Wireshark Hex Octets
                    </button>
                    <button
                      onClick={() => setActiveTab('ascii')}
                      className={`px-3 py-2 text-xs font-mono font-bold border-b-2 transition-all ${
                        activeTab === 'ascii'
                          ? 'border-blue-600 text-blue-700'
                          : 'border-transparent text-slate-500 hover:text-slate-800'
                      }`}
                    >
                      Decoded ASCII Payload
                    </button>
                  </div>

                  {isEmployee && (
                    <span className="text-[10px] text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 font-mono font-bold flex items-center gap-1">
                      <Lock className="w-3 h-3" /> Redacted
                    </span>
                  )}
                </div>

                {activeTab === 'hex' ? (
                  <div className="p-4 rounded-xl bg-slate-900 text-cyan-300 font-mono text-xs overflow-x-auto shadow-inner">
                    <pre className="hex-view select-all">{payloadHex}</pre>
                  </div>
                ) : (
                  <div className="p-4 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs overflow-x-auto shadow-inner">
                    <pre className="whitespace-pre-wrap break-all select-all">{payloadAscii}</pre>
                  </div>
                )}
              </div>
            </>
          )}
        </div>
      </div>
    </div>
  );
};

export default PacketAnalysis;
