import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';
import { useSOC } from '../context/SOCContext';
import {
  X,
  ShieldAlert,
  ShieldCheck,
  Flame,
  Binary,
  FileCode,
  CheckCircle2,
  AlertTriangle,
  Loader2,
  Lock
} from 'lucide-react';

const PacketModal = ({ packet, onClose }) => {
  const { isEmployee } = useAuth();
  const { blockIp } = useSOC();
  const [activeTab, setActiveTab] = useState('hex'); // 'hex' | 'ascii'
  const [isBlocking, setIsBlocking] = useState(false);
  const [blockStatus, setBlockStatus] = useState(null);

  if (!packet) return null;

  const handleBlockIp = async () => {
    if (isEmployee || isBlocking || !packet.src_ip) return;
    setIsBlocking(true);
    setBlockStatus(null);
    try {
      await blockIp(packet.src_ip, packet.threat_type || 'Dissection Modal Enforced Isolation');
      setBlockStatus({ success: true, message: `Firewall drop rule enforced against ${packet.src_ip}` });
      setTimeout(() => {
        setIsBlocking(false);
        if (onClose) onClose();
      }, 1200);
    } catch (err) {
      setBlockStatus({
        success: false,
        message: err.message || 'Failed to enforce firewall drop rule.'
      });
      setIsBlocking(false);
    }
  };

  const payloadHex = isEmployee ? '[REDACTED - EMPLOYEE CLEARANCE]' : (packet.payload_hex || 'No hex dump available');
  const payloadAscii = isEmployee ? '[REDACTED - EMPLOYEE CLEARANCE]' : (packet.payload_ascii || packet.payload_snippet || 'No ASCII payload decoded');

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4 bg-slate-900/50 backdrop-blur-xs animate-in fade-in duration-150">
      <div className="w-full max-w-3xl bg-white border border-slate-200 rounded-2xl shadow-2xl overflow-hidden flex flex-col max-h-[90vh] relative">
        {/* Modal Header */}
        <div className="p-5 border-b border-slate-100 flex items-center justify-between bg-slate-50/60">
          <div className="flex items-center gap-3">
            <div
              className={`p-2.5 rounded-xl border ${
                packet.is_threat
                  ? 'bg-rose-50 border-rose-200 text-rose-600'
                  : 'bg-blue-50 border-blue-200 text-blue-600'
              }`}
            >
              {packet.is_threat ? <ShieldAlert className="w-5 h-5" /> : <ShieldCheck className="w-5 h-5" />}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h3 className="text-base font-bold text-slate-900">
                  Deep Packet Inspection — Frame #{packet.id || 'LIVE'}
                </h3>
                <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-white text-blue-700 border border-slate-200">
                  {packet.protocol || 'TCP'}
                </span>
                {packet.is_threat && (
                  <span className="px-2 py-0.5 rounded text-[10px] font-mono uppercase font-bold bg-rose-50 text-rose-700 border border-rose-200">
                    THREAT DETECTED
                  </span>
                )}
              </div>
              <p className="text-xs text-slate-500 font-mono mt-0.5">
                Timestamp: {packet.timestamp ? new Date(packet.timestamp).toLocaleTimeString() : 'Now'} | Size: {packet.length || 64} bytes
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isBlocking}
            className="p-2 text-slate-400 hover:text-slate-700 rounded-lg hover:bg-slate-100 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Threat Banner */}
        {packet.is_threat && (
          <div className="px-5 py-2.5 bg-rose-50 border-b border-rose-200 flex items-center justify-between">
            <div className="flex items-center gap-2 text-rose-800 text-xs font-mono">
              <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
              <span>
                <b>Signature Match:</b> {packet.threat_type || 'Malicious Payload Signature'}
              </span>
            </div>
            <span className="text-[10px] uppercase font-bold px-2 py-0.5 rounded bg-rose-600 text-white">
              {packet.severity || 'Critical'}
            </span>
          </div>
        )}

        {/* Body */}
        <div className="p-6 overflow-y-auto space-y-6">
          {/* 5-Tuple Summary */}
          <div>
            <h4 className="text-xs font-bold uppercase tracking-wider text-slate-500 font-mono mb-2">
              5-Tuple Header Summary
            </h4>
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] text-slate-500 uppercase font-mono block mb-1">
                  Source Endpoint (Transmitter)
                </span>
                <div className="flex items-baseline justify-between font-mono">
                  <span className="font-bold text-blue-700 text-sm">{packet.src_ip || '127.0.0.1'}</span>
                  <span className="text-xs text-slate-500">Port: {packet.src_port ?? 'n/a'}</span>
                </div>
              </div>

              <div className="p-3.5 rounded-xl bg-slate-50 border border-slate-200">
                <span className="text-[10px] text-slate-500 uppercase font-mono block mb-1">
                  Destination Target (Receiver)
                </span>
                <div className="flex items-baseline justify-between font-mono">
                  <span className="font-bold text-emerald-700 text-sm">{packet.dst_ip || '127.0.0.1'}</span>
                  <span className="text-xs text-slate-500">Port: {packet.dst_port ?? 'n/a'}</span>
                </div>
              </div>
            </div>
          </div>

          {/* Tabbed Payload View */}
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
                  <span className="flex items-center gap-1.5">
                    <Binary className="w-3.5 h-3.5" /> Wireshark Hex Octets
                  </span>
                </button>

                <button
                  onClick={() => setActiveTab('ascii')}
                  className={`px-3 py-2 text-xs font-mono font-bold border-b-2 transition-all ${
                    activeTab === 'ascii'
                      ? 'border-blue-600 text-blue-700'
                      : 'border-transparent text-slate-500 hover:text-slate-800'
                  }`}
                >
                  <span className="flex items-center gap-1.5">
                    <FileCode className="w-3.5 h-3.5" /> Decoded ASCII Payload
                  </span>
                </button>
              </div>

              {isEmployee && (
                <span className="text-[10px] text-amber-700 bg-amber-50 px-2 py-0.5 rounded border border-amber-200 font-mono font-bold flex items-center gap-1">
                  <Lock className="w-3 h-3" /> Payload Redacted (Employee Role)
                </span>
              )}
            </div>

            {activeTab === 'hex' ? (
              <div className="p-4 rounded-xl bg-slate-900 text-cyan-300 font-mono text-xs overflow-x-auto">
                <pre className="hex-view select-all">{payloadHex}</pre>
              </div>
            ) : (
              <div className="p-4 rounded-xl bg-slate-900 text-slate-100 font-mono text-xs overflow-x-auto">
                <pre className="whitespace-pre-wrap break-all select-all">{payloadAscii}</pre>
              </div>
            )}
          </div>

          {/* Action Feedback */}
          {blockStatus && (
            <div
              className={`p-3 rounded-xl border text-xs font-mono flex items-center gap-2 ${
                blockStatus.success
                  ? 'bg-emerald-50 border-emerald-200 text-emerald-700'
                  : 'bg-rose-50 border-rose-200 text-rose-700'
              }`}
            >
              {blockStatus.success ? (
                <CheckCircle2 className="w-4 h-4 shrink-0 text-emerald-600" />
              ) : (
                <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600" />
              )}
              <span>{blockStatus.message}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="p-4 border-t border-slate-100 bg-slate-50 flex items-center justify-between">
          <div className="text-xs text-slate-500 font-mono">
            Originator IP: <span className="text-slate-900 font-bold">{packet.src_ip || '127.0.0.1'}</span>
          </div>

          <div className="flex items-center gap-2">
            <button
              onClick={onClose}
              disabled={isBlocking}
              className="px-4 py-2 rounded-xl text-xs font-semibold text-slate-600 hover:text-slate-900 bg-white border border-slate-200 hover:bg-slate-100 transition-colors shadow-2xs"
            >
              Close
            </button>

            {!isEmployee && packet.src_ip && (
              <button
                onClick={handleBlockIp}
                disabled={isBlocking}
                className="flex items-center gap-1.5 px-4 py-2 rounded-xl text-xs font-bold text-white bg-rose-600 hover:bg-rose-500 transition-all shadow-xs disabled:opacity-50"
              >
                {isBlocking ? (
                  <>
                    <Loader2 className="w-3.5 h-3.5 animate-spin" />
                    <span>Enforcing Drop...</span>
                  </>
                ) : (
                  <>
                    <Flame className="w-3.5 h-3.5" />
                    <span>Block IP {packet.src_ip}</span>
                  </>
                )}
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
};

export default PacketModal;
