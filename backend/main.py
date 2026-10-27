"""
SecureNet AI — Enterprise NIDS/NIPS Backend Engine
Strictly Live Packet Ingress Pipeline:
- Zero mock data, zero simulation loops, zero random number generators.
- Counters initialize strictly at ZERO.
- Captures live network frames from active NIC using promiscuous raw socket / Scapy.
- Dissects 5-tuple, protocol, byte size, bandwidth direction, and hex/ASCII payload.
- Threat Engine matches SQLi / XSS / Recon signatures.
- asyncio.Queue bridges sniffer thread to async WebSocket broadcaster.
- OS Firewall Controller enforces immediate packet drops.
- Supports Live Fire Attacker Terminal (curl / nmap attacks) and PCAP / Traffic Blast.
"""

import sys
import os
import re
import time
import socket
import select
import threading
import asyncio
import queue
import json
import struct
from datetime import datetime
from typing import List, Dict, Any, Optional

import psutil
from fastapi import (
    FastAPI,
    Depends,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    Query,
    Request,
    status,
    UploadFile,
    File,
    BackgroundTasks
)
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError

# Scapy imports
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

# Project imports
from database import get_db, init_db, SessionLocal, seed_default_topology, purge_packet_logs
from models import (
    User,
    PacketLog,
    FirewallRule,
    TopologyState,
    SecurityEvent,
    ThreatDetection,
    AIAnalysis,
    RiskAssessment,
    ResponsePolicy,
    ResponseAction,
    AuditLog,
    SystemConfig,
)
from security import verify_password, create_access_token, SECRET_KEY, ALGORITHM
from auth import get_current_user, require_role, decode_supabase_jwt, SUPABASE_JWT_SECRET
import firewall
import reports
from nids_service import (
    NIDSIngestionPipeline,
    EveJsonParser,
    ThreatClassifier,
    stateful_tracker,
    StatefulTrafficTracker
)
from ml_service import ml_detector, FeatureExtractor, MODEL_FILE, METADATA_FILE
from risk_and_response_service import (
    RiskScoringEngine,
    ResponsePolicyEngine,
    ResponseExecutionManager,
)
from jose import jwt, JWTError


app = FastAPI(
    title="SecureNet AI — Enterprise NIDS/NIPS Engine",
    description="Real-time Network Intrusion Detection & Active Prevention System",
    version="2.1.0"
)

# CORS setup for Vite frontend
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# -----------------------------------------------------------------------------
# Global State & Counters (Strictly Zero Initial State)
# -----------------------------------------------------------------------------
packet_counter = 0
threat_counter = 0
critical_threat_counter = 0
selected_interface_info: Dict[str, Any] = {
    "name": "Uninitialized",
    "ip": "0.0.0.0",
    "mac": "",
    "status": "Inactive"
}
sniffer_running = False

# Asyncio Queue for bridging background sniffer thread to async WebSocket broadcaster
packet_async_queue: Optional[asyncio.Queue] = None
event_loop: Optional[asyncio.AbstractEventLoop] = None
db_save_queue: queue.Queue = queue.Queue(maxsize=10000)

# Threat Engine Signatures
SQLI_REGEX = re.compile(
    r"(\bUNION\b.{1,50}\bSELECT\b)|('(\s|%20)*(OR|AND)(\s|%20)+)|(--\s)|(\bOR\b\s+[\w\d]+\s*=\s*[\w\d]+)|(;\s*DROP\b)|(;\s*SELECT\b)|(\b1\s*=\s*1\b)|('1'='1')",
    re.IGNORECASE
)
XSS_REGEX = re.compile(
    r"(<script.*?>.*?</script>)|(javascript:)|(onerror\s*=)|(onload\s*=)|(<img.*?src=.*?onerror=)|(alert\s*\(.*?\))|(<svg.*?onload=)",
    re.IGNORECASE
)
PROBE_PORTS = {21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 27017, 31337}

# Ingress Traffic Filter & Noise Suppression (Credible Presentation Pipeline)
capture_filter_mode = "soc_filtered"  # Options: "soc_filtered", "targeted", "raw_all"
SECURITY_MONITORED_PORTS = {
    80, 443, 8080, 8443, 8000, 5000, 5173, 53, 21, 22, 23, 25,
    110, 143, 445, 1433, 1521, 3306, 3389, 5432, 6379, 27017, 31337
}
NOISE_PORTS = {1900, 5353, 5355, 137, 138, 3702, 67, 68, 123, 17500}


# -----------------------------------------------------------------------------
# WebSocket Connection Manager
# -----------------------------------------------------------------------------
class ConnectionManager:
    """Manages active WebSocket connections for live real-time packet streaming."""
    def __init__(self):
        self.active_connections: List[tuple[WebSocket, str]] = []  # (websocket, role)
        self.lock = threading.Lock()

    async def connect(self, websocket: WebSocket, role: str):
        await websocket.accept()
        with self.lock:
            self.active_connections.append((websocket, role))
        print(f"[WebSocket] Client connected (Role: {role}). Total active: {len(self.active_connections)}")

    def disconnect(self, websocket: WebSocket):
        with self.lock:
            self.active_connections = [
                (ws, r) for ws, r in self.active_connections if ws != websocket
            ]
        print(f"[WebSocket] Client disconnected. Total active: {len(self.active_connections)}")

    async def broadcast_packet(self, packet_data: dict):
        """Broadcasts packet data. Masks payload for 'employee' role per RBAC."""
        dead_connections = []
        with self.lock:
            connections_snapshot = list(self.active_connections)

        for ws, role in connections_snapshot:
            try:
                if role == "employee":
                    sanitized = packet_data.copy()
                    if "payload_ascii" in sanitized:
                        sanitized["payload_ascii"] = "[REDACTED - EMPLOYEE CLEARANCE]"
                    if "payload_hex" in sanitized:
                        sanitized["payload_hex"] = "[REDACTED - EMPLOYEE CLEARANCE]"
                    await ws.send_json(sanitized)
                else:
                    await ws.send_json(packet_data)
            except (WebSocketDisconnect, RuntimeError, ConnectionResetError):
                dead_connections.append(ws)

        if dead_connections:
            with self.lock:
                self.active_connections = [
                    (ws, r) for ws, r in self.active_connections if ws not in dead_connections
                ]


manager = ConnectionManager()


# -----------------------------------------------------------------------------
# Packet Parsing & Deep Packet Inspection (DPI)
# -----------------------------------------------------------------------------
def format_hex_dump(raw_bytes: bytes, max_len: int = 128) -> str:
    """Renders Wireshark-style hex dump with offset, hex octets, and ASCII representation."""
    sample = raw_bytes[:max_len]
    lines = []
    for i in range(0, len(sample), 16):
        chunk = sample[i:i + 16]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        hex_col = f"{hex_bytes:<48}"
        ascii_col = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}  {hex_col}  |{ascii_col}|")
    return "\n".join(lines)


def decode_ascii_payload(raw_bytes: bytes, max_len: int = 256) -> str:
    """Extracts printable ASCII string with non-printable characters mapped to dots."""
    sample = raw_bytes[:max_len]
    return "".join(chr(b) if 32 <= b <= 126 else "." for b in sample)


def evaluate_threat_signatures(
    ascii_text: str,
    dst_port: Optional[int],
    src_ip: Optional[str] = None,
    stateful_metrics: Optional[Dict[str, Any]] = None
) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Evaluates payload and stateful connection metadata against attack signatures and deterministic rules.
    Returns: (is_threat, threat_type, severity)
    """
    # 1. Native Stateful NIDS Rules (TCP SYN Flood, Volumetric Flood, Brute Force)
    event_dict = {
        "src_ip": src_ip or "0.0.0.0",
        "dst_port": dst_port,
        "protocol": "TCP" if dst_port in (80, 443, 22, 21, 3389) else "OTHER"
    }
    is_st_threat, st_cat, st_sev, _, _ = ThreatClassifier.classify_event(
        event=event_dict,
        payload_sample=ascii_text,
        stateful_metrics=stateful_metrics
    )
    if is_st_threat:
        return True, st_cat, st_sev

    # 2. Application-layer Regex Signatures
    if SQLI_REGEX.search(ascii_text):
        return True, "SQL Injection (SQLi) Attempt", "Critical"

    if XSS_REGEX.search(ascii_text):
        return True, "Cross-Site Scripting (XSS) Injected Script", "High"

    if dst_port in PROBE_PORTS and ("NMAP" in ascii_text.upper() or "SCAN" in ascii_text.upper()):
        return True, f"Port Reconnaissance Probe (Port {dst_port})", "Medium"

    return False, None, None


def is_multicast_or_broadcast(ip_str: Optional[str]) -> bool:
    """Detects multicast (224.0.0.0 - 239.255.255.255) and broadcast addresses."""
    if not ip_str or ip_str == "255.255.255.255":
        return True
    try:
        first_octet = int(ip_str.split(".")[0])
        return 224 <= first_octet <= 239
    except (ValueError, IndexError):
        return False


def is_packet_relevant(
    src_ip: str,
    dst_ip: str,
    src_port: Optional[int],
    dst_port: Optional[int],
    protocol: str,
    payload_len: int,
    is_threat: bool,
    tcp_flags: Optional[Any] = None
) -> bool:
    """
    Evaluates packet against current capture_filter_mode.
    Eliminates noisy Windows background multicast/broadcast and empty streaming ACKs.
    """
    global capture_filter_mode
    # Threat signatures ALWAYS pass, regardless of filter mode
    if is_threat:
        return True

    if capture_filter_mode == "raw_all":
        return True

    # 1. Targeted Mode: strictly captures traffic to/from SecureNet service or localhost
    if capture_filter_mode == "targeted":
        target_ports = {8000, 5173}
        is_target_port = (src_port in target_ports) or (dst_port in target_ports)
        is_loopback = (src_ip == "127.0.0.1") or (dst_ip == "127.0.0.1")
        return is_target_port or is_loopback

    # 2. SOC Filtered Mode (Default):
    # Drop multicast & broadcast noise (SSDP 239.255.255.250, mDNS 224.0.0.251, LLMNR, etc.)
    if is_multicast_or_broadcast(dst_ip) or is_multicast_or_broadcast(src_ip):
        return False

    # Drop well-known local LAN noise ports
    if (src_port in NOISE_PORTS) or (dst_port in NOISE_PORTS):
        return False

    # Always keep monitored services: HTTP/S, DNS, SSH, FTP, DB, etc.
    if (src_port in SECURITY_MONITORED_PORTS) or (dst_port in SECURITY_MONITORED_PORTS):
        return True

    # Keep ICMP (ping probes)
    if protocol == "ICMP":
        return True

    # Drop empty TCP control frames (pure ACKs without payload on unmonitored high ports)
    if protocol == "TCP" and payload_len == 0:
        if tcp_flags and any(flag in str(tcp_flags) for flag in ("S", "F", "R")):
            return True
        return False

    # High-port to high-port with 0 payload
    if src_port and dst_port and src_port > 40000 and dst_port > 40000 and payload_len == 0:
        return False

    # Retain application packets with meaningful L7 payloads
    if payload_len > 0:
        return True

    return False


def process_packet_bytes(raw_data: bytes):
    """
    Main packet processing pipeline:
    1. Scapy IP layer dissection.
    2. 5-tuple extraction & bandwidth calculation.
    3. DPI & Threat Signature matching.
    4. Immediate OS Firewall enforcement if malicious.
    5. Dispatches to async queue for WebSocket broadcast.
    """
    global packet_counter, threat_counter, critical_threat_counter

    try:
        pkt = IP(raw_data)
    except (ValueError, IndexError, struct.error, scapy.Scapy_Exception):
        return

    src_ip = pkt.src
    dst_ip = pkt.dst
    proto_num = pkt.proto
    protocol = "OTHER"
    src_port = None
    dst_port = None

    if pkt.haslayer(TCP):
        protocol = "TCP"
        src_port = int(pkt[TCP].sport)
        dst_port = int(pkt[TCP].dport)
        if dst_port in (80, 8080) or src_port in (80, 8080):
            protocol = "HTTP"
        elif dst_port in (443, 8443) or src_port in (443, 8443):
            protocol = "HTTPS"
    elif pkt.haslayer(UDP):
        protocol = "UDP"
        src_port = int(pkt[UDP].sport)
        dst_port = int(pkt[UDP].dport)
        if dst_port == 53 or src_port == 53:
            protocol = "DNS"
    elif pkt.haslayer(ICMP):
        protocol = "ICMP"
    else:
        protocol = f"PROTO-{proto_num}"

    # Extract payload
    payload_bytes = b""
    if pkt.haslayer(Raw):
        payload_bytes = bytes(pkt[Raw].load)
    else:
        payload_bytes = bytes(pkt.payload)[:256]

    payload_hex = format_hex_dump(payload_bytes, max_len=128)
    payload_ascii = decode_ascii_payload(payload_bytes, max_len=256)
    tcp_flags = pkt[TCP].flags if pkt.haslayer(TCP) else None

    # Push packet into in-memory StatefulTrafficTracker 60s sliding window
    stateful_metrics = stateful_tracker.record_packet(
        src_ip=src_ip,
        size=len(raw_data),
        tcp_flags=tcp_flags,
        dst_port=dst_port,
        dst_ip=dst_ip,
        protocol=protocol,
        payload_sample=payload_ascii
    )

    # Signature & Stateful Traffic Analysis
    is_threat, threat_type, severity = evaluate_threat_signatures(
        ascii_text=payload_ascii,
        dst_port=dst_port,
        src_ip=src_ip,
        stateful_metrics=stateful_metrics
    )

    # Ingress Traffic Filter: Discard irrelevant background noise before counting or persistence
    if not is_packet_relevant(
        src_ip=src_ip,
        dst_ip=dst_ip,
        src_port=src_port,
        dst_port=dst_port,
        protocol=protocol,
        payload_len=len(payload_bytes),
        is_threat=is_threat,
        tcp_flags=tcp_flags
    ):
        return

    # Inbound / Outbound classification relative to bound host NIC
    host_ip = selected_interface_info.get("ip", "")
    direction = "inbound" if (dst_ip == host_ip or not host_ip) else "outbound"

    packet_counter += 1
    risk_score_val = 0
    risk_band_val = "Low"
    ai_anomaly_val = 0
    response_outcome = "MONITOR"
    is_auto_blocked = False
    can_be_autoblocked = False

    if is_threat:
        threat_counter += 1
        if severity == "Critical":
            critical_threat_counter += 1
        print(f"\n[ALERT - THREAT DETECTED] Signature: {threat_type} | Severity: {severity} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        target_block_ip = src_ip if (src_ip and src_ip != host_ip) else (src_ip or "127.0.0.1")
        
        # 1. AI Behavioral Anomaly Analysis on target host using stateful 60s sliding window
        rolling_packets = stateful_tracker.get_packets_for_ip(target_block_ip)
        features = FeatureExtractor.extract_from_packets(
            packets=rolling_packets or [
                {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": dst_port,
                    "length": len(raw_data),
                    "protocol": protocol,
                    "direction": direction,
                    "payload_ascii": payload_ascii
                }
            ],
            host_ip=target_block_ip,
            tracker=stateful_tracker
        )
        ai_result = ml_detector.analyze_host_traffic(target_block_ip, features)
        ai_anomaly_val = ai_result.get("anomaly_score", 40)

        with SessionLocal() as db_session:
            # 2. Persist ThreatDetection entity
            threat_rec = ThreatDetection(
                timestamp=datetime.utcnow(),
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                protocol=protocol,
                attack_category=threat_type or "Intrusion Attempt",
                severity=severity or "High",
                confidence=90 if severity == "Critical" else 80,
                evidence=f"Signature match '{threat_type}' on port {dst_port}. AI Anomaly Score: {ai_anomaly_val}/100.",
                status="OPEN"
            )
            db_session.add(threat_rec)
            db_session.flush()

            # 3. Calculate Explainable Risk Score
            risk_res = RiskScoringEngine.assess_and_record(
                db=db_session,
                threat=threat_rec,
                ai_anomaly_score=ai_anomaly_val,
                target_ip=dst_ip,
                src_ip=target_block_ip
            )
            risk_score_val = risk_res.risk_score
            risk_band_val = risk_res.risk_band

            # 4. Evaluate Response Policy & Safety Allowlists
            decision = ResponsePolicyEngine.evaluate_response_decision(
                db=db_session,
                risk_assessment=risk_res,
                threat=threat_rec
            )
            response_outcome = decision.get("status", "SIMULATED")

            # Check if source IP is already restricted in active firewall rules
            already_blocked_rule = db_session.query(FirewallRule).filter(
                FirewallRule.ip_address == target_block_ip,
                FirewallRule.is_active == True
            ).first()

            if already_blocked_rule:
                is_auto_blocked = True
                can_be_autoblocked = True
                response_outcome = "ALREADY_RESTRICTED"
                threat_rec.status = "MITIGATED"
                threat_rec.notes = "Suppressed: Source IP is already restricted in active kernel firewall rules."
            elif decision.get("recommended_action") == "AUTO_BLOCK_SMALL_THREAT" or decision.get("action_type") == "AUTO_BLOCK":
                is_auto_blocked = True
                can_be_autoblocked = True
                threat_rec.status = "AUTO_BLOCKED"
                threat_rec.notes = "Auto-mitigated silently by background NIPS policy."
            elif (severity or "").lower() in ("low", "medium") or risk_score_val < 65:
                can_be_autoblocked = True

            # 5. Execute Authorized Automated or Simulated Action
            if decision.get("is_eligible") and decision.get("action_type") == "BLOCK" and not already_blocked_rule:
                ResponseExecutionManager.execute_response(
                    db=db_session,
                    target_ip=target_block_ip,
                    reason=threat_type or "Automated Threat Mitigation",
                    actor="AUTOMATED_NIPS",
                    risk_assessment_id=risk_res.id,
                    threat_id=threat_rec.id,
                    duration_seconds=decision.get("duration_seconds", 3600),
                    policy_name=decision.get("policy_name")
                )


    packet_dict = {
        "id": packet_counter,
        "timestamp": datetime.utcnow().isoformat(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "src_port": src_port,
        "dst_port": dst_port,
        "protocol": protocol,
        "length": len(raw_data),
        "direction": direction,
        "is_threat": is_threat,
        "threat_type": threat_type,
        "severity": severity,
        "risk_score": risk_score_val,
        "risk_band": risk_band_val,
        "ai_anomaly_score": ai_anomaly_val,
        "response_status": response_outcome,
        "auto_blocked": is_auto_blocked,
        "can_be_autoblocked": can_be_autoblocked,
        "payload_hex": payload_hex,
        "payload_ascii": payload_ascii
    }

    # Queue packet for SQLite persistence
    try:
        if is_threat or (packet_counter % 2 == 0):
            db_save_queue.put_nowait(packet_dict)
    except queue.Full:
        pass

    # Push to asyncio queue for WebSocket broadcaster
    if packet_async_queue and event_loop and event_loop.is_running():
        event_loop.call_soon_threadsafe(
            packet_async_queue.put_nowait,
            packet_dict
        )


# -----------------------------------------------------------------------------
# WebSocket Broadcaster Worker
# -----------------------------------------------------------------------------
async def websocket_broadcaster_worker():
    """Async background worker reading from packet_async_queue and broadcasting to clients."""
    global packet_async_queue
    print("[Broadcaster Worker] WebSocket async broadcast loop initialized.")
    while True:
        try:
            packet = await packet_async_queue.get()
            await manager.broadcast_packet(packet)
            packet_async_queue.task_done()
        except asyncio.CancelledError:
            break
        except Exception:
            await asyncio.sleep(0.01)


# -----------------------------------------------------------------------------
# Database Worker Daemon
# -----------------------------------------------------------------------------
def db_saver_worker():
    """Background worker persisting queued packet logs to SQLite."""
    while True:
        try:
            batch = []
            while len(batch) < 50:
                try:
                    item = db_save_queue.get(timeout=1.0)
                    batch.append(item)
                except queue.Empty:
                    break

            if batch:
                with SessionLocal() as db:
                    records = [
                        PacketLog(
                            timestamp=datetime.fromisoformat(p["timestamp"]),
                            src_ip=p["src_ip"],
                            dst_ip=p["dst_ip"],
                            src_port=p["src_port"],
                            dst_port=p["dst_port"],
                            protocol=p["protocol"],
                            is_threat=p["is_threat"],
                            threat_type=p["threat_type"],
                            payload_sample=p["payload_ascii"][:200]
                        )
                        for p in batch
                    ]
                    db.add_all(records)
                    db.commit()
        except Exception:
            time.sleep(1)


# -----------------------------------------------------------------------------
# Scapy Sniffer Callback (Live Sniff Ingress Pipeline)
# -----------------------------------------------------------------------------
def scapy_packet_callback(pkt: Any):
    """
    Direct callback for live Scapy packet capture streams:
    Usage: scapy.sniff(prn=scapy_packet_callback, store=False)
    Dissects live Scapy packets, feeds into StatefulTrafficTracker, and evaluates threats.
    """
    try:
        if IP in pkt:
            raw_bytes = bytes(pkt[IP])
            process_packet_bytes(raw_bytes)
        elif hasattr(pkt, "haslayer") and pkt.haslayer(IP):
            raw_bytes = bytes(pkt[IP])
            process_packet_bytes(raw_bytes)
        elif isinstance(pkt, bytes):
            process_packet_bytes(pkt)
    except Exception as e:
        print(f"[Scapy Callback Error] {e}")


# -----------------------------------------------------------------------------
# Promiscuous Sniffer Thread
# -----------------------------------------------------------------------------
def promiscuous_sniffer_loop(target_ip: str):
    """
    Continuous promiscuous packet sniffer loop.
    Captures live network packets from physical/virtual NIC.
    """
    global sniffer_running
    print(f"[Sniffer Daemon] Starting promiscuous socket capture on {target_ip}...")
    sniffer_running = True

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((target_ip, 0))
        s.settimeout(1.0)

        # On Windows, activate SIO_RCVALL to capture all interface frames promiscuously
        if sys.platform == "win32":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
                print(f"[Sniffer Daemon] Windows SIO_RCVALL promiscuous mode enabled on {target_ip}.")
            except OSError as e:
                print(f"[Sniffer Daemon Notice] SIO_RCVALL requires admin privileges: {e}")

        while sniffer_running:
            try:
                raw_data, _ = s.recvfrom(65535)
                if raw_data:
                    process_packet_bytes(raw_data)
            except socket.timeout:
                continue
            except (socket.error, OSError):
                if not sniffer_running:
                    break
                time.sleep(0.01)

    except (socket.error, OSError) as e:
        print(f"[Sniffer Daemon Error] Raw socket on {target_ip}: {e}")
    finally:
        if sys.platform == "win32":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except OSError:
                pass
        try:
            s.close()
        except OSError:
            pass
        sniffer_running = False
        print("[Sniffer Daemon] Sniffer thread terminated.")


# -----------------------------------------------------------------------------
# Smart Network Interface Discovery & Operator Selector
# -----------------------------------------------------------------------------
def discover_network_interfaces() -> List[Dict[str, Any]]:
    """
    Scans host network adapters using scapy/psutil.
    Strictly filters out dead/virtual/WAN miniports and only returns interfaces
    with valid, assigned IPv4 addresses.
    """
    interfaces = []
    seen_ips = set()

    # Attempt scapy discovery
    try:
        scapy_ifaces = scapy.arch.get_working_ifaces()
        for sif in scapy_ifaces:
            ip_val = getattr(sif, "ip", None)
            if ip_val and ip_val not in seen_ips and not ip_val.startswith("169.254."):
                seen_ips.add(ip_val)
                interfaces.append({
                    "name": getattr(sif, "name", "NIC"),
                    "ip": ip_val,
                    "is_loopback": ip_val.startswith("127.")
                })
    except Exception:
        pass

    # Complement/fallback with psutil
    addrs = psutil.net_if_addrs()
    for iface_name, addr_list in addrs.items():
        # Ignore dead virtual miniports
        if "WAN Miniport" in iface_name or "Native MAC" in iface_name or "QoS" in iface_name:
            continue
        for a in addr_list:
            if a.family == socket.AF_INET:
                ip_val = a.address
                if ip_val not in seen_ips and not ip_val.startswith("169.254."):
                    seen_ips.add(ip_val)
                    interfaces.append({
                        "name": iface_name,
                        "ip": ip_val,
                        "is_loopback": ip_val.startswith("127.")
                    })

    # Always ensure loopback is available as an option for localhost attacker demos
    if "127.0.0.1" not in seen_ips:
        interfaces.append({
            "name": "Loopback Pseudo-Interface",
            "ip": "127.0.0.1",
            "is_loopback": True
        })

    # Sort so active LAN/Wi-Fi comes first, followed by loopback
    interfaces.sort(key=lambda x: (x["is_loopback"], not "wi-fi" in x["name"].lower()))
    return interfaces


def select_and_bind_interface() -> Dict[str, Any]:
    """
    Stateless Smart NIC Selector for background agent execution:
    Auto-selects the primary active network interface without blocking terminal prompts.
    Configures scapy.config.conf.iface automatically.
    """
    global selected_interface_info
    ifaces = discover_network_interfaces()

    print("\n[SecureNet AI Local Sensor] Initializing network interface...")
    for idx, iface in enumerate(ifaces, start=1):
        print(f" [{idx}] {iface['name']} (IP: {iface['ip']}, Loopback: {iface.get('is_loopback', False)})")

    selected = None
    # 1. Check CLI argument or environment variable first
    cli_arg = os.environ.get("SECURENET_IFACE")
    for arg in sys.argv:
        if arg.startswith("--iface="):
            cli_arg = arg.split("=")[1]

    if cli_arg is not None:
        try:
            val = int(cli_arg)
            if 1 <= val <= len(ifaces):
                selected = ifaces[val - 1]
        except ValueError:
            for iface in ifaces:
                if cli_arg.lower() in iface["name"].lower() or cli_arg == iface["ip"]:
                    selected = iface
                    break

    # 2. Non-blocking automatic selection: Pick first active non-loopback LAN/Wi-Fi interface
    if not selected:
        for iface in ifaces:
            if not iface.get("is_loopback") and iface.get("ip") != "127.0.0.1":
                selected = iface
                break

    # 3. Fallback to first available interface if no non-loopback interface found
    if not selected and ifaces:
        selected = ifaces[0]
    elif not selected:
        selected = {
            "name": "Default Pseudo-Interface",
            "ip": "127.0.0.1",
            "is_loopback": True
        }

    # Automatically set Scapy interface without blocking terminal prompts
    try:
        scapy.config.conf.iface = selected["name"]
        scapy.conf.iface = selected["name"]
    except Exception as e:
        print(f"[Scapy Config Notice] Could not set scapy.config.conf.iface by name: {e}")

    selected_interface_info = {
        "name": selected["name"],
        "ip": selected["ip"],
        "status": "Capturing Promiscuously"
    }
    print(f"\n[Interface Bound] Auto-selected active NIC: {selected['name']} ({selected['ip']}) — running statelessly.\n")
    return selected


# -----------------------------------------------------------------------------
# FastAPI Startup & Background Thread Initialization
# -----------------------------------------------------------------------------
@app.on_event("startup")
async def startup_event():
    """Initializes SQLite database, starts sniffer daemon, async broadcaster and DB worker."""
    global event_loop, packet_async_queue
    event_loop = asyncio.get_running_loop()
    packet_async_queue = asyncio.Queue()

    # 1. Initialize DB and baseline seeds
    init_db()

    # 2. Select interface
    iface = select_and_bind_interface()

    # 3. Start async broadcaster worker
    asyncio.create_task(websocket_broadcaster_worker())

    # 4. Start DB persistence worker daemon
    db_thread = threading.Thread(target=db_saver_worker, daemon=True)
    db_thread.start()

    # 5. Start Promiscuous Sniffer Daemon thread
    sniffer_thread = threading.Thread(
        target=promiscuous_sniffer_loop,
        args=(iface["ip"],),
        daemon=True
    )
    sniffer_thread.start()

    # 6. Start Response TTL Expiration Worker daemon
    def ttl_expiry_worker():
        while True:
            try:
                with SessionLocal() as db_session:
                    ResponseExecutionManager.check_expired_actions(db_session)
            except SQLAlchemyError as db_err:
                print(f"[TTL Expiry Worker DB Error] {db_err}")
            except Exception as worker_err:
                print(f"[TTL Expiry Worker Error] {worker_err}")
            time.sleep(30)

    ttl_thread = threading.Thread(target=ttl_expiry_worker, daemon=True)
    ttl_thread.start()

    print("[SecureNet AI System] Sniffer, TTL expiry worker, and async broadcaster active.\n")



# -----------------------------------------------------------------------------
# Real-World Live Fire Attacker Demonstration Endpoints (Method 1)
# -----------------------------------------------------------------------------
@app.get("/login")
@app.post("/login")
async def login_endpoint(
    request: Request,
    user: Optional[str] = Query(None),
    username: Optional[str] = Query(None)
):
    """Authentication status check endpoint."""
    return {"status": "ok", "message": "Authentication endpoint reached."}


@app.get("/api/data")
async def live_data_endpoint(
    request: Request,
    search: Optional[str] = Query(None),
    q: Optional[str] = Query(None)
):
    """Realtime data retrieval endpoint."""
    query_param = search or q or ""
    return {"status": "ok", "query": query_param, "results": []}


# -----------------------------------------------------------------------------
# REST API Schemas
# -----------------------------------------------------------------------------
class BlockRequest(BaseModel):
    ip_address: str
    reason: str


class UnblockRequest(BaseModel):
    ip_address: str


class ThreatResolveRequest(BaseModel):
    ip_address: str
    reason: Optional[str] = "Operator Mitigated Threat"
    threat_id: Optional[int] = None


class TopologyPayload(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class FilterModePayload(BaseModel):
    mode: str  # 'soc_filtered', 'targeted', or 'raw_all'


class NidsEventIngestPayload(BaseModel):
    events: List[Dict[str, Any]]
    sensor_id: Optional[str] = "suricata-sensor-01"


class ThreatStatusUpdate(BaseModel):
    status: str  # OPEN, INVESTIGATING, MITIGATED, RESOLVED, FALSE_POSITIVE
    notes: Optional[str] = None


class AIAnalyzeHostPayload(BaseModel):
    target_ip: str


class PolicyPayload(BaseModel):
    name: str
    description: Optional[str] = None
    min_risk_score: int = 70
    severity_threshold: str = "High"
    action_type: str = "RECOMMEND"  # MONITOR, ALERT, RECOMMEND, REQUIRE_APPROVAL, AUTO_BLOCK
    duration_seconds: int = 3600
    is_enabled: bool = True
    allowlist_ips: Optional[str] = None


class ManualResponsePayload(BaseModel):
    target_ip: str
    action_type: str = "BLOCK"
    reason: str
    duration_seconds: int = 3600


class SystemConfigUpdatePayload(BaseModel):
    configs: Dict[str, str]


def serialize_packet_log(record: PacketLog) -> Dict[str, Any]:

    """Return a frontend-safe representation of a persisted packet record."""
    severity = ""
    if record.is_threat:
        threat_name = (record.threat_type or "").lower()
        if "sqli" in threat_name or "sql injection" in threat_name:
            severity = "Critical"
        elif "xss" in threat_name:
            severity = "High"
        else:
            severity = "Medium"

    return {
        "id": record.id,
        "timestamp": record.timestamp.isoformat(),
        "src_ip": record.src_ip,
        "dst_ip": record.dst_ip,
        "src_port": record.src_port,
        "dst_port": record.dst_port,
        "protocol": record.protocol,
        "is_threat": record.is_threat,
        "threat_type": record.threat_type,
        "severity": severity,
        "payload_ascii": record.payload_sample or "",
        # PacketLog intentionally persists the decoded sample, not the entire raw frame.
        "payload_hex": "",
    }


# -----------------------------------------------------------------------------
# API Endpoints — Authentication
# -----------------------------------------------------------------------------
@app.post("/api/auth/login")
async def login(
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: Session = Depends(get_db)
):
    """
    Authenticates user credentials and issues a signed HS256 JWT Bearer token.
    Enforces RBAC matrix for 'admin', 'analyst', and 'employee'.
    """
    user = db.query(User).filter(User.username == form_data.username).first()
    if not user or not verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )

    access_token = create_access_token(
        data={"sub": user.username, "role": user.role}
    )
    return {
        "access_token": access_token,
        "token_type": "bearer",
        "role": user.role,
        "username": user.username
    }


@app.get("/api/auth/me")
async def get_me(current_user: User = Depends(get_current_user)):
    """Returns the profile and role privileges of the authenticated session."""
    return {
        "id": current_user.id,
        "username": current_user.username,
        "role": current_user.role
    }


# -----------------------------------------------------------------------------
# API Endpoints — Active Defense Firewall Management
# -----------------------------------------------------------------------------
@app.get("/api/firewall/rules")
async def get_firewall_rules(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves all active kernel firewall drop rules currently enforced."""
    return firewall.get_active_rules(db)


@app.post("/api/firewall/block")
async def block_firewall_rule(
    payload: BlockRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Manual enforcement endpoint. Restricted to 'admin' and 'analyst'.
    Executes platform-aware kernel drop command and updates persistent rule store.
    """
    result = firewall.block_ip(
        ip=payload.ip_address,
        reason=payload.reason,
        blocked_by=f"MANUAL_{current_user.username.upper()}",
        db=db
    )
    # Sync matching open threats to MITIGATED
    try:
        open_threats = db.query(ThreatDetection).filter(
            ThreatDetection.src_ip == payload.ip_address,
            ThreatDetection.status == "OPEN"
        ).all()
        for ot in open_threats:
            ot.status = "MITIGATED"
            ot.assigned_to = current_user.username
        db.commit()
    except Exception as e:
        print(f"[Threat Sync Warning] {e}")

    return {
        "message": f"Firewall drop enforced against {payload.ip_address}",
        "data": result
    }


@app.post("/api/threats/resolve")
async def resolve_threat_endpoint(
    payload: ThreatResolveRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Instantly mitigates and resolves threat:
    Enforces active firewall kernel drop and updates ThreatDetection workflow status.
    """
    result = firewall.block_ip(
        ip=payload.ip_address,
        reason=payload.reason or "Operator Threat Mitigation",
        blocked_by=f"MANUAL_{current_user.username.upper()}",
        db=db
    )

    try:
        if payload.threat_id:
            t = db.query(ThreatDetection).filter(ThreatDetection.id == payload.threat_id).first()
            if t:
                t.status = "MITIGATED"
                t.assigned_to = current_user.username
                t.notes = f"Mitigated via operator resolve by {current_user.username}."

        # Also update any other OPEN threats with this src_ip
        other_threats = db.query(ThreatDetection).filter(
            ThreatDetection.src_ip == payload.ip_address,
            ThreatDetection.status == "OPEN"
        ).all()
        for ot in other_threats:
            ot.status = "MITIGATED"
            ot.assigned_to = current_user.username

        db.commit()
    except Exception as e:
        print(f"[Threat Resolution DB Sync Notice] {e}")

    return {
        "message": f"Threat mitigated. Firewall drop enforced against {payload.ip_address}",
        "data": result
    }


@app.post("/api/firewall/unblock")
async def unblock_firewall_rule(
    payload: UnblockRequest,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Manual rule revocation endpoint. Restricted to 'admin' and 'analyst'.
    Executes platform-aware kernel delete command and deactivates database rule.
    """
    result = firewall.unblock_ip(ip=payload.ip_address, db=db)
    return {
        "message": f"Firewall drop rule revoked for {payload.ip_address}",
        "data": result
    }


# -----------------------------------------------------------------------------
# API Endpoints — Persisted telemetry views
# -----------------------------------------------------------------------------
@app.get("/api/packets")
async def get_packets(
    limit: int = Query(100, ge=1, le=500),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns recent packets persisted by the live capture pipeline."""
    records = db.query(PacketLog).order_by(PacketLog.timestamp.desc()).limit(limit).all()
    return [serialize_packet_log(record) for record in records]


@app.get("/api/threats")
async def get_threats(
    limit: int = Query(100, ge=1, le=500),
    include_all: bool = Query(False),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns genuine threat-signature matches from the packet audit ledger."""
    # Active firewall blocked IPs
    active_blocked_ips = {
        r.ip_address for r in db.query(FirewallRule.ip_address).filter(FirewallRule.is_active == True).all()
    }

    query = db.query(PacketLog).filter(PacketLog.is_threat == True)

    # User requirement: If a threat can be auto-blocked or is already blocked, don't show it in threats!
    if not include_all:
        if active_blocked_ips:
            query = query.filter(~PacketLog.src_ip.in_(active_blocked_ips))
        query = query.filter(
            ~PacketLog.threat_type.ilike("%probe%"),
            ~PacketLog.threat_type.ilike("%reconnaissance%")
        )

    records = query.order_by(PacketLog.timestamp.desc()).limit(limit).all()
    serialized = []
    for record in records:
        data = serialize_packet_log(record)
        data["is_blocked"] = record.src_ip in active_blocked_ips
        data["can_be_autoblocked"] = (
            data["is_blocked"] or
            (data.get("severity") or "").lower() in ("low", "medium") or
            "probe" in (record.threat_type or "").lower() or
            "scan" in (record.threat_type or "").lower()
        )
        serialized.append(data)
    return serialized


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Builds the alert feed from actual detected threats, excluding already mitigated/blocked IPs."""
    active_blocked_ips = {
        r.ip_address for r in db.query(FirewallRule.ip_address).filter(FirewallRule.is_active == True).all()
    }
    query = db.query(PacketLog).filter(PacketLog.is_threat == True)
    if active_blocked_ips:
        query = query.filter(~PacketLog.src_ip.in_(active_blocked_ips))

    records = (
        query
        .order_by(PacketLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [
        {
            "id": f"threat-{record.id}",
            "title": record.threat_type or "Security signature detected",
            "severity": serialize_packet_log(record)["severity"].lower() or "warning",
            "timestamp": record.timestamp.isoformat(),
            "description": f"{record.src_ip} targeted {record.dst_ip}:{record.dst_port or 'n/a'} via {record.protocol}.",
            "source_ip": record.src_ip,
        }
        for record in records
    ]


@app.get("/api/system/logs")
async def get_system_logs(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Exposes an audit-style activity feed sourced from persisted packet records."""
    records = db.query(PacketLog).order_by(PacketLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": f"packet-{record.id}",
            "timestamp": record.timestamp.isoformat(),
            "level": "ALERT" if record.is_threat else "INFO",
            "category": "THREAT_ENGINE" if record.is_threat else "PACKET_CAPTURE",
            "message": (
                f"{record.threat_type} detected from {record.src_ip}"
                if record.is_threat
                else f"{record.protocol} packet observed: {record.src_ip} → {record.dst_ip}"
            ),
            "details": record.payload_sample or "No application payload retained.",
        }
        for record in records
    ]


# -----------------------------------------------------------------------------
# API Endpoints — Interactive Network Topology Canvas
# -----------------------------------------------------------------------------
@app.get("/api/topology")
async def get_topology(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Retrieves stored network architecture node and edge coordinates."""
    top = db.query(TopologyState).order_by(TopologyState.updated_at.desc()).first()
    if not top or not top.nodes_json:
        return {"nodes": [], "edges": []}

    return {
        "nodes": json.loads(top.nodes_json),
        "edges": json.loads(top.edges_json),
        "updated_at": top.updated_at.isoformat()
    }


@app.post("/api/topology")
async def save_topology(
    payload: TopologyPayload,
    current_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """
    Persists updated node coordinates and topology links.
    Strictly restricted to 'admin' role per RBAC specifications.
    """
    top = db.query(TopologyState).first()
    if not top:
        top = TopologyState(name="default")
        db.add(top)

    top.nodes_json = json.dumps(payload.nodes)
    top.edges_json = json.dumps(payload.edges)
    top.updated_at = datetime.utcnow()
    db.commit()

    return {"message": "Network topology state saved successfully."}


# -----------------------------------------------------------------------------
# API Endpoints — Executive Audit Reports & PDF Generator
# -----------------------------------------------------------------------------
@app.get("/api/reports/summary")
async def get_report_metrics(
    range: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns aggregated cybersecurity metrics for UI preview."""
    return reports.get_reports_summary(timeframe=range, db=db)


@app.get("/api/reports/download")
async def download_pdf_report(
    range: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Generates and streams formal executive PDF audit report.
    Restricted to 'admin' and 'analyst' personas.
    """
    pdf_buffer = reports.generate_pdf_report(timeframe=range, db=db)
    filename = f"SecureNet_Audit_Report_{range}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.pdf"

    return StreamingResponse(
        pdf_buffer,
        media_type="application/pdf",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# -----------------------------------------------------------------------------
# API Endpoints — System Health & Traffic Injection Test Harness
# -----------------------------------------------------------------------------
@app.get("/api/system/status")
async def get_system_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns runtime telemetry on active adapter, sniffer state, and firewall platform."""
    fw_info = firewall.get_platform_info()
    active_rule_count = db.query(FirewallRule).filter(FirewallRule.is_active == True).count()
    total_sec_events = db.query(SecurityEvent).count()
    total_threat_detections = db.query(ThreatDetection).count()
    pending_decisions = db.query(ResponseAction).filter(ResponseAction.status == "PENDING_APPROVAL").count()
    active_restrictions = db.query(ResponseAction).filter(ResponseAction.status.in_(["EXECUTED", "SIMULATED"])).count()
    sim_mode = ResponsePolicyEngine.get_system_config(db, "simulation_mode", "true").lower() == "true"
    real_auth = ResponsePolicyEngine.get_system_config(db, "real_enforcement_authorized", "false").lower() == "true"

    # Distinct active devices observed in persisted telemetry (0 dummy data)
    recent_devices = db.query(PacketLog.src_ip).distinct().limit(50).all()
    devices_count = len(recent_devices)

    return {
        "adapter": selected_interface_info,
        "sniffer_running": sniffer_running,
        "total_packets_captured": packet_counter,
        "total_threats_detected": threat_counter,
        "critical_threats_detected": critical_threat_counter,
        "total_security_events": total_sec_events,
        "total_threat_detections": total_threat_detections,
        "active_firewall_rules_count": active_rule_count,
        "pending_response_decisions_count": pending_decisions,
        "active_restrictions_count": active_restrictions,
        "simulation_mode": sim_mode,
        "real_enforcement_authorized": real_auth,
        "ai_model_loaded": ml_detector.is_loaded,
        "ai_model_version": ml_detector.metadata.get("version", "1.0.0"),
        "recent_devices_count": devices_count,
        "capture_filter_mode": capture_filter_mode,
        "firewall_platform": fw_info["os"],
        "firewall_driver": fw_info["driver"]
    }



@app.post("/api/system/filter-mode")
async def set_filter_mode(
    payload: FilterModePayload,
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """Updates active packet capture filter mode dynamically."""
    global capture_filter_mode
    if payload.mode not in ("soc_filtered", "targeted", "raw_all"):
        raise HTTPException(
            status_code=400,
            detail="Invalid filter mode. Choose 'soc_filtered', 'targeted', or 'raw_all'."
        )
    capture_filter_mode = payload.mode
    print(f"[NIDS Controller] Ingress capture filter mode switched to: {capture_filter_mode}")
    return {
        "message": f"Capture filter mode set to {capture_filter_mode}",
        "mode": capture_filter_mode
    }


@app.post("/api/system/reset-session")
async def reset_telemetry_session(
    purge_db: bool = Query(True),
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Resets in-memory telemetry counters to 0, clears DB logs, and notifies UI.
    Allows presentation demonstration to start from a clean zero baseline.
    """
    global packet_counter, threat_counter, critical_threat_counter
    packet_counter = 0
    threat_counter = 0
    critical_threat_counter = 0

    purged_count = 0
    if purge_db:
        purged_count = purge_packet_logs(db)

    # Broadcast session reset event to all connected WebSockets
    reset_event = {
        "type": "SESSION_RESET",
        "timestamp": datetime.utcnow().isoformat()
    }
    await manager.broadcast_packet(reset_event)
    print(f"[NIDS Controller] Telemetry session reset to ZERO. Purged {purged_count} historical records.")

    return {
        "message": "Telemetry session and counters successfully reset to 0.",
        "purged_records": purged_count,
        "total_packets_captured": 0,
        "total_threats_detected": 0
    }


# -----------------------------------------------------------------------------
# API Endpoints — NIDS Telemetry Ingestion (Suricata EVE JSON)
# -----------------------------------------------------------------------------
@app.post("/api/nids/events/ingest")
async def ingest_nids_events(
    payload: NidsEventIngestPayload,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Ingests Suricata EVE JSON or standard NIDS events.
    Performs field normalization, schema validation, deduplication, and automated threat classification.
    """
    result = NIDSIngestionPipeline.ingest_batch_events(
        events_list=payload.events,
        db=db,
        sensor_id=payload.sensor_id or "suricata-sensor-01"
    )

    if result.get("threats_detected", 0) > 0 and packet_async_queue:
        event_notice = {
            "type": "NIDS_INGESTION_BATCH",
            "timestamp": datetime.utcnow().isoformat(),
            "summary": result
        }
        if event_loop and event_loop.is_running():
            event_loop.call_soon_threadsafe(packet_async_queue.put_nowait, event_notice)

    return result


@app.post("/api/nids/eve/upload")
async def upload_eve_json_file(
    file: UploadFile = File(...),
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """
    Uploads and parses a multi-line Suricata EVE JSON file (eve.json).
    Processes event lines without crashing on malformed lines.
    """
    try:
        content = await file.read()
        lines = content.decode("utf-8", errors="ignore").splitlines()
        events = []
        for line in lines:
            line_s = line.strip()
            if line_s:
                try:
                    events.append(json.loads(line_s))
                except json.JSONDecodeError:
                    pass

        if not events:
            raise HTTPException(status_code=400, detail="No valid JSON lines could be parsed from the provided file.")

        return NIDSIngestionPipeline.ingest_batch_events(events_list=events, db=db)
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"File ingestion error: {str(e)}")


@app.get("/api/nids/events")
async def get_nids_events(
    limit: int = Query(50, ge=1, le=500),
    event_type: Optional[str] = Query(None),
    severity: Optional[int] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns parsed and normalized NIDS security events."""
    query = db.query(SecurityEvent)
    if event_type:
        query = query.filter(SecurityEvent.event_type == event_type.lower())
    if severity is not None:
        query = query.filter(SecurityEvent.severity == severity)
    records = query.order_by(SecurityEvent.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "event_id": r.event_id,
            "sensor_id": r.sensor_id,
            "event_type": r.event_type,
            "timestamp": r.timestamp.isoformat(),
            "src_ip": r.src_ip,
            "src_port": r.src_port,
            "dst_ip": r.dst_ip,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "signature": r.signature,
            "category": r.category,
            "severity": r.severity,
            "flow_id": r.flow_id
        }
        for r in records
    ]


@app.get("/api/nids/sensor/status")
async def get_sensor_status(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns sensor operational status, ingested counts, and active capture mode."""
    total_sec_events = db.query(SecurityEvent).count()
    total_threat_detections = db.query(ThreatDetection).count()
    sensor_cfg = ResponsePolicyEngine.get_system_config(db, "nids_sensor_status", "ACTIVE")
    return {
        "sensor_id": "suricata-sensor-01",
        "status": sensor_cfg if sniffer_running else "WAITING_FOR_TELEMETRY",
        "sniffer_running": sniffer_running,
        "adapter": selected_interface_info,
        "total_security_events": total_sec_events,
        "total_threat_detections": total_threat_detections,
        "filter_mode": capture_filter_mode
    }


@app.get("/api/nids/traffic-tracker/{target_ip}")
async def get_traffic_tracker_metrics(
    target_ip: str,
    current_user: User = Depends(get_current_user)
):
    """Returns real-time 60-second sliding window stateful metrics for target IP."""
    return stateful_tracker.get_metrics(target_ip)


# -----------------------------------------------------------------------------
# API Endpoints — Threat Detections & AI Behavioral Analysis
# -----------------------------------------------------------------------------
@app.get("/api/threats/detections")
async def get_threat_detections(
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns classified ThreatDetection records with investigation status and risk score context."""
    query = db.query(ThreatDetection)
    if status:
        query = query.filter(ThreatDetection.status == status.upper())
    if category:
        query = query.filter(ThreatDetection.attack_category.ilike(f"%{category}%"))
    records = query.order_by(ThreatDetection.timestamp.desc()).limit(limit).all()

    results = []
    for r in records:
        risk = db.query(RiskAssessment).filter(RiskAssessment.threat_id == r.id).first()
        results.append({
            "id": r.id,
            "event_id": r.event_id,
            "timestamp": r.timestamp.isoformat(),
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "src_port": r.src_port,
            "dst_port": r.dst_port,
            "protocol": r.protocol,
            "attack_category": r.attack_category,
            "severity": r.severity,
            "confidence": r.confidence,
            "evidence": r.evidence,
            "status": r.status,
            "assigned_to": r.assigned_to,
            "risk_score": risk.risk_score if risk else (80 if r.severity == "Critical" else 65),
            "risk_band": risk.risk_band if risk else ("Critical" if r.severity == "Critical" else "High"),
            "notes": r.notes
        })
    return results


@app.patch("/api/threats/{threat_id}/status")
async def update_threat_status(
    threat_id: int,
    payload: ThreatStatusUpdate,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """Updates investigation workflow status (OPEN, INVESTIGATING, MITIGATED, RESOLVED, FALSE_POSITIVE)."""
    t = db.query(ThreatDetection).filter(ThreatDetection.id == threat_id).first()
    if not t:
        raise HTTPException(status_code=404, detail="Threat detection not found")
    t.status = payload.status.upper()
    if payload.notes:
        t.notes = payload.notes
    t.assigned_to = current_user.username
    db.commit()
    return {"message": f"Threat #{threat_id} updated to {t.status}", "status": t.status}


@app.get("/api/ai/status")
async def get_ai_model_status(current_user: User = Depends(get_current_user)):
    """Returns machine learning model metadata, version, and training evaluation metrics."""
    metadata = {}
    if os.path.exists(METADATA_FILE):
        try:
            with open(METADATA_FILE, "r") as f:
                metadata = json.load(f)
        except Exception:
            pass
    return {
        "model_loaded": ml_detector.is_loaded,
        "model_name": "IsolationForest",
        "model_version": metadata.get("version", "1.0.0"),
        "trained_at": metadata.get("trained_at"),
        "training_samples": metadata.get("training_samples", 0),
        "evaluation_results": metadata.get("evaluation_results", {}),
        "features": metadata.get("features", []),
        "status": metadata.get("status", "UNINITIALIZED" if not ml_detector.is_loaded else "READY")
    }


@app.post("/api/ai/analyze-host")
async def analyze_host_traffic_endpoint(
    payload: AIAnalyzeHostPayload,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Extracts genuine network flow features for target IP and returns Isolation Forest anomaly inference."""
    records = db.query(PacketLog).filter(
        (PacketLog.src_ip == payload.target_ip) | (PacketLog.dst_ip == payload.target_ip)
    ).order_by(PacketLog.timestamp.desc()).limit(100).all()

    packets = [
        {
            "src_ip": r.src_ip,
            "dst_ip": r.dst_ip,
            "dst_port": r.dst_port,
            "length": 128,
            "protocol": r.protocol,
            "direction": "outbound" if r.src_ip == payload.target_ip else "inbound",
            "payload_ascii": r.payload_sample or ""
        }
        for r in records
    ]

    features = FeatureExtractor.extract_from_packets(packets, host_ip=payload.target_ip)
    analysis = ml_detector.analyze_host_traffic(payload.target_ip, features)

    rec = AIAnalysis(
        target_ip=payload.target_ip,
        model_name="IsolationForest",
        model_version=analysis.get("model_version", "1.0.0"),
        anomaly_score=analysis.get("anomaly_score", 0),
        raw_decision_score=str(analysis.get("raw_decision_score", 0.0)),
        is_anomaly=analysis.get("is_anomaly", False),
        features_json=json.dumps(features),
        explanation=analysis.get("explanation"),
        limitations=analysis.get("limitations")
    )
    db.add(rec)
    db.commit()

    return analysis


# -----------------------------------------------------------------------------
# API Endpoints — Risk Scoring & Response Engine
# -----------------------------------------------------------------------------
@app.get("/api/risk/assessments")
async def get_risk_assessments(
    limit: int = Query(30, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns recent multi-factor risk assessments with factor breakdowns."""
    records = db.query(RiskAssessment).order_by(RiskAssessment.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "threat_id": r.threat_id,
            "src_ip": r.src_ip,
            "timestamp": r.timestamp.isoformat(),
            "risk_score": r.risk_score,
            "risk_band": r.risk_band,
            "contributing_factors": json.loads(r.contributing_factors_json) if r.contributing_factors_json else {},
            "policy_version": r.policy_version,
            "explanation": r.explanation
        }
        for r in records
    ]


@app.get("/api/response/policies")
async def get_response_policies(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Lists configured automated response policies."""
    policies = db.query(ResponsePolicy).order_by(ResponsePolicy.min_risk_score.desc()).all()
    return [
        {
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "min_risk_score": p.min_risk_score,
            "severity_threshold": p.severity_threshold,
            "action_type": p.action_type,
            "duration_seconds": p.duration_seconds,
            "is_enabled": p.is_enabled,
            "allowlist_ips": p.allowlist_ips
        }
        for p in policies
    ]


@app.post("/api/response/policies")
async def create_or_update_policy(
    payload: PolicyPayload,
    current_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Admin-only endpoint to create or update an automated response policy."""
    policy = db.query(ResponsePolicy).filter(ResponsePolicy.name == payload.name).first()
    if policy:
        policy.description = payload.description or policy.description
        policy.min_risk_score = payload.min_risk_score
        policy.severity_threshold = payload.severity_threshold
        policy.action_type = payload.action_type
        policy.duration_seconds = payload.duration_seconds
        policy.is_enabled = payload.is_enabled
        if payload.allowlist_ips:
            policy.allowlist_ips = payload.allowlist_ips
        policy.updated_at = datetime.utcnow()
    else:
        policy = ResponsePolicy(
            name=payload.name,
            description=payload.description,
            min_risk_score=payload.min_risk_score,
            severity_threshold=payload.severity_threshold,
            action_type=payload.action_type,
            duration_seconds=payload.duration_seconds,
            is_enabled=payload.is_enabled,
            allowlist_ips=payload.allowlist_ips or "127.0.0.1,10.0.0.1,192.168.1.1,8.8.8.8,1.1.1.1"
        )
        db.add(policy)

    db.add(AuditLog(
        actor=current_user.username,
        action="CONFIG_RESPONSE_POLICY",
        target=payload.name,
        details=f"Policy {payload.name} configured with min risk score {payload.min_risk_score} and action {payload.action_type}.",
        status="SUCCESS"
    ))
    db.commit()
    return {"message": f"Policy '{payload.name}' saved successfully."}


@app.get("/api/response/actions")
async def get_response_actions(
    limit: int = Query(50, ge=1, le=200),
    status: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns historical and active response actions (simulated vs real, pending, expired, reversed)."""
    query = db.query(ResponseAction)
    if status:
        query = query.filter(ResponseAction.status == status.upper())
    records = query.order_by(ResponseAction.created_at.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "risk_assessment_id": r.risk_assessment_id,
            "threat_id": r.threat_id,
            "target_ip": r.target_ip,
            "action_type": r.action_type,
            "status": r.status,
            "is_simulated": r.is_simulated,
            "reason": r.reason,
            "initiated_by": r.initiated_by,
            "policy_name": r.policy_name,
            "created_at": r.created_at.isoformat(),
            "executed_at": r.executed_at.isoformat() if r.executed_at else None,
            "expires_at": r.expires_at.isoformat() if r.expires_at else None,
            "reversed_at": r.reversed_at.isoformat() if r.reversed_at else None,
            "reversed_by": r.reversed_by,
            "execution_output": r.execution_output
        }
        for r in records
    ]


@app.post("/api/response/actions/{action_id}/approve")
async def approve_response_action(
    action_id: int,
    current_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Admin endpoint to approve and execute a pending response action."""
    act = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not act:
        raise HTTPException(status_code=404, detail="Response action not found")
    if act.status != "PENDING_APPROVAL":
        raise HTTPException(status_code=400, detail=f"Action cannot be approved; status is {act.status}")

    res = ResponseExecutionManager.execute_response(
        db=db,
        target_ip=act.target_ip,
        reason=act.reason,
        actor=f"ADMIN_{current_user.username.upper()}",
        risk_assessment_id=act.risk_assessment_id,
        threat_id=act.threat_id,
        duration_seconds=3600,
        policy_name=act.policy_name
    )
    act.status = res.get("status", "EXECUTED")
    act.executed_at = datetime.utcnow()
    act.initiated_by = current_user.username
    db.commit()
    return {"message": f"Action #{action_id} approved and executed.", "result": res}


@app.post("/api/response/actions/{action_id}/reject")
async def reject_response_action(
    action_id: int,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """Rejects a pending response action."""
    act = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
    if not act:
        raise HTTPException(status_code=404, detail="Response action not found")
    act.status = "REJECTED"
    db.add(AuditLog(
        actor=current_user.username,
        action="REJECT_RESPONSE_ACTION",
        target=act.target_ip,
        details=f"ResponseAction #{action_id} rejected by operator {current_user.username}.",
        status="SUCCESS"
    ))
    db.commit()
    return {"message": f"Action #{action_id} rejected.", "status": "REJECTED"}


@app.post("/api/response/actions/{action_id}/rollback")
async def rollback_response_action(
    action_id: int,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """Rolls back an executed or simulated response action (unblocks target)."""
    res = ResponseExecutionManager.rollback_action(
        db=db,
        action_id=action_id,
        reversed_by=current_user.username
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.post("/api/response/execute-manual")
async def execute_manual_response(
    payload: ManualResponsePayload,
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """Executes an authorized manual response with configured duration."""
    res = ResponseExecutionManager.execute_response(
        db=db,
        target_ip=payload.target_ip,
        reason=payload.reason,
        actor=current_user.username,
        duration_seconds=payload.duration_seconds,
        policy_name="Manual Operator Command"
    )
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error"))
    return res


@app.get("/api/response/system-config")
async def get_response_system_config(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns runtime response configuration (simulation mode, real enforcement toggle, allowlists)."""
    configs = db.query(SystemConfig).all()
    cfg_dict = {c.key: c.value for c in configs}
    fw_info = firewall.get_platform_info()
    return {
        "simulation_mode": cfg_dict.get("simulation_mode", "true").lower() == "true",
        "real_enforcement_authorized": cfg_dict.get("real_enforcement_authorized", "false").lower() == "true",
        "allowlist_ips": cfg_dict.get("allowlist_ips", "127.0.0.1,10.0.0.1,192.168.1.1,8.8.8.8,1.1.1.1,10.0.0.50"),
        "firewall_platform": fw_info["os"],
        "firewall_driver": fw_info["driver"]
    }


@app.post("/api/response/system-config")
async def update_response_system_config(
    payload: SystemConfigUpdatePayload,
    current_user: User = Depends(require_role(["admin"])),
    db: Session = Depends(get_db)
):
    """Admin-only endpoint to update simulation mode, real enforcement, and allowlists."""
    for k, v in payload.configs.items():
        cfg = db.query(SystemConfig).filter(SystemConfig.key == k).first()
        if cfg:
            cfg.value = str(v).strip()
            cfg.updated_at = datetime.utcnow()
        else:
            db.add(SystemConfig(key=k, value=str(v).strip()))

    db.add(AuditLog(
        actor=current_user.username,
        action="UPDATE_SYSTEM_CONFIG",
        target="Response Engine",
        details=f"System configs updated by {current_user.username}: {list(payload.configs.keys())}",
        status="SUCCESS"
    ))
    db.commit()
    return {"message": "System configuration updated successfully."}


@app.get("/api/system/audit-logs")
async def get_audit_logs(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """Retrieves immutable system audit records."""
    records = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    return [
        {
            "id": r.id,
            "timestamp": r.timestamp.isoformat(),
            "actor": r.actor,
            "action": r.action,
            "target": r.target,
            "details": r.details,
            "status": r.status
        }
        for r in records
    ]


@app.get("/api/reports/download/csv")
async def download_csv_report(
    range: str = Query("daily", pattern="^(daily|weekly|monthly)$"),
    current_user: User = Depends(require_role(["admin", "analyst"])),
    db: Session = Depends(get_db)
):
    """Streams RFC 4180 CSV export of security events, threats, and firewall actions."""
    csv_buf = reports.generate_csv_report(timeframe=range, db=db)
    filename = f"SecureNet_Audit_Report_{range}_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}.csv"
    return StreamingResponse(
        iter([csv_buf.getvalue()]),
        media_type="text/csv",
        headers={"Content-Disposition": f"attachment; filename={filename}"}
    )


# -----------------------------------------------------------------------------
# WebSocket Stream Pipeline
# -----------------------------------------------------------------------------

@app.websocket("/ws/stream")
async def websocket_stream_endpoint(
    websocket: WebSocket,
    token: Optional[str] = Query(None)
):
    """
    Real-time packet telemetry WebSocket endpoint.
    Performs role-based connection authorization:
    - Admin/Analyst: Full 5-tuple, Hex Dump & ASCII payload view.
    - Employee: Sanitized overview with redacted payload.
    """
    role = "employee"
    if token:
        try:
            payload = decode_supabase_jwt(token)
            user_meta = payload.get("user_metadata") or {}
            app_meta = payload.get("app_metadata") or {}
            r = user_meta.get("role") or app_meta.get("role") or payload.get("role")
            if r in ["admin", "analyst", "employee"]:
                role = r
            else:
                email = (payload.get("email") or "").lower()
                sub = (payload.get("sub") or "").lower()
                if "admin" in email or "admin" in sub:
                    role = "admin"
                elif "analyst" in email or "analyst" in sub:
                    role = "analyst"
                else:
                    role = "admin"
        except (JWTError, KeyError, ValueError) as token_err:
            print(f"[WebSocket Auth Notice] Token validation failed: {token_err}")
            role = "employee"

    await manager.connect(websocket, role)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except (RuntimeError, ConnectionResetError):
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
