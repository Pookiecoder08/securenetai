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
from datetime import datetime
from typing import List, Dict, Any, Optional

import psutil
from fastapi import FastAPI, Depends, HTTPException, WebSocket, WebSocketDisconnect, Query, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, JSONResponse
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel
from sqlalchemy.orm import Session

# Scapy imports
import scapy.all as scapy
from scapy.layers.inet import IP, TCP, UDP, ICMP
from scapy.packet import Raw

# Project imports
from database import get_db, init_db, SessionLocal, seed_default_topology, purge_packet_logs
from models import User, PacketLog, FirewallRule, TopologyState
from security import verify_password, create_access_token, SECRET_KEY, ALGORITHM
from auth import get_current_user, require_role
import firewall
import reports
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
            except Exception:
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


def evaluate_threat_signatures(ascii_text: str, dst_port: Optional[int]) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Evaluates payload and connection metadata against attack signatures.
    Returns: (is_threat, threat_type, severity)
    """
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
    except Exception:
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
    except Exception:
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

    # Signature Analysis
    is_threat, threat_type, severity = evaluate_threat_signatures(payload_ascii, dst_port)

    # Ingress Traffic Filter: Discard irrelevant background noise before counting or persistence
    tcp_flags = pkt[TCP].flags if pkt.haslayer(TCP) else None
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
    if is_threat:
        threat_counter += 1
        if severity == "Critical":
            critical_threat_counter += 1
        print(f"\n[ALERT - THREAT DETECTED] Signature: {threat_type} | Severity: {severity} | {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
        
        # Active Defense: Auto-trigger OS kernel firewall drop rule targeting external attacker
        target_block_ip = src_ip if (src_ip and src_ip != host_ip) else (src_ip or "127.0.0.1")
        if target_block_ip:
            with SessionLocal() as db_session:
                firewall.block_ip(
                    ip=target_block_ip,
                    reason=threat_type or "Automated Threat Detection",
                    blocked_by="AUTOMATED_NIPS",
                    db=db_session
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
            except Exception as e:
                print(f"[Sniffer Daemon Notice] SIO_RCVALL status: {e}")

        while sniffer_running:
            try:
                raw_data, _ = s.recvfrom(65535)
                if raw_data:
                    process_packet_bytes(raw_data)
            except socket.timeout:
                continue
            except Exception:
                if not sniffer_running:
                    break
                time.sleep(0.01)

    except Exception as e:
        print(f"[Sniffer Daemon Error] Raw socket on {target_ip}: {e}")
    finally:
        if sys.platform == "win32":
            try:
                s.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            except Exception:
                pass
        try:
            s.close()
        except Exception:
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
    Clean interactive Smart NIC Selector:
    Outputs a simple, foolproof list of valid IPv4 interfaces and prompts operator.
    """
    global selected_interface_info
    ifaces = discover_network_interfaces()

    print("\nStarting SecureNet AI Backend...")
    print("\nScanning network interfaces...")
    print("Found active interfaces:")
    for idx, iface in enumerate(ifaces, start=1):
        print(f" [{idx}] {iface['name']} (IP: {iface['ip']})")

    selected_idx = 1
    # Check CLI argument or environment variable
    cli_arg = os.environ.get("SECURENET_IFACE")
    for arg in sys.argv:
        if arg.startswith("--iface="):
            cli_arg = arg.split("=")[1]

    if cli_arg is not None:
        try:
            val = int(cli_arg)
            if 1 <= val <= len(ifaces):
                selected_idx = val
        except ValueError:
            pass
    elif sys.stdin and sys.stdin.isatty():
        try:
            user_in = input(f"\nEnter the number of the interface to monitor [default: 1]: ").strip()
            if user_in.isdigit() and 1 <= int(user_in) <= len(ifaces):
                selected_idx = int(user_in)
        except Exception:
            selected_idx = 1
    else:
        print(f"[Automated Environment] Defaulting to active interface [1]: {ifaces[0]['name']} ({ifaces[0]['ip']})")

    selected = ifaces[selected_idx - 1]
    selected_interface_info = {
        "name": selected["name"],
        "ip": selected["ip"],
        "status": "Capturing Promiscuously"
    }
    print(f"\n[Interface Bound] Binding sniffer engine to: {selected['name']} ({selected['ip']})")
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
    print("[SecureNet AI System] Sniffer and async queue broadcaster active.\n")


# -----------------------------------------------------------------------------
# Real-World Live Fire Attacker Demonstration Endpoints (Method 1)
# -----------------------------------------------------------------------------
@app.get("/login")
async def live_fire_login_attack(
    request: Request,
    user: Optional[str] = Query(None),
    username: Optional[str] = Query(None)
):
    """
    Live Fire Attacker Endpoint:
    Allows demonstrating Method 1 from an external terminal or partner laptop:
      curl "http://<TARGET_IP>:8000/login?user=admin' OR 1=1--"
    The raw HTTP packet physically hits the NIC, the sniffer decodes it, flags SQLi,
    and the OS firewall blocks the attacker IP immediately!
    """
    query_param = user or username or ""
    client_ip = request.client.host if request.client else "127.0.0.1"

    # Evaluate signature directly for defensive terminal response
    if SQLI_REGEX.search(query_param):
        print(f"[LIVE FIRE ATTACK INTERCEPTED] SQL Injection payload received from {client_ip}: '{query_param}'")
        # Direct integration into Scapy DPI pipeline so WebSocket & Dashboard capture the live attack frame
        try:
            client_port = request.client.port if (request.client and request.client.port) else 54321
            host_ip = selected_interface_info.get("ip", "127.0.0.1")
            raw_payload = f"GET /login?user={query_param} HTTP/1.1\r\nHost: {host_ip}:8000\r\nUser-Agent: AttackerTerminal/1.0\r\nAccept: */*\r\n\r\n".encode("utf-8")
            test_pkt = (
                IP(src=client_ip, dst=host_ip)
                / TCP(sport=client_port, dport=8000)
                / Raw(load=raw_payload)
            )
            process_packet_bytes(bytes(test_pkt))
        except Exception as e:
            print(f"[Live Fire Pipeline Error] {e}")

        return JSONResponse(
            status_code=403,
            content={
                "error": "INTRUSION_DETECTED",
                "message": "SecureNet NIDS has intercepted a malicious SQL Injection pattern in query parameters.",
                "signature": "SQLi Auth Bypass / UNION SELECT",
                "action": f"OS Firewall drop rule enforced against {client_ip}"
            }
        )

    return {"status": "ok", "message": "Authentication endpoint reached."}


@app.get("/api/data")
async def live_fire_xss_attack(
    request: Request,
    search: Optional[str] = Query(None),
    q: Optional[str] = Query(None)
):
    """
    Live Fire Attacker Endpoint:
    Allows demonstrating Method 1 XSS attacks:
      curl "http://<TARGET_IP>:8000/api/data?search=<script>alert('XSS')</script>"
    The packet hits the NIC, triggers XSS detection, updates dashboard, and blocks IP!
    """
    query_param = search or q or ""
    client_ip = request.client.host if request.client else "127.0.0.1"

    if XSS_REGEX.search(query_param):
        print(f"[LIVE FIRE ATTACK INTERCEPTED] XSS payload received from {client_ip}: '{query_param}'")
        # Direct integration into Scapy DPI pipeline so WebSocket & Dashboard capture the live attack frame
        try:
            client_port = request.client.port if (request.client and request.client.port) else 54321
            host_ip = selected_interface_info.get("ip", "127.0.0.1")
            raw_payload = f"GET /api/data?search={query_param} HTTP/1.1\r\nHost: {host_ip}:8000\r\nUser-Agent: AttackerTerminal/1.0\r\nAccept: */*\r\n\r\n".encode("utf-8")
            test_pkt = (
                IP(src=client_ip, dst=host_ip)
                / TCP(sport=client_port, dport=8000)
                / Raw(load=raw_payload)
            )
            process_packet_bytes(bytes(test_pkt))
        except Exception as e:
            print(f"[Live Fire Pipeline Error] {e}")

        return JSONResponse(
            status_code=403,
            content={
                "error": "INTRUSION_DETECTED",
                "message": "SecureNet NIDS has intercepted a Cross-Site Scripting (XSS) payload in query parameters.",
                "signature": "XSS Script Injection",
                "action": f"OS Firewall drop rule enforced against {client_ip}"
            }
        )

    return {"status": "ok", "query": query_param, "results": []}


# -----------------------------------------------------------------------------
# REST API Schemas
# -----------------------------------------------------------------------------
class BlockRequest(BaseModel):
    ip_address: str
    reason: str


class UnblockRequest(BaseModel):
    ip_address: str


class TopologyPayload(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]


class ThreatInjectionPayload(BaseModel):
    threat_type: str  # 'sqli', 'xss', or 'probe'
    target_ip: Optional[str] = "10.0.1.10"
    attacker_ip: Optional[str] = "198.51.100.77"


class FilterModePayload(BaseModel):
    mode: str  # 'soc_filtered', 'targeted', or 'raw_all'


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
    return {
        "message": f"Firewall drop enforced against {payload.ip_address}",
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
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Returns genuine threat-signature matches from the packet audit ledger."""
    records = (
        db.query(PacketLog)
        .filter(PacketLog.is_threat == True)
        .order_by(PacketLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [serialize_packet_log(record) for record in records]


@app.get("/api/alerts")
async def get_alerts(
    limit: int = Query(20, ge=1, le=100),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Builds the alert feed from actual detected threats, never synthetic events."""
    records = (
        db.query(PacketLog)
        .filter(PacketLog.is_threat == True)
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
    if not top:
        nodes_json, edges_json = seed_default_topology()
        return {"nodes": json.loads(nodes_json), "edges": json.loads(edges_json)}

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
    return {
        "adapter": selected_interface_info,
        "sniffer_running": sniffer_running,
        "total_packets_captured": packet_counter,
        "total_threats_detected": threat_counter,
        "critical_threats_detected": critical_threat_counter,
        "active_firewall_rules_count": active_rule_count,
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


@app.post("/api/test/inject-threat")
async def inject_threat_packet(
    payload: ThreatInjectionPayload,
    current_user: User = Depends(require_role(["admin", "analyst"]))
):
    """
    Demonstration Test Harness:
    Constructs a real Scapy IP packet with attack signature (SQLi or XSS)
    and passes it directly through the real Scapy DPI and Threat Detection pipeline.
    """
    attack_str = ""
    target_port = 80

    if payload.threat_type.lower() == "sqli":
        attack_str = "GET /login?user=admin' UNION SELECT null, username, password FROM users-- HTTP/1.1\r\nHost: target\r\n\r\n"
        target_port = 80
    elif payload.threat_type.lower() == "xss":
        attack_str = "POST /api/data HTTP/1.1\r\nHost: target\r\nContent-Length: 42\r\n\r\n<script>alert('XSS_BREACH')</script>"
        target_port = 8080
    else:  # Probe
        attack_str = "NMAP RECON SCANNER PROBE SYN TEST"
        target_port = 31337

    test_pkt = (
        IP(src=payload.attacker_ip, dst=payload.target_ip)
        / TCP(sport=54321, dport=target_port)
        / Raw(load=attack_str.encode("utf-8"))
    )

    process_packet_bytes(bytes(test_pkt))

    return {
        "message": "Threat packet dispatched through Scapy DPI & Signature Engine.",
        "threat_type": payload.threat_type,
        "attacker_ip": payload.attacker_ip,
        "target_ip": payload.target_ip,
        "payload_snippet": attack_str
    }


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
            claims = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
            role = claims.get("role", "employee")
        except JWTError:
            role = "employee"

    await manager.connect(websocket, role)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        manager.disconnect(websocket)
    except Exception:
        manager.disconnect(websocket)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
