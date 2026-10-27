"""
SecureNet AI — NIDS Telemetry Ingestion & Threat Classification Engine
Provides enterprise-grade ingestion for Suricata EVE JSON and standard NIDS telemetry.
Handles event parsing, field normalization, deduplication, schema validation,
and deterministic rule-based threat classification.
"""

import json
import logging
import re
import time
import threading
from collections import defaultdict, deque
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple, Deque
from sqlalchemy.orm import Session

from models import SecurityEvent, ThreatDetection, PacketLog

logger = logging.getLogger("securenet.nids")

# -----------------------------------------------------------------------------
# Attack Signatures & Regex Patterns
# -----------------------------------------------------------------------------
SQLI_PATTERN = re.compile(
    r"(\bUNION\b.{1,50}\bSELECT\b)|('(\s|%20)*(OR|AND)(\s|%20)+)|(--\s)|(\bOR\b\s+[\w\d]+\s*=\s*[\w\d]+)|(;\s*DROP\b)|(;\s*SELECT\b)|(\b1\s*=\s*1\b)|('1'='1')",
    re.IGNORECASE
)

XSS_PATTERN = re.compile(
    r"(<script.*?>.*?</script>)|(javascript:)|(onerror\s*=)|(onload\s*=)|(<img.*?src=.*?onerror=)|(alert\s*\(.*?\))|(<svg.*?onload=)",
    re.IGNORECASE
)

PATH_TRAVERSAL_PATTERN = re.compile(
    r"(\.\./\.\./)|(\.\.\\\.\.\\)|(/etc/passwd)|(/boot\.ini)|(win\.ini)|(\.\.%2f)",
    re.IGNORECASE
)

COMMAND_INJECTION_PATTERN = re.compile(
    r"(;\s*cat\s+/etc)|(\|\s*whoami)|(&&\s*net\s+user)|(\$\(whoami\))|(;\s*id\b)",
    re.IGNORECASE
)

SUSPICIOUS_DNS_TLDS = {".xyz", ".top", ".tk", ".pw", ".bid", ".club", ".country", ".onion"}
RECON_PORTS = {21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 27017, 31337}

# -----------------------------------------------------------------------------
# Suricata EVE JSON Parser & Normalizer
# -----------------------------------------------------------------------------
class EveJsonParser:
    """
    Parses and normalizes raw Suricata EVE JSON objects into standardized telemetry events.
    Robustly handles absent fields and malformed payloads without crashing.
    """

    @staticmethod
    def parse_eve_record(record: Any) -> Optional[Dict[str, Any]]:
        """Parses a single dict or JSON string into a normalized security event dict."""
        if isinstance(record, str):
            try:
                record = json.loads(record.strip())
            except Exception as e:
                logger.warning(f"Failed to parse EVE JSON string: {e}")
                return None

        if not isinstance(record, dict):
            return None

        # Parse timestamp safely
        raw_ts = record.get("timestamp")
        parsed_ts = datetime.utcnow()
        if raw_ts:
            try:
                if isinstance(raw_ts, str):
                    ts_clean = raw_ts.replace("Z", "+00:00")
                    if "+" in ts_clean and len(ts_clean.split("+")[-1]) == 4:
                        prefix, tz = ts_clean.rsplit("+", 1)
                        ts_clean = f"{prefix}+{tz[:2]}:{tz[2:]}"
                    parsed_ts = datetime.fromisoformat(ts_clean)
            except Exception:
                parsed_ts = datetime.utcnow()

        event_type = str(record.get("event_type", "alert")).lower()
        src_ip = record.get("src_ip") or record.get("source_ip") or "0.0.0.0"
        dst_ip = record.get("dest_ip") or record.get("dst_ip") or record.get("destination_ip") or "0.0.0.0"
        src_port = record.get("src_port")
        dst_port = record.get("dest_port") or record.get("dst_port")
        protocol = str(record.get("proto") or record.get("protocol") or "TCP").upper()

        signature_id = None
        signature = None
        category = None
        severity = 3  # Default medium/low

        # Extract alert sub-object if present (standard Suricata alert structure)
        alert_info = record.get("alert")
        if isinstance(alert_info, dict):
            signature_id = alert_info.get("signature_id") or alert_info.get("sid")
            signature = alert_info.get("signature")
            category = alert_info.get("category")
            raw_sev = alert_info.get("severity")
            if raw_sev is not None:
                try:
                    severity = int(raw_sev)
                except (ValueError, TypeError):
                    severity = 2
        elif event_type == "anomaly":
            anomaly_info = record.get("anomaly", {})
            signature = anomaly_info.get("type", "Protocol Anomaly Detected")
            category = "Protocol Anomaly"
            severity = 2
        elif event_type == "dns":
            dns_info = record.get("dns", {})
            signature = f"DNS Query: {dns_info.get('rrname', 'unknown')}"
            category = "DNS Telemetry"
            severity = 4
        elif event_type == "http":
            http_info = record.get("http", {})
            signature = f"HTTP {http_info.get('http_method', 'REQ')}: {http_info.get('url', '/')}"
            category = "HTTP Telemetry"
            severity = 4

        return {
            "event_id": str(record.get("flow_id") or record.get("event_id") or f"{src_ip}-{dst_ip}-{int(parsed_ts.timestamp())}"),
            "sensor_id": str(record.get("sensor_id") or record.get("host") or "suricata-sensor-01"),
            "event_type": event_type,
            "timestamp": parsed_ts,
            "src_ip": str(src_ip),
            "src_port": int(src_port) if src_port is not None else None,
            "dst_ip": str(dst_ip),
            "dst_port": int(dst_port) if dst_port is not None else None,
            "protocol": protocol,
            "signature_id": int(signature_id) if signature_id is not None else None,
            "signature": signature,
            "category": category,
            "severity": severity,
            "flow_id": str(record.get("flow_id") or "") if record.get("flow_id") else None,
            "raw_details": json.dumps(record) if isinstance(record, dict) else str(record)
        }


# -----------------------------------------------------------------------------
# Stateful Traffic Tracker (Sliding-Window Telemetry)
# -----------------------------------------------------------------------------
class StatefulTrafficTracker:
    """
    Maintains an in-memory sliding window (default 60 seconds) of network activity per Source IP.
    Tracks packet timestamps, byte sizes, TCP flags, destination ports, and protocols to
    enable native, deterministic detection of DDoS (SYN / Volumetric floods) and Brute-Force attacks
    directly on live scapy capture streams without relying on external signatures.
    """

    AUTH_PORTS = {21, 22, 3389}  # FTP, SSH, RDP
    HTTP_PORTS = {80, 443, 8000, 8080, 5000, 5173, 8443}
    LOGIN_KEYWORDS = ("/login", "login", "signin", "authenticate", "auth", "wp-login", "user/login")

    def __init__(self, window_seconds: float = 60.0):
        self.window_seconds = float(window_seconds)
        self._traffic: Dict[str, Deque[Dict[str, Any]]] = defaultdict(deque)
        self._lock = threading.Lock()
        self._last_cleanup = time.time()

    def _resolve_now(self, dq: Optional[Deque[Dict[str, Any]]] = None, now: Optional[float] = None) -> float:
        """Resolves reference timestamp, supporting synthetic timestamps in tests and PCAP replay."""
        if now is not None:
            return float(now)
        real_now = time.time()
        if dq and len(dq) > 0 and abs(real_now - dq[-1]["timestamp"]) > 3600.0:
            return float(dq[-1]["timestamp"])
        return real_now

    def record_packet(
        self,
        src_ip: str,
        size: int,
        tcp_flags: Optional[Any] = None,
        dst_port: Optional[int] = None,
        dst_ip: Optional[str] = None,
        protocol: str = "TCP",
        payload_sample: str = "",
        timestamp: Optional[float] = None
    ) -> Dict[str, Any]:
        """
        Appends packet metadata to the sliding window for src_ip, prunes expired
        entries older than window_seconds, and returns computed stateful metrics.
        """
        if not src_ip or src_ip == "0.0.0.0":
            return {}

        now = float(timestamp) if timestamp is not None else time.time()
        proto_clean = str(protocol or "TCP").upper()
        flag_str = str(tcp_flags) if tcp_flags is not None else ""

        # Identify TCP SYN frame: SYN set without ACK, or minimal TCP probe frame
        is_syn = False
        if "S" in flag_str and "A" not in flag_str:
            is_syn = True
        elif flag_str == "S" or flag_str == "0x02":
            is_syn = True
        elif proto_clean == "TCP" and size <= 64 and ("S" in flag_str or not flag_str):
            is_syn = True

        # Identify authentication / login connection attempts
        is_auth = False
        if dst_port in self.AUTH_PORTS:
            # Connections directed against FTP, SSH, or RDP auth services
            if is_syn or not flag_str or size > 0:
                is_auth = True
        elif dst_port in self.HTTP_PORTS or proto_clean in ("HTTP", "HTTPS"):
            # HTTP/HTTPS requests targeting login endpoints
            lower_sample = payload_sample.lower() if payload_sample else ""
            if any(kw in lower_sample for kw in self.LOGIN_KEYWORDS):
                is_auth = True

        packet_entry = {
            "timestamp": now,
            "size": int(size) if size else 64,
            "tcp_flags": flag_str,
            "is_syn": is_syn,
            "dst_port": int(dst_port) if dst_port is not None else None,
            "dst_ip": str(dst_ip) if dst_ip else None,
            "protocol": proto_clean,
            "payload_sample": payload_sample[:128] if payload_sample else "",
            "is_auth_attempt": is_auth
        }

        with self._lock:
            dq = self._traffic[src_ip]
            dq.append(packet_entry)

            # Filter records strictly within the window
            effective_now = self._resolve_now(dq, timestamp)
            cutoff = effective_now - self.window_seconds
            self._traffic[src_ip] = deque(p for p in dq if p["timestamp"] >= cutoff)

            # Periodic cleanup of inactive IPs (every 15 seconds)
            if effective_now - self._last_cleanup > 15.0:
                self._prune_inactive_locked(effective_now)

        return self.get_metrics(src_ip, now=timestamp)

    def _prune_inactive_locked(self, now: float):
        """Prunes stale IPs from tracker to prevent memory leaks."""
        cutoff = now - self.window_seconds
        stale_ips = []
        for ip, dq in list(self._traffic.items()):
            dq_filtered = deque(p for p in dq if p["timestamp"] >= cutoff)
            if dq_filtered:
                self._traffic[ip] = dq_filtered
            else:
                stale_ips.append(ip)
        for ip in stale_ips:
            self._traffic.pop(ip, None)
        self._last_cleanup = now

    def prune_expired(self, now: Optional[float] = None):
        """Explicitly triggers sliding window cleanup across all IPs."""
        with self._lock:
            current_time = self._resolve_now(None, now)
            self._prune_inactive_locked(current_time)

    def calculate_packets_per_second(self, src_ip: str, now: Optional[float] = None) -> float:
        """Calculates instantaneous/rolling packet rate (pps) for src_ip within the sliding window."""
        with self._lock:
            dq = self._traffic.get(src_ip)
            if not dq:
                return 0.0
            current_time = self._resolve_now(dq, now)
            cutoff = current_time - self.window_seconds
            self._traffic[src_ip] = deque(p for p in dq if p["timestamp"] >= cutoff)
            dq = self._traffic[src_ip]
            if not dq:
                return 0.0
            time_span = max(current_time - dq[0]["timestamp"], 1.0)
            return round(len(dq) / time_span, 2)

    def calculate_tcp_syn_ratio(self, src_ip: str, now: Optional[float] = None) -> float:
        """Calculates ratio of TCP SYN frames to total frames (0.0 to 1.0) within sliding window."""
        with self._lock:
            dq = self._traffic.get(src_ip)
            if not dq:
                return 0.0
            current_time = self._resolve_now(dq, now)
            cutoff = current_time - self.window_seconds
            self._traffic[src_ip] = deque(p for p in dq if p["timestamp"] >= cutoff)
            dq = self._traffic[src_ip]
            if not dq:
                return 0.0
            syn_count = sum(1 for p in dq if p["is_syn"])
            return round(float(syn_count) / max(len(dq), 1), 3)

    def calculate_auth_connection_count(self, src_ip: str, now: Optional[float] = None) -> int:
        """Counts connections to authentication ports (21, 22, 3389) or HTTP login endpoints in window."""
        with self._lock:
            dq = self._traffic.get(src_ip)
            if not dq:
                return 0
            current_time = self._resolve_now(dq, now)
            cutoff = current_time - self.window_seconds
            self._traffic[src_ip] = deque(p for p in dq if p["timestamp"] >= cutoff)
            dq = self._traffic[src_ip]
            return sum(1 for p in dq if p["is_auth_attempt"])

    # Method aliases for convenience
    def packets_per_second(self, src_ip: str) -> float:
        return self.calculate_packets_per_second(src_ip)

    def tcp_syn_ratio(self, src_ip: str) -> float:
        return self.calculate_tcp_syn_ratio(src_ip)

    def auth_connection_count(self, src_ip: str) -> int:
        return self.calculate_auth_connection_count(src_ip)

    def get_metrics(self, src_ip: str, now: Optional[float] = None) -> Dict[str, Any]:
        """Returns consolidated stateful flow metrics for src_ip in the sliding window."""
        with self._lock:
            dq = self._traffic.get(src_ip)
            if not dq:
                return {
                    "src_ip": src_ip,
                    "packets_in_window": 0,
                    "packets_per_second": 0.0,
                    "tcp_syn_ratio": 0.0,
                    "auth_connection_count": 0,
                    "total_bytes": 0,
                    "avg_bytes": 0.0,
                    "avg_bytes_per_pkt": 0.0,
                    "bandwidth_bytes_per_sec": 0.0,
                    "udp_bytes_per_sec": 0.0,
                    "udp_pps": 0.0,
                    "unique_dst_ports": 0,
                    "unique_dst_ips": 0,
                    "window_seconds": self.window_seconds
                }

            current_time = self._resolve_now(dq, now)
            cutoff = current_time - self.window_seconds
            self._traffic[src_ip] = deque(p for p in dq if p["timestamp"] >= cutoff)
            dq = self._traffic[src_ip]

            count = len(dq)
            if count == 0:
                return {
                    "src_ip": src_ip,
                    "packets_in_window": 0,
                    "packets_per_second": 0.0,
                    "tcp_syn_ratio": 0.0,
                    "auth_connection_count": 0,
                    "total_bytes": 0,
                    "avg_bytes": 0.0,
                    "avg_bytes_per_pkt": 0.0,
                    "bandwidth_bytes_per_sec": 0.0,
                    "udp_bytes_per_sec": 0.0,
                    "udp_pps": 0.0,
                    "unique_dst_ports": 0,
                    "unique_dst_ips": 0,
                    "window_seconds": self.window_seconds
                }

            time_span = max(current_time - dq[0]["timestamp"], 1.0)
            total_bytes = sum(p["size"] for p in dq)
            syn_count = sum(1 for p in dq if p["is_syn"])
            auth_count = sum(1 for p in dq if p["is_auth_attempt"])
            udp_packets = [p for p in dq if p["protocol"] == "UDP"]
            udp_bytes = sum(p["size"] for p in udp_packets)
            unique_ports = {p["dst_port"] for p in dq if p["dst_port"] is not None}
            unique_ips = {p["dst_ip"] for p in dq if p["dst_ip"]}

            avg_b = round(float(total_bytes) / count, 2)
            pps = round(float(count) / time_span, 2)
            syn_r = round(float(syn_count) / count, 3)
            bw_bps = round(float(total_bytes) / time_span, 2)
            udp_bps = round(float(udp_bytes) / time_span, 2)
            udp_pps = round(float(len(udp_packets)) / time_span, 2)

            return {
                "src_ip": src_ip,
                "packets_in_window": count,
                "packets_per_second": pps,
                "tcp_syn_ratio": syn_r,
                "auth_connection_count": auth_count,
                "total_bytes": total_bytes,
                "avg_bytes": avg_b,
                "avg_bytes_per_pkt": avg_b,
                "bandwidth_bytes_per_sec": bw_bps,
                "udp_bytes_per_sec": udp_bps,
                "udp_pps": udp_pps,
                "unique_dst_ports": len(unique_ports),
                "unique_dst_ips": len(unique_ips),
                "window_seconds": self.window_seconds
            }

    def get_packets_for_ip(self, src_ip: str, now: Optional[float] = None) -> List[Dict[str, Any]]:
        """Returns all packet records for src_ip formatted for FeatureExtractor."""
        with self._lock:
            dq = self._traffic.get(src_ip)
            if not dq:
                return []
            current_time = self._resolve_now(dq, now)
            cutoff = current_time - self.window_seconds
            self._traffic[src_ip] = deque(p for p in dq if p["timestamp"] >= cutoff)
            dq = self._traffic[src_ip]
            return [
                {
                    "src_ip": src_ip,
                    "dst_ip": p["dst_ip"] or "127.0.0.1",
                    "dst_port": p["dst_port"],
                    "length": p["size"],
                    "protocol": p["protocol"],
                    "direction": "outbound",
                    "tcp_flags": p["tcp_flags"],
                    "payload_ascii": p["payload_sample"]
                }
                for p in dq
            ]

    def has_ip(self, src_ip: str) -> bool:
        """Returns True if tracker currently holds active packets for src_ip."""
        with self._lock:
            dq = self._traffic.get(src_ip)
            return bool(dq and len(dq) > 0)

    def clear(self):
        """Resets all tracked state."""
        with self._lock:
            self._traffic.clear()
            self._last_cleanup = time.time()


# Global Singleton Traffic Tracker
stateful_tracker = StatefulTrafficTracker(window_seconds=60.0)


# -----------------------------------------------------------------------------
# Threat Classification Layer
# -----------------------------------------------------------------------------
class ThreatClassifier:
    """
    Evaluates normalized security events, network flows, and stateful traffic metrics
    against deterministic NIDS/NIPS rules. Accurately detects Brute Force, TCP SYN floods,
    Volumetric floods, and application-layer exploits.
    """

    @staticmethod
    def classify_event(
        event: Dict[str, Any],
        payload_sample: Optional[str] = None,
        stateful_metrics: Optional[Dict[str, Any]] = None,
        tracker: Optional[StatefulTrafficTracker] = None
    ) -> Tuple[bool, Optional[str], Optional[str], int, str]:
        """
        Evaluates a normalized event and stateful metrics against deterministic rules.
        Returns:
            (is_threat: bool,
             attack_category: Optional[str],
             severity: Optional[str],
             confidence: int,
             evidence: str)
        """
        src_ip = event.get("src_ip") or "0.0.0.0"
        signature = (event.get("signature") or "").lower()
        category = (event.get("category") or "").lower()
        dst_port = event.get("dst_port")
        raw_sev = event.get("severity", 3)
        raw_details = event.get("raw_details") or ""
        payload = payload_sample or ""

        search_blob = f"{signature} {category} {payload} {raw_details}".lower()

        # Resolve timestamp from event if provided
        event_ts = None
        raw_ts = event.get("timestamp")
        if isinstance(raw_ts, datetime):
            event_ts = raw_ts.timestamp()
        elif isinstance(raw_ts, (int, float)):
            event_ts = float(raw_ts)

        # Resolve stateful metrics if not directly supplied
        if stateful_metrics is None:
            if tracker is not None:
                stateful_metrics = tracker.get_metrics(src_ip, now=event_ts)
            elif event.get("stateful_metrics"):
                stateful_metrics = event["stateful_metrics"]
            elif src_ip and src_ip != "0.0.0.0" and stateful_tracker.has_ip(src_ip):
                stateful_metrics = stateful_tracker.get_metrics(src_ip, now=event_ts)

        # ---------------------------------------------------------------------
        # 1. Native Stateful Traffic Anomaly Rules (DDoS & Brute Force)
        # ---------------------------------------------------------------------
        if stateful_metrics:
            pps = float(stateful_metrics.get("packets_per_second", 0.0))
            syn_ratio = float(stateful_metrics.get("tcp_syn_ratio", 0.0))
            avg_bytes = float(stateful_metrics.get("avg_bytes", stateful_metrics.get("avg_bytes_per_pkt", 0.0)))
            auth_conns = int(stateful_metrics.get("auth_connection_count", 0))
            bandwidth_bps = float(stateful_metrics.get("bandwidth_bytes_per_sec", 0.0))
            udp_volume_bps = float(stateful_metrics.get("udp_bytes_per_sec", 0.0))
            udp_pps = float(stateful_metrics.get("udp_pps", 0.0))

            # Rule 1A: DDoS - TCP SYN Flood
            # Condition: > 100 packets/sec AND tcp_syn_ratio > 80% (0.80) AND avg_bytes < 100
            if pps > 100.0 and syn_ratio > 0.80 and avg_bytes < 100.0:
                return (
                    True,
                    "TCP SYN Flood (DDoS)",
                    "Critical",
                    98,
                    f"Stateful TCP SYN flood detected from {src_ip}: {pps:.1f} pkts/sec, {syn_ratio*100:.1f}% SYN ratio, avg frame size {avg_bytes:.1f} bytes in 60s window"
                )

            # Rule 1B: DDoS - Volumetric Flood
            # Condition: Exceeds bandwidth threshold (> 10 MB/s or massive UDP volume) within sliding window
            ten_mb_s = 10.0 * 1024.0 * 1024.0
            five_mb_s = 5.0 * 1024.0 * 1024.0
            if bandwidth_bps > ten_mb_s or udp_volume_bps > five_mb_s or (udp_pps > 500.0 and bandwidth_bps > (1024.0 * 1024.0)):
                mb_s = bandwidth_bps / (1024.0 * 1024.0)
                return (
                    True,
                    "Volumetric DoS Attack",
                    "Critical",
                    98,
                    f"Stateful volumetric flood detected from {src_ip}: {mb_s:.2f} MB/s bandwidth consumption ({udp_pps:.0f} UDP pps) exceeding 10 MB/s defense threshold"
                )

            # Rule 1C: Brute-Force Authentication
            # Condition: Initiates > 20 connections to authentication ports (22, 3389, 21) or HTTP login endpoints within 60s
            if auth_conns > 20:
                return (
                    True,
                    "Brute-Force Authentication Attempt",
                    "High",
                    92,
                    f"Stateful brute-force threshold exceeded from {src_ip}: {auth_conns} authentication attempts in 60s sliding window targeting auth services"
                )

        # ---------------------------------------------------------------------
        # 2. Deterministic Application-Layer Signatures (SQLi, XSS, RCE, LFI)
        # ---------------------------------------------------------------------
        # 2A. SQL Injection (SQLi)
        if SQLI_PATTERN.search(payload) or "sql injection" in signature or "sqli" in signature:
            return (
                True,
                "SQL Injection (SQLi) Attempt",
                "Critical",
                95,
                f"SQL syntax manipulation pattern or NIDS signature match: '{signature or 'UNION SELECT / Auth Bypass'}' targeting port {dst_port}"
            )

        # 2B. Cross-Site Scripting (XSS)
        if XSS_PATTERN.search(payload) or "cross-site scripting" in signature or "xss" in signature:
            return (
                True,
                "Cross-Site Scripting (XSS) Attack",
                "High",
                90,
                f"Malicious script injection payload or XSS signature match: '{signature or '<script> Injected Script'}' targeting port {dst_port}"
            )

        # 2C. Path Traversal & LFI
        if PATH_TRAVERSAL_PATTERN.search(payload) or "traversal" in signature or "path traversal" in category:
            return (
                True,
                "Web Exploitation — Path Traversal",
                "High",
                88,
                f"Directory traversal characters ('../') or sensitive system file access attempt matching '{signature or 'Path Traversal'}'"
            )

        # 2D. Remote Command Execution / Shell Injection
        if COMMAND_INJECTION_PATTERN.search(payload) or "command execution" in signature or "rce" in signature:
            return (
                True,
                "Command Injection Attempt",
                "Critical",
                92,
                f"Operating system shell command characters observed in HTTP parameters targeting port {dst_port}"
            )

        # 2E. Port Scanning & Reconnaissance
        if "scan" in signature or "nmap" in signature or "reconnaissance" in category or (
            dst_port in RECON_PORTS and ("probe" in signature or "recon" in signature)
        ):
            sev = "High" if raw_sev <= 2 else "Medium"
            return (
                True,
                "Port Scanning & Reconnaissance",
                sev,
                82,
                f"Reconnaissance sweep or SYN/FIN port scanner probe directed against sensitive port {dst_port}"
            )

        # 2F. Brute-Force Indicators (External Suricata / Signature fallback)
        if "brute force" in signature or "login attempt" in signature or "authentication failure" in signature:
            return (
                True,
                "Brute-Force Authentication Attempt",
                "High",
                85,
                f"High-frequency credential challenge pattern: '{signature}' on destination port {dst_port}"
            )

        # 2G. DoS / DDoS Indicators (External Suricata / Signature fallback)
        if "denial of service" in signature or "dos" in signature or "flood" in signature:
            return (
                True,
                "DoS / DDoS Indicator",
                "Critical" if raw_sev == 1 else "High",
                86,
                f"Volumetric traffic flood or high packet rate exhaustion pattern: '{signature}'"
            )

        # 2H. Suspicious DNS Activity / Potential C2 Beaconing
        if event.get("event_type") == "dns" or "dns" in category:
            for tld in SUSPICIOUS_DNS_TLDS:
                if tld in search_blob:
                    return (
                        True,
                        "Suspicious DNS Activity",
                        "High",
                        78,
                        f"Query to high-risk top-level domain ({tld}) characteristic of automated malware C2 rendezvous"
                    )

        # 2I. Generic Suricata / NIDS High Severity Alert
        if event.get("event_type") == "alert" and signature:
            if raw_sev == 1:
                return (
                    True,
                    category.capitalize() if category else "High-Severity NIDS Intrusion",
                    "Critical",
                    80,
                    f"Suricata signature match (SID {event.get('signature_id')}): '{signature}'"
                )
            elif raw_sev == 2:
                return (
                    True,
                    category.capitalize() if category else "Medium-Severity Security Alert",
                    "High",
                    75,
                    f"Suricata signature match (SID {event.get('signature_id')}): '{signature}'"
                )

        return False, None, None, 0, ""


# -----------------------------------------------------------------------------
# NIDS Event Ingestion Pipeline
# -----------------------------------------------------------------------------
class NIDSIngestionPipeline:
    """
    Coordinates ingestion, deduplication, persistence of security events,
    and automatic threat classification.
    """

    @staticmethod
    def ingest_single_event(
        raw_event: Any,
        db: Session,
        sensor_id: str = "suricata-sensor-01"
    ) -> Dict[str, Any]:
        """
        Parses a single EVE JSON or dict, validates, deduplicates, persists,
        and evaluates threat classification.
        """
        parsed = EveJsonParser.parse_eve_record(raw_event)
        if not parsed:
            return {"success": False, "error": "Invalid or malformed event record"}

        if sensor_id and parsed["sensor_id"] == "suricata-sensor-01":
            parsed["sensor_id"] = sensor_id

        # Deduplication
        existing = None
        if parsed.get("event_id"):
            existing = db.query(SecurityEvent).filter(
                SecurityEvent.event_id == parsed["event_id"]
            ).first()

        if existing:
            return {
                "success": True,
                "deduplicated": True,
                "event_id": existing.id,
                "message": "Duplicate event record ignored"
            }

        # Create SecurityEvent record
        sec_event = SecurityEvent(
            event_id=parsed["event_id"],
            sensor_id=parsed["sensor_id"],
            event_type=parsed["event_type"],
            timestamp=parsed["timestamp"],
            src_ip=parsed["src_ip"],
            src_port=parsed["src_port"],
            dst_ip=parsed["dst_ip"],
            dst_port=parsed["dst_port"],
            protocol=parsed["protocol"],
            signature_id=parsed["signature_id"],
            signature=parsed["signature"],
            category=parsed["category"],
            severity=parsed["severity"],
            flow_id=parsed["flow_id"],
            raw_details=parsed["raw_details"]
        )
        # Record in stateful traffic tracker for sliding window anomaly correlation
        if parsed.get("src_ip"):
            stateful_tracker.record_packet(
                src_ip=parsed["src_ip"],
                size=len(parsed.get("raw_details") or "") or 64,
                dst_port=parsed.get("dst_port"),
                dst_ip=parsed.get("dst_ip"),
                protocol=parsed.get("protocol", "TCP")
            )

        # Classify threat (evaluates stateful metrics and deterministic signatures)
        is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(parsed)

        threat_detection_id = None
        if is_threat:
            detection = ThreatDetection(
                event_id=sec_event.id,
                timestamp=sec_event.timestamp,
                src_ip=sec_event.src_ip,
                dst_ip=sec_event.dst_ip,
                src_port=sec_event.src_port,
                dst_port=sec_event.dst_port,
                protocol=sec_event.protocol,
                attack_category=category or "Security Incident",
                severity=severity or "High",
                confidence=confidence,
                evidence=evidence,
                status="OPEN"
            )
            db.add(detection)
            db.flush()
            threat_detection_id = detection.id

        db.commit()

        return {
            "success": True,
            "deduplicated": False,
            "security_event_id": sec_event.id,
            "is_threat": is_threat,
            "threat_id": threat_detection_id,
            "category": category,
            "severity": severity,
            "confidence": confidence,
            "evidence": evidence
        }

    @staticmethod
    def ingest_batch_events(
        events_list: List[Any],
        db: Session,
        sensor_id: str = "suricata-sensor-01"
    ) -> Dict[str, Any]:
        """Processes a batch of EVE JSON records transactionally."""
        processed = 0
        threats_detected = 0
        deduplicated = 0
        errors = 0

        for item in events_list:
            try:
                res = NIDSIngestionPipeline.ingest_single_event(item, db, sensor_id=sensor_id)
                if res.get("success"):
                    if res.get("deduplicated"):
                        deduplicated += 1
                    else:
                        processed += 1
                        if res.get("is_threat"):
                            threats_detected += 1
                else:
                    errors += 1
            except Exception as e:
                logger.error(f"Error processing batch event: {e}")
                errors += 1

        return {
            "total_submitted": len(events_list),
            "processed": processed,
            "threats_detected": threats_detected,
            "deduplicated": deduplicated,
            "errors": errors
        }
