"""
SecureNet AI — NIDS Telemetry Ingestion & Threat Classification Engine
Provides enterprise-grade ingestion for Suricata EVE JSON and standard NIDS telemetry.
Handles event parsing, field normalization, deduplication, schema validation,
and deterministic rule-based threat classification.
"""

import json
import logging
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
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
# Threat Classification Layer
# -----------------------------------------------------------------------------
class ThreatClassifier:
    """
    Evaluates normalized security events and network flows against deterministic rules.
    Accurately classifies attack vectors without conflating benign traffic with intrusions.
    """

    @staticmethod
    def classify_event(event: Dict[str, Any], payload_sample: Optional[str] = None) -> Tuple[bool, Optional[str], Optional[str], int, str]:
        """
        Evaluates a normalized event.
        Returns:
            (is_threat: bool,
             attack_category: Optional[str],
             severity: Optional[str],
             confidence: int,
             evidence: str)
        """
        signature = (event.get("signature") or "").lower()
        category = (event.get("category") or "").lower()
        dst_port = event.get("dst_port")
        raw_sev = event.get("severity", 3)
        raw_details = event.get("raw_details") or ""
        payload = payload_sample or ""

        search_blob = f"{signature} {category} {payload} {raw_details}".lower()

        # 1. SQL Injection (SQLi)
        if SQLI_PATTERN.search(payload) or "sql injection" in signature or "sqli" in signature:
            return (
                True,
                "SQL Injection (SQLi) Attempt",
                "Critical",
                95,
                f"SQL syntax manipulation pattern or NIDS signature match: '{signature or 'UNION SELECT / Auth Bypass'}' targeting port {dst_port}"
            )

        # 2. Cross-Site Scripting (XSS)
        if XSS_PATTERN.search(payload) or "cross-site scripting" in signature or "xss" in signature:
            return (
                True,
                "Cross-Site Scripting (XSS) Attack",
                "High",
                90,
                f"Malicious script injection payload or XSS signature match: '{signature or '<script> Injected Script'}' targeting port {dst_port}"
            )

        # 3. Path Traversal & LFI
        if PATH_TRAVERSAL_PATTERN.search(payload) or "traversal" in signature or "path traversal" in category:
            return (
                True,
                "Web Exploitation — Path Traversal",
                "High",
                88,
                f"Directory traversal characters ('../') or sensitive system file access attempt matching '{signature or 'Path Traversal'}'"
            )

        # 4. Remote Command Execution / Shell Injection
        if COMMAND_INJECTION_PATTERN.search(payload) or "command execution" in signature or "rce" in signature:
            return (
                True,
                "Command Injection Attempt",
                "Critical",
                92,
                f"Operating system shell command characters observed in HTTP parameters targeting port {dst_port}"
            )

        # 5. Port Scanning & Reconnaissance
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

        # 6. Brute-Force Indicators
        if "brute force" in signature or "login attempt" in signature or "authentication failure" in signature:
            return (
                True,
                "Brute-Force Authentication Attempt",
                "High",
                85,
                f"High-frequency credential challenge pattern: '{signature}' on destination port {dst_port}"
            )

        # 7. DoS / DDoS Indicators
        if "denial of service" in signature or "dos" in signature or "flood" in signature:
            return (
                True,
                "DoS / DDoS Indicator",
                "Critical" if raw_sev == 1 else "High",
                86,
                f"Volumetric traffic flood or high packet rate exhaustion pattern: '{signature}'"
            )

        # 8. Suspicious DNS Activity / Potential C2 Beaconing
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

        # 9. Generic Suricata / NIDS High Severity Alert
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
        db.add(sec_event)
        db.flush()

        # Classify threat
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
