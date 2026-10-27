import pytest
import os
import sys
import json
from datetime import datetime, timezone, timedelta

# Ensure backend directory is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
BACKEND_DIR = os.path.dirname(CURRENT_DIR)
if BACKEND_DIR not in sys.path:
    sys.path.insert(0, BACKEND_DIR)

from nids_service import EveJsonParser, ThreatClassifier, NIDSIngestionPipeline, StatefulTrafficTracker, stateful_tracker
from ml_service import FeatureExtractor, ml_detector, BehavioralAnomalyDetector
from risk_and_response_service import (
    RiskScoringEngine,
    ResponsePolicyEngine,
    ResponseExecutionManager,
    get_risk_band,
    CRITICAL_ASSETS
)
from models import SecurityEvent, ThreatDetection, ResponseAction, ResponsePolicy, SystemConfig, User
from database import SessionLocal, init_db
from fastapi.testclient import TestClient
from main import app
from security import create_access_token


@pytest.fixture(scope="session", autouse=True)
def setup_test_environment():
    """Initialize database and seed baseline policies before running tests."""
    init_db()


@pytest.fixture
def db_session():
    """Provides a fresh database session for tests."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@pytest.fixture
def client():
    """FastAPI TestClient fixture."""
    return TestClient(app)


# ---------------------------------------------------------------------------
# 1. EVE JSON PARSING & MALFORMED DATA RESILIENCE
# ---------------------------------------------------------------------------

def test_eve_json_parser_valid_alert():
    raw_eve = json.dumps({
        "timestamp": "2026-10-12T10:15:30.123456+0000",
        "event_type": "alert",
        "src_ip": "198.51.100.22",
        "src_port": 49201,
        "dest_ip": "192.168.1.50",
        "dest_port": 80,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 2100498,
            "rev": 7,
            "signature": "ET EXPLOIT Possible SQL Injection Attack (UNION SELECT)",
            "category": "Web Application Attack",
            "severity": 1
        },
        "payload_printable": "GET /api/user?id=1%20UNION%20SELECT%20username,password%20FROM%20users HTTP/1.1"
    })

    event = EveJsonParser.parse_eve_record(raw_eve)
    assert event is not None
    assert event["event_type"] == "alert"
    assert event["src_ip"] == "198.51.100.22"
    assert event["dst_ip"] == "192.168.1.50"
    assert event["dst_port"] == 80
    assert event["protocol"] == "TCP"
    assert "UNION SELECT" in event["signature"]
    assert event["severity"] == 1
    assert event["signature_id"] == 2100498


def test_eve_json_parser_flow_event():
    raw_flow = json.dumps({
        "timestamp": "2026-10-12T10:16:00.000000+0000",
        "event_type": "flow",
        "src_ip": "10.0.0.15",
        "src_port": 53200,
        "dest_ip": "1.1.1.1",
        "dest_port": 53,
        "proto": "UDP",
        "flow": {
            "pkts_toserver": 4,
            "pkts_toclient": 4,
            "bytes_toserver": 320,
            "bytes_toclient": 840,
            "start": "2026-10-12T10:15:58.000000+0000"
        }
    })

    event = EveJsonParser.parse_eve_record(raw_flow)
    assert event is not None
    assert event["event_type"] == "flow"
    assert event["src_ip"] == "10.0.0.15"
    assert event["dst_ip"] == "1.1.1.1"
    assert event["protocol"] == "UDP"


def test_eve_json_parser_malformed_and_empty_resilience():
    # Invalid JSON syntax
    assert EveJsonParser.parse_eve_record("This is not valid JSON at all") is None
    assert EveJsonParser.parse_eve_record("{truncated_json: true, ") is None
    # Empty string or whitespace
    assert EveJsonParser.parse_eve_record("") is None
    assert EveJsonParser.parse_eve_record("   \n  ") is None
    # Non-dictionary input
    assert EveJsonParser.parse_eve_record([1, 2, 3]) is None


# ---------------------------------------------------------------------------
# 2. DETERMINISTIC THREAT CLASSIFICATION
# ---------------------------------------------------------------------------

def test_threat_classifier_sqli():
    dummy_event = {
        "signature": "ET EXPLOIT Possible SQL Injection Attack (UNION SELECT)",
        "category": "Web Application Attack",
        "dst_port": 80,
        "severity": 1
    }
    payload = "GET /search?q=test' UNION SELECT null, username, password FROM users-- HTTP/1.1"
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(dummy_event, payload)
    assert is_threat is True
    assert "SQL" in category
    assert severity == "Critical"
    assert confidence >= 90


def test_threat_classifier_xss():
    dummy_event = {
        "signature": "Web Application Attack (XSS script)",
        "category": "Web Attack",
        "dst_port": 80,
        "severity": 2
    }
    payload = "POST /comment HTTP/1.1\r\n\r\n<script>alert(document.cookie)</script>"
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(dummy_event, payload)
    assert is_threat is True
    assert "XSS" in category
    assert severity == "High"


def test_threat_classifier_path_traversal():
    dummy_event = {
        "signature": "Directory Traversal Attempt",
        "category": "Path Traversal",
        "dst_port": 80,
        "severity": 2
    }
    payload = "GET /download?file=../../../../etc/passwd HTTP/1.1"
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(dummy_event, payload)
    assert is_threat is True
    assert "Path Traversal" in category
    assert severity == "High"


def test_threat_classifier_command_injection():
    dummy_event = {
        "signature": "Command Execution Pattern",
        "category": "Remote Code Execution",
        "dst_port": 80,
        "severity": 1
    }
    payload = "POST /ping HTTP/1.1\r\nip=127.0.0.1; cat /etc/shadow"
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(dummy_event, payload)
    assert is_threat is True
    assert "Command Injection" in category
    assert severity == "Critical"


def test_threat_classifier_benign_traffic():
    dummy_event = {
        "signature": "Normal HTTP GET Request",
        "category": "Benign Telemetry",
        "dst_port": 80,
        "severity": 4
    }
    benign_payload = "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: text/html"
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(dummy_event, benign_payload)
    assert is_threat is False
    assert category is None


# ---------------------------------------------------------------------------
# 3. AI BEHAVIORAL ANOMALY FEATURE EXTRACTION & INFERENCE
# ---------------------------------------------------------------------------

def test_ai_feature_extractor_flow_metrics():
    packets = [
        {"src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "dst_port": 80, "length": 1500, "protocol": "TCP", "direction": "outbound", "payload_ascii": ""},
        {"src_ip": "10.0.0.99", "dst_ip": "192.168.1.10", "dst_port": 80, "length": 1500, "protocol": "TCP", "direction": "outbound", "payload_ascii": ""},
        {"src_ip": "10.0.0.99", "dst_ip": "192.168.1.11", "dst_port": 443, "length": 512, "protocol": "TCP", "direction": "outbound", "payload_ascii": ""},
        {"src_ip": "10.0.0.99", "dst_ip": "192.168.1.1", "dst_port": 53, "length": 76, "protocol": "UDP", "direction": "outbound", "payload_ascii": "query.example.com"},
    ]

    features = FeatureExtractor.extract_from_packets(packets, host_ip="10.0.0.99")
    assert "conn_count" in features
    assert "total_bytes" in features
    assert "unique_dst_ports" in features
    assert "unique_dst_ips" in features
    assert features["conn_count"] == 4.0
    assert features["total_bytes"] == 3588.0
    assert features["unique_dst_ports"] == 3.0


def test_ai_behavioral_anomaly_detector_inference():
    detector = BehavioralAnomalyDetector()
    assert detector.is_loaded is True

    # Normal baseline feature set
    normal_features = {
        "conn_count": 12.0,
        "unique_dst_ports": 2.0,
        "unique_dst_ips": 2.0,
        "total_bytes": 12000.0,
        "avg_bytes_per_pkt": 600.0,
        "outbound_ratio": 0.5,
        "tcp_syn_ratio": 0.1,
        "sensitive_port_ratio": 0.05,
        "dns_query_ratio": 0.1,
        "payload_entropy": 3.0
    }
    result_normal = detector.analyze_host_traffic("192.168.1.45", normal_features)
    assert "anomaly_score" in result_normal
    assert "is_anomaly" in result_normal
    assert "explanation" in result_normal
    assert "limitations" in result_normal

    # Extreme volumetric and port sweep anomaly feature set
    anomalous_features = {
        "conn_count": 5000.0,
        "unique_dst_ports": 2500.0,
        "unique_dst_ips": 150.0,
        "total_bytes": 85000000.0,
        "avg_bytes_per_pkt": 1400.0,
        "outbound_ratio": 0.99,
        "tcp_syn_ratio": 0.95,
        "sensitive_port_ratio": 0.90,
        "dns_query_ratio": 0.90,
        "payload_entropy": 7.9
    }
    result_anomaly = detector.analyze_host_traffic("203.0.113.88", anomalous_features)
    assert result_anomaly["anomaly_score"] > result_normal["anomaly_score"]
    assert result_anomaly["is_anomaly"] is True


# ---------------------------------------------------------------------------
# 4. RISK SCORING ENGINE & POLICY EVALUATION
# ---------------------------------------------------------------------------

def test_risk_scoring_engine_calculation(db_session):
    threat = ThreatDetection(
        src_ip="203.0.113.55",
        dst_ip="10.0.2.20",  # Core Database Cluster with 1.35x multiplier
        attack_category="SQL Injection (SQLi) Attempt",
        severity="Critical",
        confidence=95,
        status="OPEN"
    )

    result_crit = RiskScoringEngine.calculate_risk(
        threat=threat,
        ai_anomaly_score=90,
        target_ip="10.0.2.20",
        db=db_session,
        src_ip="203.0.113.55"
    )

    assert result_crit["risk_score"] >= 80
    assert result_crit["risk_band"] in ["High", "Critical"]
    assert "contributing_factors" in result_crit
    assert "explanation" in result_crit

    # Low severity benign telemetry on standard external host (multiplier 1.0)
    result_low = RiskScoringEngine.calculate_risk(
        threat=None,
        ai_anomaly_score=10,
        target_ip="192.168.1.150",
        db=db_session,
        src_ip="10.0.0.99"
    )
    assert result_low["risk_score"] <= 45
    assert result_low["risk_band"] in ["Low", "Moderate"]


def test_response_policy_allowlist_protection(db_session):
    # Attempting to block loopback or gateway must be strictly blocked by allowlist
    is_protected_loopback, reason_lb = ResponsePolicyEngine.is_ip_allowlisted(db_session, "127.0.0.1")
    assert is_protected_loopback is True
    assert "Loopback" in reason_lb

    is_protected_gateway, reason_gw = ResponsePolicyEngine.is_ip_allowlisted(db_session, "192.168.1.1")
    assert is_protected_gateway is True
    assert "allowlist" in reason_gw.lower()

    # Regular external IP is NOT allowlisted
    is_protected_attacker, _ = ResponsePolicyEngine.is_ip_allowlisted(db_session, "198.51.100.88")
    assert is_protected_attacker is False


def test_response_execution_simulation_mode(db_session):
    test_attacker_ip = "198.51.100.77"

    # Execution in default simulation mode
    exec_result = ResponseExecutionManager.execute_response(
        db=db_session,
        target_ip=test_attacker_ip,
        reason="Automated Unit Test SQLi",
        actor="TEST_SUITE",
        duration_seconds=900,
        policy_name="Unit Test Policy"
    )

    assert exec_result["success"] is True
    assert exec_result["is_simulated"] is True
    assert exec_result["status"] == "SIMULATED"
    assert exec_result["target_ip"] == test_attacker_ip

    action_id = exec_result["action_id"]

    # Rollback simulation
    rollback_res = ResponseExecutionManager.rollback_action(
        db=db_session,
        action_id=action_id,
        reversed_by="TEST_ADMIN"
    )
    assert rollback_res["success"] is True
    assert rollback_res["status"] == "REVERSED"


# ---------------------------------------------------------------------------
# 5. RBAC ENDPOINT PERMISSION ENFORCEMENT & API HEALTH
# ---------------------------------------------------------------------------

def test_api_status_endpoint(client):
    admin_token = create_access_token(data={"sub": "admin", "role": "admin"})
    headers = {"Authorization": f"Bearer {admin_token}"}

    response = client.get("/api/system/status", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "total_security_events" in data
    assert "recent_devices_count" in data
    assert "total_threats_detected" in data
    assert "simulation_mode" in data


def test_ai_status_endpoint(client):
    employee_token = create_access_token(data={"sub": "employee", "role": "employee"})
    headers = {"Authorization": f"Bearer {employee_token}"}

    response = client.get("/api/ai/status", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["model_name"] == "IsolationForest"
    assert "features" in data
    assert len(data["features"]) == 10


def test_rbac_unauthorized_manual_response(client):
    # Viewer / Employee token
    employee_token = create_access_token(data={"sub": "employee", "role": "employee"})
    headers = {"Authorization": f"Bearer {employee_token}"}

    # Employee attempting privileged manual firewall enforcement must get 403 Forbidden
    response = client.post(
        "/api/response/execute-manual",
        json={"target_ip": "203.0.113.99", "action_type": "BLOCK", "reason": "Test", "duration_seconds": 1800},
        headers=headers
    )
    assert response.status_code == 403

    # Admin token
    admin_token = create_access_token(data={"sub": "admin", "role": "admin"})
    admin_headers = {"Authorization": f"Bearer {admin_token}"}

    # Admin attempting manual enforcement must succeed (in simulation mode)
    response_admin = client.post(
        "/api/response/execute-manual",
        json={"target_ip": "203.0.113.99", "action_type": "BLOCK", "reason": "Test Admin Block", "duration_seconds": 1800},
        headers=admin_headers
    )
    assert response_admin.status_code == 200
    data_admin = response_admin.json()
    assert data_admin["success"] is True
    assert data_admin["is_simulated"] is True


# ---------------------------------------------------------------------------
# 6. STATEFUL NIDS: BRUTE-FORCE, SYN FLOOD & VOLUMETRIC DOS TESTS
# ---------------------------------------------------------------------------

def test_stateful_traffic_tracker_sliding_window_and_pruning():
    tracker = StatefulTrafficTracker(window_seconds=60.0)
    ip = "198.51.100.77"
    now = 1000.0

    # Add 10 SYN packets 50s ago
    for _ in range(10):
        tracker.record_packet(
            src_ip=ip,
            size=60,
            tcp_flags="S",
            dst_port=80,
            protocol="TCP",
            timestamp=now - 50.0
        )

    # Add 1 stale packet 70s ago (must be pruned)
    tracker.record_packet(
        src_ip=ip,
        size=60,
        tcp_flags="S",
        dst_port=80,
        protocol="TCP",
        timestamp=now - 70.0
    )

    metrics = tracker.get_metrics(ip, now=now)
    assert metrics["packets_in_window"] == 10
    assert metrics["tcp_syn_ratio"] == 1.0
    assert metrics["avg_bytes"] == 60.0


def test_stateful_brute_force_detection():
    tracker = StatefulTrafficTracker(window_seconds=60.0)
    attacker_ip = "198.51.100.88"
    now = 2000.0

    # Simulate 25 SSH/RDP authentication connection attempts in window (> 20 threshold)
    for i in range(25):
        tracker.record_packet(
            src_ip=attacker_ip,
            size=74,
            tcp_flags="S",
            dst_port=22 if i % 2 == 0 else 3389,
            protocol="TCP",
            timestamp=now - (25 - i)
        )

    assert tracker.calculate_auth_connection_count(attacker_ip, now=now) == 25

    event = {"src_ip": attacker_ip, "dst_port": 22, "protocol": "TCP"}
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(
        event=event,
        tracker=tracker
    )

    assert is_threat is True
    assert category == "Brute-Force Authentication Attempt"
    assert severity == "High"
    assert "25 authentication attempts" in evidence


def test_stateful_ddos_tcp_syn_flood_detection():
    tracker = StatefulTrafficTracker(window_seconds=60.0)
    flooder_ip = "198.51.100.99"
    now = 3000.0

    # Simulate 150 SYN packets in 1 second (> 100 pps, syn_ratio 1.0 > 80%, avg_bytes 54 < 100)
    for i in range(150):
        tracker.record_packet(
            src_ip=flooder_ip,
            size=54,
            tcp_flags="S",
            dst_port=80,
            protocol="TCP",
            timestamp=now - (0.5 * (150 - i) / 150)
        )

    pps = tracker.calculate_packets_per_second(flooder_ip, now=now)
    syn_ratio = tracker.calculate_tcp_syn_ratio(flooder_ip, now=now)
    metrics = tracker.get_metrics(flooder_ip, now=now)

    assert pps > 100.0
    assert syn_ratio > 0.80
    assert metrics["avg_bytes"] < 100.0

    event = {"src_ip": flooder_ip, "dst_port": 80, "protocol": "TCP"}
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(
        event=event,
        tracker=tracker
    )

    assert is_threat is True
    assert category == "TCP SYN Flood (DDoS)"
    assert severity == "Critical"


def test_stateful_ddos_volumetric_flood_detection():
    tracker = StatefulTrafficTracker(window_seconds=60.0)
    attacker_ip = "198.51.100.111"
    now = 4000.0

    # Simulate 12 MB transmission in 1 second (> 10 MB/s bandwidth threshold)
    chunk_size = 60000
    for i in range(210):  # 210 * 60,000 bytes = 12.6 MB
        tracker.record_packet(
            src_ip=attacker_ip,
            size=chunk_size,
            tcp_flags="A",
            dst_port=8000,
            protocol="UDP",
            timestamp=now - (0.8 * (210 - i) / 210)
        )

    metrics = tracker.get_metrics(attacker_ip, now=now)
    assert metrics["bandwidth_bytes_per_sec"] > (10 * 1024 * 1024)

    event = {"src_ip": attacker_ip, "dst_port": 8000, "protocol": "UDP"}
    is_threat, category, severity, confidence, evidence = ThreatClassifier.classify_event(
        event=event,
        tracker=tracker
    )

    assert is_threat is True
    assert category == "Volumetric DoS Attack"
    assert severity == "Critical"


def test_stateful_ml_feature_extraction_and_anomaly_score():
    tracker = StatefulTrafficTracker(window_seconds=60.0)
    target_ip = "198.51.100.122"
    now = 5000.0

    # Record 500 SYN packets in tracker
    for i in range(500):
        tracker.record_packet(
            src_ip=target_ip,
            size=60,
            tcp_flags="S",
            dst_port=80 + (i % 5),
            dst_ip="192.168.1.10",
            protocol="TCP",
            timestamp=now - (0.5 * (500 - i) / 500)
        )

    features = FeatureExtractor.extract_from_packets(
        packets=[],
        host_ip=target_ip,
        tracker=tracker
    )

    assert features["conn_count"] == 500.0
    assert features["tcp_syn_ratio"] == 1.0
    assert features["avg_bytes_per_pkt"] == 60.0

    # Evaluate Isolation Forest behavioral anomaly detector
    detector = BehavioralAnomalyDetector()
    analysis = detector.analyze_host_traffic(target_ip, features)
    assert analysis["is_anomaly"] is True
    assert analysis["anomaly_score"] >= 90
