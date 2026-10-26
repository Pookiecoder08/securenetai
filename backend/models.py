"""
SecureNet AI — Database Models
Defines SQLAlchemy schemas for persistent telemetry, users, firewall rules, and topology state.
"""

from datetime import datetime
from sqlalchemy import Column, Integer, String, Boolean, DateTime, Text
from sqlalchemy.orm import declarative_base

Base = declarative_base()


class User(Base):
    """
    User entity representing system operators and their respective RBAC privileges.
    Roles:
      - 'admin': Full administrative authority (firewall, topology, reports, packets).
      - 'analyst': Security analyst (firewall management, reports, deep packet inspection).
      - 'employee': General viewer (sanitized dashboard overview, read-only topology).
    """
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(64), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default="employee")

    def __repr__(self) -> str:
        return f"<User(id={self.id}, username='{self.username}', role='{self.role}')>"


class PacketLog(Base):
    """
    PacketLog entity capturing live network ingress telemetry parsed by Scapy/raw sockets.
    Records 5-tuple attributes, protocol classifications, and threat signatures.
    """
    __tablename__ = "packet_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    src_ip = Column(String(45), nullable=False, index=True)
    dst_ip = Column(String(45), nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), nullable=False)
    is_threat = Column(Boolean, default=False, index=True, nullable=False)
    threat_type = Column(String(64), nullable=True)
    payload_sample = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<PacketLog(id={self.id}, {self.src_ip}:{self.src_port}->{self.dst_ip}:{self.dst_port}, proto={self.protocol}, threat={self.is_threat})>"


class FirewallRule(Base):
    """
    FirewallRule entity representing active drops enforced against the OS kernel firewall
    via platform commands (Windows `netsh advfirewall` or Linux `iptables`).
    """
    __tablename__ = "firewall_rules"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    ip_address = Column(String(45), index=True, nullable=False)
    reason = Column(String(255), nullable=False)
    blocked_by = Column(String(64), nullable=False, default="AUTOMATED_NIPS")
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)

    def __repr__(self) -> str:
        return f"<FirewallRule(id={self.id}, ip='{self.ip_address}', active={self.is_active}, by='{self.blocked_by}')>"


class TopologyState(Base):
    """
    TopologyState entity persisting the interactive network node & edge topology canvas.
    Stores layout JSON for Gateway Routers, Firewalls, Sensors, Web Servers, and Databases.
    """
    __tablename__ = "topology_state"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(64), nullable=False, default="default")
    nodes_json = Column(Text, nullable=False)
    edges_json = Column(Text, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<TopologyState(id={self.id}, name='{self.name}', updated_at={self.updated_at})>"


class SecurityEvent(Base):
    """
    SecurityEvent entity representing parsed and normalized NIDS telemetry
    (e.g., Suricata EVE JSON alerts, network flows, anomalies, DNS, HTTP).
    """
    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String(64), unique=True, index=True, nullable=True)
    sensor_id = Column(String(64), default="suricata-sensor-01", index=True, nullable=False)
    event_type = Column(String(32), default="alert", index=True, nullable=False)  # alert, flow, dns, http, anomaly
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    src_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_ip = Column(String(45), index=True, nullable=False)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), default="TCP", nullable=False)
    signature_id = Column(Integer, nullable=True)
    signature = Column(String(255), nullable=True)
    category = Column(String(128), nullable=True)
    severity = Column(Integer, default=3, nullable=False)  # Suricata 1=High/Critical, 2=Medium, 3=Low, 4=Info
    flow_id = Column(String(64), nullable=True, index=True)
    raw_details = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<SecurityEvent(id={self.id}, sensor='{self.sensor_id}', type='{self.event_type}', {self.src_ip}->{self.dst_ip})>"


class ThreatDetection(Base):
    """
    ThreatDetection entity storing classified security intrusions with attack classification,
    evidence confidence, and SOC investigation workflow status.
    """
    __tablename__ = "threat_detections"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(Integer, nullable=True, index=True)  # Reference to SecurityEvent.id or PacketLog.id
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    src_ip = Column(String(45), index=True, nullable=False)
    dst_ip = Column(String(45), index=True, nullable=False)
    src_port = Column(Integer, nullable=True)
    dst_port = Column(Integer, nullable=True)
    protocol = Column(String(16), default="TCP", nullable=False)
    attack_category = Column(String(64), index=True, nullable=False)  # Port Scanning, SQL Injection, XSS, DoS, Brute Force, etc.
    severity = Column(String(16), default="High", index=True, nullable=False)  # Critical, High, Medium, Low
    confidence = Column(Integer, default=85, nullable=False)  # 0 to 100%
    evidence = Column(Text, nullable=True)
    status = Column(String(32), default="OPEN", index=True, nullable=False)  # OPEN, INVESTIGATING, MITIGATED, RESOLVED, FALSE_POSITIVE
    assigned_to = Column(String(64), nullable=True)
    notes = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<ThreatDetection(id={self.id}, category='{self.attack_category}', severity='{self.severity}', src='{self.src_ip}')>"


class AIAnalysis(Base):
    """
    AIAnalysis entity recording unsupervised anomaly detection inference results,
    observed network flow feature vectors, anomaly scores, and model explanation metadata.
    """
    __tablename__ = "ai_analyses"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    target_ip = Column(String(45), index=True, nullable=False)
    model_name = Column(String(64), default="IsolationForest", nullable=False)
    model_version = Column(String(32), default="1.0.0", nullable=False)
    anomaly_score = Column(Integer, default=0, nullable=False)  # Scaled 0 to 100 anomaly intensity
    raw_decision_score = Column(Text, nullable=True)  # Raw decision function output float string
    is_anomaly = Column(Boolean, default=False, index=True, nullable=False)
    features_json = Column(Text, nullable=False)  # JSON representation of feature vector
    explanation = Column(Text, nullable=True)  # Human-understandable top feature contributions
    limitations = Column(Text, nullable=True)  # Model constraints and documented bounds

    def __repr__(self) -> str:
        return f"<AIAnalysis(id={self.id}, ip='{self.target_ip}', anomaly={self.is_anomaly}, score={self.anomaly_score})>"


class RiskAssessment(Base):
    """
    RiskAssessment entity combining detection severity, evidence confidence,
    AI anomaly score, asset criticality, and incident recurrence into an explainable 0-100 score.
    """
    __tablename__ = "risk_assessments"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    threat_id = Column(Integer, nullable=True, index=True)
    src_ip = Column(String(45), index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    risk_score = Column(Integer, default=0, index=True, nullable=False)  # 0 to 100
    risk_band = Column(String(16), default="Low", index=True, nullable=False)  # Low, Moderate, Elevated, High, Critical
    contributing_factors_json = Column(Text, nullable=False)  # JSON factor breakdown
    policy_version = Column(String(32), default="v1.0", nullable=False)
    explanation = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<RiskAssessment(id={self.id}, ip='{self.src_ip}', score={self.risk_score}, band='{self.risk_band}')>"


class ResponsePolicy(Base):
    """
    ResponsePolicy entity defining administrator-configured rules and thresholds
    governing automated response recommendations and execution triggers.
    """
    __tablename__ = "response_policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(64), unique=True, index=True, nullable=False)
    description = Column(String(255), nullable=True)
    min_risk_score = Column(Integer, default=70, nullable=False)  # Minimum risk score to trigger
    severity_threshold = Column(String(16), default="High", nullable=False)
    action_type = Column(String(32), default="RECOMMEND", nullable=False)  # MONITOR, ALERT, RECOMMEND, REQUIRE_APPROVAL, AUTO_BLOCK
    duration_seconds = Column(Integer, default=3600, nullable=False)  # Default block TTL in seconds
    is_enabled = Column(Boolean, default=True, nullable=False)
    allowlist_ips = Column(Text, default="127.0.0.1,10.0.0.1,192.168.1.1,8.8.8.8,1.1.1.1", nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<ResponsePolicy(id={self.id}, name='{self.name}', action='{self.action_type}', enabled={self.is_enabled})>"


class ResponseAction(Base):
    """
    ResponseAction entity recording all defensive actions, approval requests,
    enforcement outcomes, simulation flags, and manual rollback histories.
    """
    __tablename__ = "response_actions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    risk_assessment_id = Column(Integer, nullable=True, index=True)
    threat_id = Column(Integer, nullable=True, index=True)
    target_ip = Column(String(45), index=True, nullable=False)
    action_type = Column(String(32), default="BLOCK", nullable=False)  # BLOCK, UNBLOCK, MONITOR, RATE_LIMIT
    status = Column(String(32), default="PENDING_APPROVAL", index=True, nullable=False)  # PENDING_APPROVAL, EXECUTED, SIMULATED, EXPIRED, REVERSED, REJECTED, FAILED
    is_simulated = Column(Boolean, default=True, nullable=False)
    reason = Column(String(255), nullable=False)
    initiated_by = Column(String(64), default="POLICY_ENGINE", nullable=False)  # SYSTEM, username
    policy_name = Column(String(64), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    executed_at = Column(DateTime, nullable=True)
    expires_at = Column(DateTime, nullable=True, index=True)
    reversed_at = Column(DateTime, nullable=True)
    reversed_by = Column(String(64), nullable=True)
    execution_output = Column(Text, nullable=True)

    def __repr__(self) -> str:
        return f"<ResponseAction(id={self.id}, target='{self.target_ip}', action='{self.action_type}', status='{self.status}', sim={self.is_simulated})>"


class AuditLog(Base):
    """
    AuditLog entity providing an immutable security audit ledger of administrative,
    analyst, and automated defense decisions.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True, nullable=False)
    actor = Column(String(64), default="SYSTEM", index=True, nullable=False)
    action = Column(String(64), index=True, nullable=False)  # ENFORCE_BLOCK, ROLLBACK, APPROVE_RESPONSE, REJECT_RESPONSE, POLICY_UPDATE, SIMULATION_MODE_TOGGLE, LOGIN
    target = Column(String(128), nullable=True)
    details = Column(Text, nullable=True)
    status = Column(String(16), default="SUCCESS", nullable=False)  # SUCCESS, FAILURE, WARNING

    def __repr__(self) -> str:
        return f"<AuditLog(id={self.id}, actor='{self.actor}', action='{self.action}', target='{self.target}')>"


class SystemConfig(Base):
    """
    SystemConfig entity persisting runtime system-wide settings
    such as real firewall enforcement toggle, sensor status, allowlists, and notification settings.
    """
    __tablename__ = "system_configs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    key = Column(String(64), unique=True, index=True, nullable=False)
    value = Column(Text, nullable=False)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    def __repr__(self) -> str:
        return f"<SystemConfig(key='{self.key}', value='{self.value}')>"

