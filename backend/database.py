"""
SecureNet AI — Database Connectivity & Seeding
Configures the SQLite engine, session factory, and handles initial baseline seeding
for default administrative/analyst/employee accounts and initial network topology.
"""

import os
import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import (
    Base,
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
from security import get_password_hash

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DEFAULT_DB_PATH = os.path.join(BASE_DIR, "securenet.db")
DATABASE_URL = os.getenv("DATABASE_URL", f"sqlite:///{DEFAULT_DB_PATH}")

# Normalize Supabase/Heroku postgres:// URLs for SQLAlchemy
if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

# Support both Supabase PostgreSQL and SQLite seamlessly
if DATABASE_URL.startswith("postgresql://") or DATABASE_URL.startswith("postgresql+"):
    engine = create_engine(
        DATABASE_URL,
        pool_pre_ping=True,
        pool_size=10,
        max_overflow=20
    )
else:
    engine = create_engine(
        DATABASE_URL,
        connect_args={"check_same_thread": False}
    )

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db():
    """FastAPI dependency yielding a scoped database session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


DEFAULT_TOPOLOGY_NODES = [
    {
        "id": "gateway-1",
        "type": "customNode",
        "position": {"x": 100, "y": 180},
        "data": {
            "label": "Gateway Edge Router",
            "category": "router",
            "ip": "198.51.100.1",
            "status": "online",
            "description": "Border BGP / Edge Routing Gateway"
        }
    },
    {
        "id": "firewall-1",
        "type": "customNode",
        "position": {"x": 360, "y": 180},
        "data": {
            "label": "Next-Gen Firewall (NGFW)",
            "category": "firewall",
            "ip": "10.0.0.1",
            "status": "active",
            "description": "Kernel Packet Filter & Active Defense Controller"
        }
    },
    {
        "id": "sensor-1",
        "type": "customNode",
        "position": {"x": 620, "y": 60},
        "data": {
            "label": "SecureNet NIDS Sensor",
            "category": "sensor",
            "ip": "10.0.0.50",
            "status": "monitoring",
            "description": "Promiscuous DPI & Threat Signature Analyzer"
        }
    },
    {
        "id": "web-1",
        "type": "customNode",
        "position": {"x": 620, "y": 280},
        "data": {
            "label": "Web Application Cluster",
            "category": "server",
            "ip": "10.0.1.10",
            "status": "online",
            "description": "Production HTTP/HTTPS Web Services"
        }
    },
    {
        "id": "db-1",
        "type": "customNode",
        "position": {"x": 880, "y": 280},
        "data": {
            "label": "Core Database Cluster",
            "category": "database",
            "ip": "10.0.2.20",
            "status": "online",
            "description": "Enterprise Relational Database (SQL)"
        }
    }
]

DEFAULT_TOPOLOGY_EDGES = [
    {
        "id": "e1-2",
        "source": "gateway-1",
        "target": "firewall-1",
        "animated": True,
        "label": "WAN Uplink"
    },
    {
        "id": "e2-3",
        "source": "firewall-1",
        "target": "sensor-1",
        "animated": True,
        "label": "Mirror/TAP Port"
    },
    {
        "id": "e2-4",
        "source": "firewall-1",
        "target": "web-1",
        "animated": False,
        "label": "DMZ Traffic"
    },
    {
        "id": "e4-5",
        "source": "web-1",
        "target": "db-1",
        "animated": False,
        "label": "Internal Query Bus"
    }
]


def seed_default_topology() -> tuple[str, str]:
    """Returns baseline network architecture with Gateway, Firewall, Sensor, Web, and DB."""
    return json.dumps(DEFAULT_TOPOLOGY_NODES), json.dumps(DEFAULT_TOPOLOGY_EDGES)


def init_db():
    """Initializes the database schema and seeds initial accounts and topology if missing."""
    Base.metadata.create_all(bind=engine)

    db: Session = SessionLocal()
    try:
        # 1. Seed RBAC Users if table is empty
        if db.query(User).count() == 0:
            print("[Database] Seeding default RBAC accounts (admin, analyst, employee)...")
            default_users = [
                User(
                    username="admin",
                    hashed_password=get_password_hash("admin123"),
                    role="admin"
                ),
                User(
                    username="analyst",
                    hashed_password=get_password_hash("analyst123"),
                    role="analyst"
                ),
                User(
                    username="employee",
                    hashed_password=get_password_hash("employee123"),
                    role="employee"
                ),
            ]
            db.add_all(default_users)
            db.commit()
            print("[Database] Default users created successfully.")

        # 2. Seed Default Network Topology if missing
        if db.query(TopologyState).count() == 0:
            print("[Database] Seeding initial network topology...")
            nodes_json, edges_json = seed_default_topology()
            topology = TopologyState(
                name="default",
                nodes_json=nodes_json,
                edges_json=edges_json,
                updated_at=datetime.utcnow()
            )
            db.add(topology)
            db.commit()
            print("[Database] Network topology baseline initialized.")

        # 3. Seed Default Automated Response Policies if table is empty
        if db.query(ResponsePolicy).count() == 0:
            print("[Database] Seeding default Response Policies...")
            policies = [
                ResponsePolicy(
                    name="Critical Threat Auto-Mitigation",
                    description="Automatically isolates confirmed critical SQLi, XSS, and exploit attempts in simulation or real mode.",
                    min_risk_score=85,
                    severity_threshold="Critical",
                    action_type="REQUIRE_APPROVAL",
                    duration_seconds=3600,
                    is_enabled=True,
                    allowlist_ips="127.0.0.1,1.1.1.1,8.8.8.8"
                ),
                ResponsePolicy(
                    name="Elevated Reconnaissance Containment",
                    description="Recommends temporary port and address restrictions for high-frequency scanner probes.",
                    min_risk_score=65,
                    severity_threshold="High",
                    action_type="RECOMMEND",
                    duration_seconds=1800,
                    is_enabled=True,
                    allowlist_ips="127.0.0.1,1.1.1.1,8.8.8.8"
                ),
                ResponsePolicy(
                    name="Behavioral Anomaly Surveillance",
                    description="Flags anomalous network flow deviations detected by Isolation Forest for analyst investigation.",
                    min_risk_score=50,
                    severity_threshold="Medium",
                    action_type="ALERT",
                    duration_seconds=0,
                    is_enabled=True,
                    allowlist_ips="127.0.0.1,1.1.1.1,8.8.8.8"
                ),
            ]
            db.add_all(policies)
            db.commit()
            print("[Database] Default response policies initialized.")

        # 4. Seed Default System Configuration
        default_configs = [
            ("simulation_mode", "true", "Global response execution mode: true for simulation, false for OS enforcement"),
            ("real_enforcement_authorized", "false", "Explicit administrator authorization toggle to execute live OS kernel drops"),
            ("allowlist_ips", "127.0.0.1,10.0.0.1,192.168.1.1,8.8.8.8,1.1.1.1,10.0.0.50", "Protected network addresses immune to automated blocking"),
            ("nids_sensor_status", "ACTIVE", "NIDS telemetry ingestion engine status (ACTIVE / WAITING / UNCONFIGURED)"),
            ("ai_model_version", "1.0.0", "Active unsupervised anomaly model version"),
        ]
        for key, val, desc in default_configs:
            cfg = db.query(SystemConfig).filter(SystemConfig.key == key).first()
            if not cfg:
                db.add(SystemConfig(key=key, value=val, description=desc))
            elif key == "allowlist_ips" and "192.168.1.1" not in (cfg.value or ""):
                cfg.value = val
        db.commit()

        # 5. Seed initial system audit entry if empty
        if db.query(AuditLog).count() == 0:
            db.add(AuditLog(
                actor="SYSTEM",
                action="SYSTEM_INIT",
                target="SecureNetAI Engine",
                details="SecureNetAI Security Operations Engine and DB baseline initialized successfully.",
                status="SUCCESS"
            ))
            db.commit()

    finally:
        db.close()



def purge_packet_logs(db: Session) -> int:
    """Purges all accumulated packet logs and reclaims database storage space."""
    count = db.query(PacketLog).delete()
    db.commit()
    try:
        from sqlalchemy import text
        from sqlalchemy.exc import SQLAlchemyError
        db.execute(text("VACUUM"))
        db.commit()
    except SQLAlchemyError:
        pass
    return count
