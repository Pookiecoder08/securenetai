"""
SecureNet AI — Database Connectivity & Seeding
Configures the SQLite engine, session factory, and handles initial baseline seeding
for default administrative/analyst/employee accounts and initial network topology.
"""

import json
from datetime import datetime
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from models import Base, User, PacketLog, FirewallRule, TopologyState
from security import get_password_hash

DATABASE_URL = "sqlite:///./securenet.db"

# SQLite configuration with thread-safe settings for concurrent FastAPI requests and background sniffers
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


def seed_default_topology() -> tuple[str, str]:
    """Generates initial topology nodes and edges representing an enterprise perimeter."""
    nodes = [
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

    edges = [
        {"id": "e1-2", "source": "gateway-1", "target": "firewall-1", "animated": True, "label": "WAN Uplink"},
        {"id": "e2-3", "source": "firewall-1", "target": "sensor-1", "animated": True, "label": "Mirror/TAP Port"},
        {"id": "e2-4", "source": "firewall-1", "target": "web-1", "animated": False, "label": "DMZ Traffic"},
        {"id": "e4-5", "source": "web-1", "target": "db-1", "animated": False, "label": "Internal Query Bus"}
    ]

    return json.dumps(nodes), json.dumps(edges)


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

    finally:
        db.close()


def purge_packet_logs(db: Session) -> int:
    """Purges all accumulated packet logs and reclaims database storage space."""
    count = db.query(PacketLog).delete()
    db.commit()
    try:
        # Reclaim disk space on SQLite
        db.execute("VACUUM")
        db.commit()
    except Exception:
        pass
    return count
