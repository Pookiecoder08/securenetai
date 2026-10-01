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
