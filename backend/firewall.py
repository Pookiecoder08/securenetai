import platform
import subprocess
from datetime import datetime
from typing import Optional, Dict, Any, List
from sqlalchemy.orm import Session
from sqlalchemy.exc import SQLAlchemyError
from models import FirewallRule

SYSTEM_PLATFORM = platform.system()


def get_platform_info() -> Dict[str, str]:
    if SYSTEM_PLATFORM == "Windows":
        driver = "netsh advfirewall (Windows Filtering Platform / WFP)"
    elif SYSTEM_PLATFORM == "Linux":
        driver = "iptables / Netfilter Kernel Hook"
    else:
        driver = f"Generic / Unsupported OS ({SYSTEM_PLATFORM})"

    return {
        "os": SYSTEM_PLATFORM,
        "release": platform.release(),
        "driver": driver
    }


def execute_os_block(ip: str) -> Dict[str, Any]:
    # Technical Note: Invokes platform-native kernel packet filtering commands.
    # On Windows: 'netsh advfirewall firewall add rule' adds an inbound block rule.
    # On Linux: 'iptables -I INPUT -s {ip} -j DROP' inserts a drop at the head of the filter chain.
    rule_name = f"SecureNet_Block_{ip}"

    if SYSTEM_PLATFORM == "Windows":
        cmd = [
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={rule_name}",
            "dir=in",
            "action=block",
            f"remoteip={ip}",
            "enable=yes",
            f"description=Active Defense Rule created by SecureNet NIPS for IP {ip}"
        ]
    elif SYSTEM_PLATFORM == "Linux":
        cmd = ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        return {"success": False, "message": f"Unsupported platform: {SYSTEM_PLATFORM}"}

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True
        )
        return {"success": True, "output": result.stdout.strip(), "cmd": " ".join(cmd)}
    except subprocess.CalledProcessError as e:
        stderr_clean = e.stderr.strip() or e.stdout.strip()
        if "already exists" in stderr_clean.lower():
            return {"success": True, "output": f"Rule already present: {stderr_clean}", "cmd": " ".join(cmd)}
        return {"success": False, "error": f"Command failed (exit code {e.returncode}): {stderr_clean}", "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired as e:
        return {"success": False, "error": f"Firewall command timed out after 10s: {e}", "cmd": " ".join(cmd)}
    except FileNotFoundError as e:
        return {"success": False, "error": f"Firewall binary not found: {e}", "cmd": " ".join(cmd)}
    except OSError as e:
        return {"success": False, "error": f"OS execution error: {e}", "cmd": " ".join(cmd)}


def execute_os_unblock(ip: str) -> Dict[str, Any]:
    # Technical Note: Removes the kernel packet filtering rule created by execute_os_block.
    rule_name = f"SecureNet_Block_{ip}"

    if SYSTEM_PLATFORM == "Windows":
        cmd = [
            "netsh", "advfirewall", "firewall", "delete", "rule",
            f"name={rule_name}"
        ]
    elif SYSTEM_PLATFORM == "Linux":
        cmd = ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"]
    else:
        return {"success": False, "message": f"Unsupported platform: {SYSTEM_PLATFORM}"}

    try:
        result = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=10,
            check=True
        )
        return {"success": True, "output": result.stdout.strip(), "cmd": " ".join(cmd)}
    except subprocess.CalledProcessError as e:
        stderr_clean = e.stderr.strip() or e.stdout.strip()
        return {"success": True, "output": f"Rule removed or was not active: {stderr_clean}", "cmd": " ".join(cmd)}
    except subprocess.TimeoutExpired as e:
        return {"success": False, "error": f"Firewall unblock command timed out after 10s: {e}", "cmd": " ".join(cmd)}
    except FileNotFoundError as e:
        return {"success": False, "error": f"Firewall binary not found: {e}", "cmd": " ".join(cmd)}
    except OSError as e:
        return {"success": False, "error": f"OS execution error: {e}", "cmd": " ".join(cmd)}


_firewall_cache: Optional[List[Dict[str, Any]]] = None
_firewall_cache_time: float = 0.0


def invalidate_firewall_cache():
    global _firewall_cache
    _firewall_cache = None


def block_ip(
    ip: str,
    reason: str,
    blocked_by: str = "AUTOMATED_NIPS",
    db: Optional[Session] = None
) -> Dict[str, Any]:
    invalidate_firewall_cache()
    # Safeguard loopback addresses and invalid targets to avoid severing local development IPC
    if not ip or ip in ("127.0.0.1", "localhost", "0.0.0.0", "Unknown IP") or ip.startswith("127."):
        os_result = {
            "success": True,
            "output": "Rule enforced in NIPS Active Defense Ledger (loopback kernel preserved).",
            "cmd": "Internal Ledger Enforcement"
        }
    else:
        os_result = execute_os_block(ip)

    db_updated = False
    if db is not None:
        try:
            existing_rule = db.query(FirewallRule).filter(
                FirewallRule.ip_address == ip,
                FirewallRule.is_active == True
            ).first()

            if existing_rule:
                existing_rule.reason = reason
                existing_rule.blocked_by = blocked_by
                existing_rule.timestamp = datetime.utcnow()
            else:
                new_rule = FirewallRule(
                    ip_address=ip,
                    reason=reason,
                    blocked_by=blocked_by,
                    timestamp=datetime.utcnow(),
                    is_active=True
                )
                db.add(new_rule)
            db.commit()
            db_updated = True
        except SQLAlchemyError as e:
            db.rollback()
            print(f"[Firewall Controller DB ERROR] Failed to record rule: {e}")

    return {
        "ip": ip,
        "reason": reason,
        "blocked_by": blocked_by,
        "os_success": os_result.get("success", False),
        "os_details": os_result,
        "db_synced": db_updated
    }


def unblock_ip(ip: str, db: Optional[Session] = None) -> Dict[str, Any]:
    invalidate_firewall_cache()
    os_result = execute_os_unblock(ip)

    db_updated = False
    if db is not None:
        try:
            rules = db.query(FirewallRule).filter(
                FirewallRule.ip_address == ip,
                FirewallRule.is_active == True
            ).all()

            for r in rules:
                r.is_active = False
            db.commit()
            db_updated = True
        except SQLAlchemyError as e:
            db.rollback()
            print(f"[Firewall Controller DB ERROR] Failed to deactivate rule: {e}")

    return {
        "ip": ip,
        "os_success": os_result.get("success", False),
        "os_details": os_result,
        "db_synced": db_updated
    }


def get_active_rules(db: Session) -> List[Dict[str, Any]]:
    global _firewall_cache, _firewall_cache_time
    import time
    now = time.time()
    if _firewall_cache is not None and (now - _firewall_cache_time < 3.0):
        return _firewall_cache

    rules = db.query(FirewallRule).order_by(FirewallRule.timestamp.desc()).all()
    _firewall_cache = [
        {
            "id": r.id,
            "ip_address": r.ip_address,
            "reason": r.reason,
            "blocked_by": r.blocked_by,
            "timestamp": r.timestamp.isoformat(),
            "is_active": r.is_active
        }
        for r in rules
    ]
    _firewall_cache_time = now
    return _firewall_cache
