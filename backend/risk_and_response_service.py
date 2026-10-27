"""
SecureNet AI — Risk Scoring Engine & Automated Response Controller
Combines threat severity, evidence confidence, AI anomaly intensity, asset criticality,
and incident recurrence to calculate explainable 0-100 risk scores.
Evaluates response policies, enforces allowlist safety boundaries, manages simulation
vs real kernel firewall execution, and maintains comprehensive audit histories.
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.orm import Session

from models import (
    RiskAssessment,
    ThreatDetection,
    ResponsePolicy,
    ResponseAction,
    AuditLog,
    SystemConfig,
    FirewallRule
)
import firewall

logger = logging.getLogger("securenet.response")

# Configurable Risk Bands
RISK_BANDS = {
    "Low": (0, 29),
    "Moderate": (30, 49),
    "Elevated": (50, 69),
    "High": (70, 89),
    "Critical": (90, 100)
}

# Zero hardcoded dummy assets — populated dynamically from real configured network nodes
CRITICAL_ASSETS = {}


def get_risk_band(score: int) -> str:
    """Maps a 0-100 risk score to its operational risk band."""
    for band, (low, high) in RISK_BANDS.items():
        if low <= score <= high:
            return band
    return "Critical" if score > 100 else "Low"


# -----------------------------------------------------------------------------
# Risk Scoring Engine
# -----------------------------------------------------------------------------
class RiskScoringEngine:
    """
    Computes explainable, multi-factor risk scores prioritizing threats based on:
    - Detection severity (potential impact)
    - Evidence confidence (certainty)
    - AI anomaly score (rarity/deviation)
    - Asset criticality (target value)
    - Source recurrence (repetition frequency)
    """

    @staticmethod
    def calculate_risk(
        threat: Optional[ThreatDetection] = None,
        ai_anomaly_score: Optional[int] = None,
        target_ip: Optional[str] = None,
        db: Optional[Session] = None,
        src_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Calculates a calibrated composite risk score between 0 and 100.
        Returns:
            {
                "risk_score": int (0-100),
                "risk_band": str,
                "contributing_factors": Dict,
                "explanation": str
            }
        """
        # 1. Base Severity Score (0 to 100 scale, 40% weight)
        sev_str = (threat.severity if threat else "Medium").capitalize()
        sev_weights = {
            "Critical": 95,
            "High": 80,
            "Medium": 55,
            "Low": 30,
            "Info": 10
        }
        severity_val = sev_weights.get(sev_str, 50)
        sev_component = severity_val * 0.40

        # 2. Evidence Confidence (0 to 100 scale, 25% weight)
        confidence_val = threat.confidence if threat else 60
        conf_component = confidence_val * 0.25

        # 3. AI Behavioral Anomaly Score (0 to 100 scale, 20% weight)
        anomaly_val = ai_anomaly_score if ai_anomaly_score is not None else 30
        anomaly_component = anomaly_val * 0.20

        # 4. Source Recurrence & Frequency (15% weight)
        effective_src = src_ip or (threat.src_ip if threat else "0.0.0.0")
        recurrence_count = 1
        if db is not None and effective_src not in ("0.0.0.0", "127.0.0.1"):
            recent_cutoff = datetime.utcnow() - timedelta(minutes=30)
            recurrence_count = db.query(ThreatDetection).filter(
                ThreatDetection.src_ip == effective_src,
                ThreatDetection.timestamp >= recent_cutoff
            ).count()

        # Scale recurrence: 1 event = 30, 2 = 60, >=3 = 100
        recurrence_val = min(100, max(30, recurrence_count * 30))
        rec_component = recurrence_val * 0.15

        # Base composite score before asset weighting
        base_score = sev_component + conf_component + anomaly_component + rec_component

        # 5. Asset Criticality Multiplier
        effective_dst = target_ip or (threat.dst_ip if threat else "")
        asset_info = CRITICAL_ASSETS.get(effective_dst)
        asset_multiplier = asset_info["multiplier"] if asset_info else 1.0

        final_score = int(min(100, round(base_score * asset_multiplier)))
        band = get_risk_band(final_score)

        factors = {
            "severity": {"label": sev_str, "value": severity_val, "weighted": round(sev_component, 1), "weight_pct": 40},
            "confidence": {"value": confidence_val, "weighted": round(conf_component, 1), "weight_pct": 25},
            "anomaly_score": {"value": anomaly_val, "weighted": round(anomaly_component, 1), "weight_pct": 20},
            "recurrence": {"count_recent_30m": recurrence_count, "value": recurrence_val, "weighted": round(rec_component, 1), "weight_pct": 15},
            "asset_criticality": {
                "target_ip": effective_dst,
                "asset_name": asset_info["name"] if asset_info else "Standard Enterprise Host",
                "multiplier": asset_multiplier
            }
        }

        explanation_parts = [
            f"Assigned {band} risk score ({final_score}/100) based on {sev_str} severity ({severity_val}/100) with {confidence_val}% evidence confidence."
        ]
        if anomaly_val >= 60:
            explanation_parts.append(f"Elevated by behavioral outlier intensity ({anomaly_val}/100).")
        if recurrence_count > 1:
            explanation_parts.append(f"Compounded by {recurrence_count} security alerts from source in the last 30 minutes.")
        if asset_multiplier > 1.0:
            explanation_parts.append(f"Adjusted by {asset_multiplier}x asset criticality targeting {asset_info['name']}.")

        explanation = " ".join(explanation_parts)

        return {
            "risk_score": final_score,
            "risk_band": band,
            "contributing_factors": factors,
            "explanation": explanation
        }

    @staticmethod
    def assess_and_record(
        db: Session,
        threat: Optional[ThreatDetection] = None,
        ai_anomaly_score: Optional[int] = None,
        target_ip: Optional[str] = None,
        src_ip: Optional[str] = None
    ) -> RiskAssessment:
        """Computes risk and persists a new RiskAssessment record."""
        calc = RiskScoringEngine.calculate_risk(
            threat=threat,
            ai_anomaly_score=ai_anomaly_score,
            target_ip=target_ip,
            db=db,
            src_ip=src_ip
        )
        effective_src = src_ip or (threat.src_ip if threat else "0.0.0.0")

        assessment = RiskAssessment(
            threat_id=threat.id if threat else None,
            src_ip=effective_src,
            timestamp=datetime.utcnow(),
            risk_score=calc["risk_score"],
            risk_band=calc["risk_band"],
            contributing_factors_json=json.dumps(calc["contributing_factors"]),
            policy_version="v2.1",
            explanation=calc["explanation"]
        )
        db.add(assessment)
        db.commit()
        db.refresh(assessment)
        return assessment


# -----------------------------------------------------------------------------
# Response Policy & Decision Engine
# -----------------------------------------------------------------------------
class ResponsePolicyEngine:
    """
    Evaluates risk assessments and active policies to determine response actions:
    MONITOR, ALERT, RECOMMEND, REQUIRE_APPROVAL, or AUTO_BLOCK.
    Enforces allowlist protections, simulation boundaries, and active restriction checks.
    """

    @staticmethod
    def get_system_config(db: Session, key: str, default: str = "") -> str:
        """Fetches runtime system configuration value."""
        cfg = db.query(SystemConfig).filter(SystemConfig.key == key).first()
        return cfg.value if cfg else default

    @staticmethod
    def is_ip_allowlisted(db: Session, ip: str) -> Tuple[bool, str]:
        """
        Validates if an IP is protected by administrative allowlists or loopback safeguards.
        Returns: (is_protected: bool, reason: str)
        """
        # Hard loopback / broadcast safeguards
        if ip in ("127.0.0.1", "localhost", "0.0.0.0", "255.255.255.255") or ip.startswith("127."):
            return True, "Loopback & local development stack protection"

        # Check configured allowlists
        raw_allowlist = ResponsePolicyEngine.get_system_config(
            db, "allowlist_ips", "127.0.0.1,10.0.0.1,192.168.1.1,8.8.8.8,1.1.1.1,10.0.0.50"
        )
        allowed = [addr.strip() for addr in raw_allowlist.split(",") if addr.strip()]
        if ip in allowed:
            return True, f"Configured administrative allowlist entry ({ip})"

        # Check critical asset protection (never auto-block gateways/servers as attackers)
        if ip in CRITICAL_ASSETS:
            return True, f"Protected infrastructure asset ({CRITICAL_ASSETS[ip]['name']})"

        return False, ""

    @staticmethod
    def evaluate_response_decision(
        db: Session,
        risk_assessment: RiskAssessment,
        threat: Optional[ThreatDetection] = None
    ) -> Dict[str, Any]:
        """
        Evaluates active policies against a risk assessment.
        Returns recommended action outcome, status, and eligible duration.
        """
        src_ip = risk_assessment.src_ip
        risk_score = risk_assessment.risk_score

        # Allowlist Pre-Check
        is_protected, protect_reason = ResponsePolicyEngine.is_ip_allowlisted(db, src_ip)
        if is_protected:
            return {
                "action_type": "MONITOR",
                "recommended_action": "ALLOWLIST_PROTECTED",
                "status": "REJECTED",
                "is_eligible": False,
                "reason": f"Source IP {src_ip} is protected: {protect_reason}. Automated isolation suppressed.",
                "duration_seconds": 0,
                "policy_name": "Allowlist Protection Rule"
            }

        # Check if already actively blocked in FirewallRule or active ResponseAction
        existing_block = db.query(FirewallRule).filter(
            FirewallRule.ip_address == src_ip,
            FirewallRule.is_active == True
        ).first()
        if existing_block:
            return {
                "action_type": "MONITOR",
                "recommended_action": "ALREADY_RESTRICTED",
                "status": "REJECTED",
                "is_eligible": False,
                "reason": f"Active firewall restriction already enforced against {src_ip}.",
                "duration_seconds": 0,
                "policy_name": "Deduplication Rule"
            }

        # Check active policies matching threshold
        policies = db.query(ResponsePolicy).filter(
            ResponsePolicy.is_enabled == True,
            ResponsePolicy.min_risk_score <= risk_score
        ).order_by(ResponsePolicy.min_risk_score.desc()).all()

        selected_policy = policies[0] if policies else None
        policy_name = selected_policy.name if selected_policy else "Default Risk Baseline Policy"
        duration = selected_policy.duration_seconds if selected_policy else 3600

        # Determine outcome based on risk band and policy action type
        if risk_score >= 85:
            # Critical risk: Eligible for isolation (Admin Approval or Auto Block depending on policy)
            action_type = "BLOCK"
            recommended = "ISOLATE_HOST"
            status = "PENDING_APPROVAL" if (selected_policy and selected_policy.action_type == "REQUIRE_APPROVAL") else "PENDING_APPROVAL"
            reason = f"Critical risk score ({risk_score}/100) triggered {policy_name}. Isolation recommended."
            is_eligible = True
        elif risk_score >= 65:
            # High risk
            action_type = "BLOCK"
            recommended = "TEMPORARY_BLOCK"
            status = "PENDING_APPROVAL"
            reason = f"High risk score ({risk_score}/100) triggered {policy_name}. Temporary restriction recommended."
            is_eligible = True
        elif threat is not None and (getattr(threat, 'severity', '') in ("Low", "Medium") or risk_score < 65):
            # Small / low-severity threats: Automatically blocked by background NIPS policy
            # without requiring manual administrator approval or disturbing continuous operations
            action_type = "BLOCK"
            recommended = "AUTO_BLOCK_SMALL_THREAT"
            status = "EXECUTED"
            reason = f"Minor threat ({threat.attack_category}) automatically blocked by silent mitigation policy. Admin not disturbed."
            is_eligible = True
        elif risk_score >= 50:
            # Elevated risk (benign anomaly / protocol irregularity)
            action_type = "MONITOR"
            recommended = "INTENSIVE_MONITORING"
            status = "SIMULATED"
            reason = f"Elevated risk score ({risk_score}/100) warrants heightened SOC surveillance."
            is_eligible = False
        else:
            # Low/Moderate benign telemetry
            action_type = "MONITOR"
            recommended = "STANDARD_MONITORING"
            status = "SIMULATED"
            reason = f"Risk score ({risk_score}/100) within normal operational tolerance."
            is_eligible = False

        return {
            "action_type": action_type,
            "recommended_action": recommended,
            "status": status,
            "is_eligible": is_eligible,
            "reason": reason,
            "duration_seconds": duration,
            "policy_name": policy_name
        }


# -----------------------------------------------------------------------------
# Response Execution & Rollback Manager
# -----------------------------------------------------------------------------
class ResponseExecutionManager:
    """
    Executes authorized response actions, manages simulation mode vs real OS
    firewall enforcement, schedules expirations, and handles rollback unblocks.
    """

    @staticmethod
    def execute_response(
        db: Session,
        target_ip: str,
        reason: str,
        actor: str = "POLICY_ENGINE",
        risk_assessment_id: Optional[int] = None,
        threat_id: Optional[int] = None,
        duration_seconds: int = 3600,
        policy_name: Optional[str] = None,
        force_real: bool = False
    ) -> Dict[str, Any]:
        """
        Executes a defense action (BLOCK) respecting simulation mode and allowlists.
        """
        # Allowlist Protection
        is_protected, prot_reason = ResponsePolicyEngine.is_ip_allowlisted(db, target_ip)
        if is_protected:
            return {
                "success": False,
                "error": f"Operation denied: {target_ip} is protected ({prot_reason})."
            }

        # Check simulation mode and real enforcement authorization
        sim_mode_str = ResponsePolicyEngine.get_system_config(db, "simulation_mode", "true").lower()
        real_auth_str = ResponsePolicyEngine.get_system_config(db, "real_enforcement_authorized", "false").lower()

        is_simulated = True
        if force_real or (sim_mode_str == "false" and real_auth_str == "true"):
            is_simulated = False

        now = datetime.utcnow()
        expires_at = now + timedelta(seconds=duration_seconds) if duration_seconds > 0 else None

        os_output = "SIMULATED: Action logged in Automated Response Centre ledger without touching OS packet filter."
        fw_result = None

        if not is_simulated:
            # Real OS Kernel Enforcement
            fw_result = firewall.block_ip(
                ip=target_ip,
                reason=reason,
                blocked_by=f"SECURENET_{actor.upper()}",
                db=db
            )
            os_success = fw_result.get("os_success", False)
            os_output = f"REAL OS ENFORCEMENT: {fw_result.get('os_details', {}).get('output', 'Enforced')}"
            action_status = "EXECUTED" if os_success else "FAILED"
        else:
            # Simulated Execution: Synchronize in DB without executing privileged kernel commands
            action_status = "SIMULATED"
            # Add to FirewallRule as simulated / active
            existing_rule = db.query(FirewallRule).filter(
                FirewallRule.ip_address == target_ip,
                FirewallRule.is_active == True
            ).first()
            if not existing_rule:
                db.add(FirewallRule(
                    ip_address=target_ip,
                    reason=f"[SIMULATION] {reason}",
                    blocked_by=f"SIMULATED_{actor.upper()}",
                    timestamp=now,
                    is_active=True
                ))

        # Record ResponseAction
        action_record = ResponseAction(
            risk_assessment_id=risk_assessment_id,
            threat_id=threat_id,
            target_ip=target_ip,
            action_type="BLOCK",
            status=action_status,
            is_simulated=is_simulated,
            reason=reason,
            initiated_by=actor,
            policy_name=policy_name or "Automated Response Policy",
            created_at=now,
            executed_at=now,
            expires_at=expires_at,
            execution_output=os_output
        )
        db.add(action_record)

        # Record AuditLog
        db.add(AuditLog(
            actor=actor,
            action="SIMULATED_BLOCK" if is_simulated else "KERNEL_BLOCK_ENFORCED",
            target=target_ip,
            details=f"Action: BLOCK | Mode: {'SIMULATION' if is_simulated else 'REAL KERNEL'} | TTL: {duration_seconds}s | Reason: {reason}",
            status="SUCCESS" if action_status in ("EXECUTED", "SIMULATED") else "FAILURE"
        ))

        db.commit()
        db.refresh(action_record)

        return {
            "success": action_status in ("EXECUTED", "SIMULATED"),
            "action_id": action_record.id,
            "target_ip": target_ip,
            "status": action_status,
            "is_simulated": is_simulated,
            "expires_at": expires_at.isoformat() if expires_at else None,
            "output": os_output,
            "firewall_result": fw_result
        }

    @staticmethod
    def rollback_action(
        db: Session,
        action_id: int,
        reversed_by: str = "ADMIN"
    ) -> Dict[str, Any]:
        """
        Reverses an existing response action (unblocks host and updates audit ledger).
        """
        action = db.query(ResponseAction).filter(ResponseAction.id == action_id).first()
        if not action:
            return {"success": False, "error": f"Response action #{action_id} not found"}

        target_ip = action.target_ip
        now = datetime.utcnow()

        if not action.is_simulated:
            # Revoke real OS firewall drop
            fw_res = firewall.unblock_ip(ip=target_ip, db=db)
            os_out = f"Kernel drop rule revoked: {fw_res.get('os_details', {}).get('output', 'Revoked')}"
        else:
            # Deactivate in FirewallRule DB table
            rules = db.query(FirewallRule).filter(
                FirewallRule.ip_address == target_ip,
                FirewallRule.is_active == True
            ).all()
            for r in rules:
                r.is_active = False
            os_out = "Simulated restriction deactivated in NIDS defense ledger."

        action.status = "REVERSED"
        action.reversed_at = now
        action.reversed_by = reversed_by
        action.execution_output = f"{action.execution_output or ''}\n[REVERSED at {now.isoformat()} by {reversed_by}]: {os_out}"

        # AuditLog
        db.add(AuditLog(
            actor=reversed_by,
            action="ROLLBACK_RESPONSE",
            target=target_ip,
            details=f"Rollback of ResponseAction #{action_id} ({action.action_type}) by {reversed_by}. {os_out}",
            status="SUCCESS"
        ))

        db.commit()

        return {
            "success": True,
            "action_id": action.id,
            "target_ip": target_ip,
            "status": "REVERSED",
            "reversed_by": reversed_by,
            "reversed_at": now.isoformat(),
            "details": os_out
        }

    @staticmethod
    def check_expired_actions(db: Session) -> int:
        """
        Background maintenance routine checking for expired temporary restrictions
        and rolling them back safely.
        """
        now = datetime.utcnow()
        expired = db.query(ResponseAction).filter(
            ResponseAction.status.in_(["EXECUTED", "SIMULATED"]),
            ResponseAction.expires_at != None,
            ResponseAction.expires_at <= now
        ).all()

        reclaimed_count = 0
        for act in expired:
            try:
                ResponseExecutionManager.rollback_action(
                    db=db,
                    action_id=act.id,
                    reversed_by="SYSTEM_TTL_EXPIRY"
                )
                act.status = "EXPIRED"
                reclaimed_count += 1
            except Exception as e:
                logger.error(f"Failed to expire action #{act.id}: {e}")

        if reclaimed_count > 0:
            db.commit()
            logger.info(f"Reclaimed {reclaimed_count} expired response restrictions.")

        return reclaimed_count
