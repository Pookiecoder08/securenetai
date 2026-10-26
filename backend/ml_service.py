"""
SecureNet AI — AI Behavioral Anomaly Detection Engine
Implements unsupervised network traffic behavioral analysis using Isolation Forest.
Provides feature extraction, scalable model persistence, explainable deviation scoring,
and offline training/evaluation pipelines.
"""

import os
import math
import json
import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
import numpy as np

try:
    import joblib
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import RobustScaler
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    IsolationForest = None
    RobustScaler = None
    joblib = None

from models import AIAnalysis, PacketLog

logger = logging.getLogger("securenet.ml")

MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models_store")
MODEL_FILE = os.path.join(MODEL_DIR, "isolation_forest_v1.joblib")
METADATA_FILE = os.path.join(MODEL_DIR, "model_metadata.json")

FEATURE_NAMES = [
    "conn_count",
    "unique_dst_ports",
    "unique_dst_ips",
    "total_bytes",
    "avg_bytes_per_pkt",
    "outbound_ratio",
    "tcp_syn_ratio",
    "sensitive_port_ratio",
    "dns_query_ratio",
    "payload_entropy"
]

FEATURE_BASELINES = {
    "conn_count": {"mean": 12.0, "std": 15.0},
    "unique_dst_ports": {"mean": 2.5, "std": 3.0},
    "unique_dst_ips": {"mean": 1.8, "std": 2.0},
    "total_bytes": {"mean": 14500.0, "std": 25000.0},
    "avg_bytes_per_pkt": {"mean": 512.0, "std": 400.0},
    "outbound_ratio": {"mean": 0.45, "std": 0.25},
    "tcp_syn_ratio": {"mean": 0.10, "std": 0.15},
    "sensitive_port_ratio": {"mean": 0.05, "std": 0.10},
    "dns_query_ratio": {"mean": 0.15, "std": 0.20},
    "payload_entropy": {"mean": 3.2, "std": 1.2}
}


def calculate_shannon_entropy(data_str: str) -> float:
    """Calculates Shannon entropy of string data in bits per character."""
    if not data_str:
        return 0.0
    entropy = 0.0
    length = len(data_str)
    counts = {}
    for char in data_str:
        counts[char] = counts.get(char, 0) + 1
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


class FeatureExtractor:
    """
    Extracts reproducible network flow features from packet sequences or summarized telemetry.
    """

    @staticmethod
    def extract_from_packets(packets: List[Dict[str, Any]], host_ip: str) -> Dict[str, float]:
        """Calculates 10 numeric network-flow features for a target host."""
        if not packets:
            return {name: 0.0 for name in FEATURE_NAMES}

        conn_count = len(packets)
        dst_ports = set()
        dst_ips = set()
        total_bytes = 0
        outbound_count = 0
        syn_count = 0
        sensitive_count = 0
        dns_count = 0
        payload_samples = []

        recon_ports = {21, 22, 23, 25, 445, 1433, 1521, 3306, 3389, 5432, 6379, 8080, 27017, 31337}

        for p in packets:
            src = p.get("src_ip", "")
            dst = p.get("dst_ip", "")
            dport = p.get("dst_port")
            length = p.get("length") or 64
            proto = (p.get("protocol") or "").upper()
            payload = p.get("payload_ascii") or ""

            if dport is not None:
                dst_ports.add(dport)
                if dport in recon_ports:
                    sensitive_count += 1
            if dst:
                dst_ips.add(dst)

            total_bytes += length

            if p.get("direction") == "outbound" or src == host_ip:
                outbound_count += 1

            if proto == "DNS" or dport == 53 or p.get("src_port") == 53:
                dns_count += 1

            # Estimate SYN probe if packet has minimal length and TCP
            if proto == "TCP" and length <= 64:
                syn_count += 1

            if payload:
                payload_samples.append(payload[:64])

        combined_payload = "".join(payload_samples)
        entropy = calculate_shannon_entropy(combined_payload) if combined_payload else 0.0

        return {
            "conn_count": float(conn_count),
            "unique_dst_ports": float(len(dst_ports)),
            "unique_dst_ips": float(len(dst_ips)),
            "total_bytes": float(total_bytes),
            "avg_bytes_per_pkt": round(float(total_bytes) / max(conn_count, 1), 2),
            "outbound_ratio": round(float(outbound_count) / max(conn_count, 1), 3),
            "tcp_syn_ratio": round(float(syn_count) / max(conn_count, 1), 3),
            "sensitive_port_ratio": round(float(sensitive_count) / max(conn_count, 1), 3),
            "dns_query_ratio": round(float(dns_count) / max(conn_count, 1), 3),
            "payload_entropy": float(entropy)
        }


class BehavioralAnomalyDetector:
    """
    Loads, executes, and manages the Isolation Forest anomaly detector.
    Provides explainable factor contributions and documented model limitations.
    """

    def __init__(self):
        self.model = None
        self.scaler = None
        self.metadata = {}
        self.is_loaded = False
        self._load_model()

    def _load_model(self):
        """Loads serialized model and scaler from disk if available."""
        if not SKLEARN_AVAILABLE:
            logger.warning("scikit-learn is unavailable; AI model running in fallback mode.")
            return

        if os.path.exists(MODEL_FILE):
            try:
                bundle = joblib.load(MODEL_FILE)
                self.model = bundle.get("model")
                self.scaler = bundle.get("scaler")
                if os.path.exists(METADATA_FILE):
                    with open(METADATA_FILE, "r") as f:
                        self.metadata = json.load(f)
                self.is_loaded = True
                logger.info(f"Loaded Isolation Forest model from {MODEL_FILE}")
            except Exception as e:
                logger.error(f"Failed to load Isolation Forest artifact: {e}")
                self.is_loaded = False
        else:
            logger.info("No trained Isolation Forest model found on disk. Initial training pending.")

    def analyze_host_traffic(
        self,
        target_ip: str,
        feature_dict: Dict[str, float]
    ) -> Dict[str, Any]:
        """
        Runs anomaly detection on a host's feature vector.
        Returns:
            - anomaly_score: 0-100 normalized score
            - raw_decision_score: float
            - is_anomaly: bool
            - model_version: str
            - explanation: str
            - contributing_features: List[Dict]
            - limitations: str
        """
        # Ensure feature vector follows exact sequence
        vec = [feature_dict.get(name, 0.0) for name in FEATURE_NAMES]
        x_raw = np.array([vec], dtype=np.float64)

        model_version = self.metadata.get("version", "1.0.0-uninitialized")
        limitations = (
            "Isolation Forest is an unsupervised outlier detection model. "
            "It measures multidimensional isolation depth in network flow metrics. "
            "High anomaly scores indicate statistically unusual traffic patterns relative "
            "to baseline training data, but do NOT prove malicious attack intent."
        )

        if self.is_loaded and self.model is not None and self.scaler is not None:
            try:
                x_scaled = self.scaler.transform(x_raw)
                # In scikit-learn IsolationForest:
                # decision_function returns < 0 for anomalies, > 0 for inliers
                decision_score = float(self.model.decision_function(x_scaled)[0])
                pred = int(self.model.predict(x_scaled)[0])  # -1 for anomaly, 1 for normal
                is_anomaly = (pred == -1)

                # Normalize score from ~[-0.3, 0.3] to [0, 100]
                # Lower decision score = more isolated = higher anomaly score
                raw_anomaly_score = (0.35 - decision_score) / 0.70
                anomaly_score = int(np.clip(round(raw_anomaly_score * 100), 0, 100))
            except Exception as e:
                logger.error(f"Inference error with Isolation Forest: {e}")
                anomaly_score, decision_score, is_anomaly = self._fallback_score(feature_dict)
        else:
            anomaly_score, decision_score, is_anomaly = self._fallback_score(feature_dict)

        # Compute top explainable feature deviations
        deviations = []
        for name, val in feature_dict.items():
            base = FEATURE_BASELINES.get(name, {"mean": 1.0, "std": 1.0})
            z_score = abs(val - base["mean"]) / max(base["std"], 0.001)
            deviations.append({
                "feature": name,
                "observed_value": val,
                "baseline_mean": base["mean"],
                "deviation_sigma": round(z_score, 2),
                "is_deviant": z_score > 2.0
            })

        deviations.sort(key=lambda d: d["deviation_sigma"], reverse=True)
        top_deviations = [d for d in deviations if d["is_deviant"]][:3]

        if is_anomaly:
            if top_deviations:
                dev_text = ", ".join(f"{d['feature']} ({d['deviation_sigma']}σ above baseline)" for d in top_deviations)
                explanation = f"Host traffic displays strong divergence from baseline network norms in: {dev_text}."
            else:
                explanation = "Multidimensional flow combination isolated as statistically rare outlier."
        else:
            explanation = "Host network telemetry conforms to typical baseline distributions."

        return {
            "target_ip": target_ip,
            "anomaly_score": anomaly_score,
            "raw_decision_score": round(decision_score, 4),
            "is_anomaly": is_anomaly,
            "model_name": "IsolationForest",
            "model_version": model_version,
            "model_loaded": self.is_loaded,
            "features": feature_dict,
            "top_deviations": top_deviations,
            "explanation": explanation,
            "limitations": limitations,
            "timestamp": datetime.utcnow().isoformat()
        }

    def _fallback_score(self, feature_dict: Dict[str, float]) -> Tuple[int, float, bool]:
        """Calculates a baseline z-score anomaly estimation when trained model is not loaded."""
        total_z = 0.0
        count = 0
        for name, val in feature_dict.items():
            base = FEATURE_BASELINES.get(name)
            if base:
                z = (val - base["mean"]) / max(base["std"], 0.001)
                if z > 0:
                    total_z += z
                count += 1
        avg_z = total_z / max(count, 1)
        score = int(np.clip(round(avg_z * 20), 0, 100))
        is_anomaly = score >= 60
        decision_score = round(0.5 - (score / 100.0), 3)
        return score, decision_score, is_anomaly


# Global Singleton
ml_detector = BehavioralAnomalyDetector()
