"""
detector.py  —  Real-time DDoS detection engine
Loads trained model and predicts on incoming flow data.
"""
import os
import json
import numpy as np
import joblib
import time
import logging

logger = logging.getLogger(__name__)

MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')

FEATURE_COLS = [
    ' Flow Duration', ' Total Fwd Packets', ' Total Backward Packets',
    'Total Length of Fwd Packets', ' Total Length of Bwd Packets',
    ' Fwd Packet Length Max', ' Fwd Packet Length Min',
    ' Fwd Packet Length Mean', ' Fwd Packet Length Std',
    'Bwd Packet Length Max', ' Bwd Packet Length Min',
    ' Bwd Packet Length Mean', ' Bwd Packet Length Std',
    ' Flow Bytes/s', ' Flow Packets/s',
    ' Flow IAT Mean', ' Flow IAT Std', ' Flow IAT Max', ' Flow IAT Min',
    'Fwd IAT Total', ' Fwd IAT Mean', ' Fwd IAT Std',
    ' Fwd IAT Max', ' Fwd IAT Min', 'Bwd IAT Total',
    ' Bwd IAT Mean', ' Bwd IAT Std', ' Bwd IAT Max', ' Bwd IAT Min',
    ' Fwd PSH Flags', ' Bwd PSH Flags', ' Fwd URG Flags', ' Bwd URG Flags',
    ' Fwd Header Length', ' Bwd Header Length',
    'Fwd Packets/s', ' Bwd Packets/s',
    ' Min Packet Length', ' Max Packet Length',
    ' Packet Length Mean', ' Packet Length Std', ' Packet Length Variance',
    ' FIN Flag Count', ' SYN Flag Count', ' RST Flag Count',
    ' PSH Flag Count', ' ACK Flag Count', ' URG Flag Count',
    ' CWE Flag Count', ' ECE Flag Count',
    ' Down/Up Ratio', ' Average Packet Size', ' Avg Fwd Segment Size',
    ' Avg Bwd Segment Size',
    ' Subflow Fwd Packets', ' Subflow Fwd Bytes',
    ' Subflow Bwd Packets', ' Subflow Bwd Bytes',
    'Init_Win_bytes_forward', ' Init_Win_bytes_backward',
    ' act_data_pkt_fwd', ' min_seg_size_forward',
    'Active Mean', ' Active Std', ' Active Max', ' Active Min',
    'Idle Mean', ' Idle Std', ' Idle Max', ' Idle Min',
]


class DDoSDetector:
    def __init__(self):
        self.model       = None
        self.meta        = {}
        self.model_name  = "Unknown"
        self.all_results = {}
        self._load()

    def _load(self):
        model_path = os.path.join(MODEL_DIR, 'model.pkl')
        meta_path  = os.path.join(MODEL_DIR, 'meta.json')

        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            logger.info("Model loaded from %s", model_path)
        else:
            logger.warning("No model.pkl found — run train_model.py first")

        if os.path.exists(meta_path):
            with open(meta_path) as f:
                self.meta = json.load(f)
            self.model_name  = self.meta.get('best_model', 'Unknown')
            self.all_results = self.meta.get('all_results', {})

    def is_ready(self):
        return self.model is not None

    def predict(self, flow_features: dict) -> dict:
        """
        flow_features: dict with feature_name -> value
        Returns: {'label': 'ATTACK'|'BENIGN', 'confidence': float, 'model': str}
        """
        if not self.is_ready():
            return {'label': 'UNKNOWN', 'confidence': 0.0, 'model': 'none'}

        import pandas as pd
        row = {c: float(flow_features.get(c, 0)) for c in FEATURE_COLS}
        # Replace inf/nan
        for k in row:
            v = row[k]
            if v != v or abs(v) == float('inf'):
                row[k] = 0.0
        df   = pd.DataFrame([row])[FEATURE_COLS]

        pred  = self.model.predict(df)[0]
        label = 'ATTACK' if pred == 1 else 'BENIGN'

        confidence = 0.5
        if hasattr(self.model, 'predict_proba'):
            proba      = self.model.predict_proba(df)[0]
            confidence = float(max(proba))
        elif hasattr(self.model, 'decision_function'):
            score = self.model.decision_function(df)[0]
            confidence = float(1 / (1 + np.exp(-abs(score))))  # sigmoid

        return {
            'label':      label,
            'confidence': round(confidence, 4),
            'model':      self.model_name,
        }

    def predict_batch(self, rows: list) -> list:
        """rows: list of feature dicts"""
        return [self.predict(r) for r in rows]

    def get_model_info(self):
        return {
            'model_name':  self.model_name,
            'ready':       self.is_ready(),
            'all_results': self.all_results,
        }


# Singleton
_detector = None

def get_detector() -> DDoSDetector:
    global _detector
    if _detector is None:
        _detector = DDoSDetector()
    return _detector


# ─── Demo synthetic flow generator (for simulation) ─────────────────────────
import random

def generate_benign_flow(src_ip=None):
    np.random.seed(None)
    features = {c: float(np.random.normal(0.3, 0.1)) for c in FEATURE_COLS}
    features[' Flow Packets/s']    = float(np.random.uniform(10, 200))
    features[' Flow Bytes/s']      = float(np.random.uniform(1000, 50000))
    features[' Total Fwd Packets'] = float(np.random.randint(1, 20))
    features[' SYN Flag Count']    = 0.0
    return features


def generate_attack_flow(attack_type='DrDoS_UDP', src_ip=None):
    np.random.seed(None)
    features = {c: float(np.random.normal(0.8, 0.1)) for c in FEATURE_COLS}
    if attack_type == 'DrDoS_UDP':
        features[' Flow Packets/s'] = float(np.random.uniform(5000, 50000))
        features[' Flow Bytes/s']   = float(np.random.uniform(100000, 1000000))
        features[' Flow Duration']  = float(np.random.uniform(0, 100))
    elif attack_type == 'DrDoS_LDAP':
        features[' Flow Packets/s'] = float(np.random.uniform(3000, 30000))
        features[' Flow Bytes/s']   = float(np.random.uniform(500000, 5000000))
        features[' SYN Flag Count'] = float(np.random.randint(100, 500))
    elif attack_type == 'DrDoS_MSSQL':
        features[' Flow Packets/s'] = float(np.random.uniform(4000, 40000))
        features[' Flow Bytes/s']   = float(np.random.uniform(800000, 8000000))
        features[' ACK Flag Count'] = float(np.random.randint(200, 800))
    return features