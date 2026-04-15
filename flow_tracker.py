"""
flow_tracker.py — Real HTTP Traffic Flow Feature Extractor
Tracks actual incoming requests per IP and computes ML features from real data.
No fake IPs. Real source IPs from request.remote_addr.
"""
import time
import threading
from collections import defaultdict, deque
import numpy as np

# Per-IP flow window (seconds)
WINDOW_SEC = 10

class FlowRecord:
    """Accumulates real packet/request data per IP over a time window."""
    def __init__(self, src_ip):
        self.src_ip       = src_ip
        self.start_time   = time.time()
        self.packets      = []          # list of (timestamp, size, direction, flags)
        self.fwd_packets  = []          # client→server
        self.bwd_packets  = []          # server→client (response sizes)
        self.syn_count    = 0
        self.fin_count    = 0
        self.rst_count    = 0
        self.psh_count    = 0
        self.ack_count    = 0
        self.lock         = threading.Lock()

    def add_request(self, size_bytes, response_size, method, path, elapsed_ms):
        now = time.time()
        with self.lock:
            self.fwd_packets.append({'ts': now, 'size': size_bytes})
            self.bwd_packets.append({'ts': now, 'size': response_size})

            # Infer TCP flags from HTTP method/behavior
            if method in ('GET', 'HEAD'):
                self.ack_count += 1
            if method == 'POST':
                self.psh_count += 1
            # High-frequency tiny requests → SYN flood-like
            if size_bytes < 100:
                self.syn_count += 1

    def compute_features(self):
        """Compute the 68 CIC-IDS-2017 features from real request data."""
        now = time.time()
        with self.lock:
            fwd = self.fwd_packets[-200:]  # cap for perf
            bwd = self.bwd_packets[-200:]

            if not fwd:
                return None

            flow_duration   = max((now - self.start_time) * 1e6, 1)  # microseconds
            total_fwd       = len(fwd)
            total_bwd       = len(bwd)
            fwd_sizes       = [p['size'] for p in fwd]
            bwd_sizes       = [p['size'] for p in bwd]
            fwd_ts          = [p['ts'] for p in fwd]
            bwd_ts          = [p['ts'] for p in bwd]
            all_ts          = sorted(fwd_ts + bwd_ts)
            all_sizes       = fwd_sizes + bwd_sizes

            def safe_stats(arr):
                if not arr: return 0, 0, 0, 0
                a = np.array(arr, dtype=float)
                return float(np.max(a)), float(np.min(a)), float(np.mean(a)), float(np.std(a))

            def iat(ts_list):
                if len(ts_list) < 2: return [0]
                return [ts_list[i+1]-ts_list[i] for i in range(len(ts_list)-1)]

            fwd_max, fwd_min, fwd_mean, fwd_std = safe_stats(fwd_sizes)
            bwd_max, bwd_min, bwd_mean, bwd_std = safe_stats(bwd_sizes)
            all_max, all_min, all_mean, all_std  = safe_stats(all_sizes)

            flow_iats  = iat(all_ts)
            fwd_iats   = iat(fwd_ts)
            bwd_iats   = iat(bwd_ts)
            fi_max, fi_min, fi_mean, fi_std = safe_stats(flow_iats)
            fwi_max, fwi_min, fwi_mean, fwi_std = safe_stats(fwd_iats)
            bwi_max, bwi_min, bwi_mean, bwi_std = safe_stats(bwd_iats)

            total_fwd_bytes = sum(fwd_sizes)
            total_bwd_bytes = sum(bwd_sizes)
            flow_dur_sec    = max(flow_duration / 1e6, 0.001)
            flow_bytes_s    = (total_fwd_bytes + total_bwd_bytes) / flow_dur_sec
            flow_pkts_s     = (total_fwd + total_bwd) / flow_dur_sec
            fwd_pkts_s      = total_fwd / flow_dur_sec
            bwd_pkts_s      = total_bwd / flow_dur_sec
            down_up         = total_bwd_bytes / max(total_fwd_bytes, 1)
            avg_pkt_size    = (total_fwd_bytes + total_bwd_bytes) / max(total_fwd + total_bwd, 1)

            features = {
                ' Flow Duration':              flow_duration,
                ' Total Fwd Packets':          float(total_fwd),
                ' Total Backward Packets':     float(total_bwd),
                'Total Length of Fwd Packets': float(total_fwd_bytes),
                ' Total Length of Bwd Packets':float(total_bwd_bytes),
                ' Fwd Packet Length Max':      fwd_max,
                ' Fwd Packet Length Min':      fwd_min,
                ' Fwd Packet Length Mean':     fwd_mean,
                ' Fwd Packet Length Std':      fwd_std,
                'Bwd Packet Length Max':       bwd_max,
                ' Bwd Packet Length Min':      bwd_min,
                ' Bwd Packet Length Mean':     bwd_mean,
                ' Bwd Packet Length Std':      bwd_std,
                ' Flow Bytes/s':               flow_bytes_s,
                ' Flow Packets/s':             flow_pkts_s,
                ' Flow IAT Mean':              fi_mean,
                ' Flow IAT Std':               fi_std,
                ' Flow IAT Max':               fi_max,
                ' Flow IAT Min':               fi_min,
                'Fwd IAT Total':               sum(fwd_iats),
                ' Fwd IAT Mean':               fwi_mean,
                ' Fwd IAT Std':                fwi_std,
                ' Fwd IAT Max':                fwi_max,
                ' Fwd IAT Min':                fwi_min,
                'Bwd IAT Total':               sum(bwd_iats),
                ' Bwd IAT Mean':               bwi_mean,
                ' Bwd IAT Std':                bwi_std,
                ' Bwd IAT Max':                bwi_max,
                ' Bwd IAT Min':                bwi_min,
                ' Fwd PSH Flags':              float(self.psh_count),
                ' Bwd PSH Flags':              0.0,
                ' Fwd URG Flags':              0.0,
                ' Bwd URG Flags':              0.0,
                ' Fwd Header Length':          float(total_fwd * 20),
                ' Bwd Header Length':          float(total_bwd * 20),
                'Fwd Packets/s':               fwd_pkts_s,
                ' Bwd Packets/s':              bwd_pkts_s,
                ' Min Packet Length':          all_min,
                ' Max Packet Length':          all_max,
                ' Packet Length Mean':         all_mean,
                ' Packet Length Std':          all_std,
                ' Packet Length Variance':     all_std ** 2,
                ' FIN Flag Count':             float(self.fin_count),
                ' SYN Flag Count':             float(self.syn_count),
                ' RST Flag Count':             float(self.rst_count),
                ' PSH Flag Count':             float(self.psh_count),
                ' ACK Flag Count':             float(self.ack_count),
                ' URG Flag Count':             0.0,
                ' CWE Flag Count':             0.0,
                ' ECE Flag Count':             0.0,
                ' Down/Up Ratio':              down_up,
                ' Average Packet Size':        avg_pkt_size,
                ' Avg Fwd Segment Size':       fwd_mean,
                ' Avg Bwd Segment Size':       bwd_mean,
                ' Subflow Fwd Packets':        float(total_fwd),
                ' Subflow Fwd Bytes':          float(total_fwd_bytes),
                ' Subflow Bwd Packets':        float(total_bwd),
                ' Subflow Bwd Bytes':          float(total_bwd_bytes),
                'Init_Win_bytes_forward':      float(min(65535, total_fwd_bytes)),
                ' Init_Win_bytes_backward':    float(min(65535, total_bwd_bytes)),
                ' act_data_pkt_fwd':           float(total_fwd),
                ' min_seg_size_forward':       fwd_min,
                'Active Mean':                 fi_mean,
                ' Active Std':                 fi_std,
                ' Active Max':                 fi_max,
                ' Active Min':                 fi_min,
                'Idle Mean':                   0.0,
                ' Idle Std':                   0.0,
                ' Idle Max':                   0.0,
                ' Idle Min':                   0.0,
            }
            return features

    def reset(self):
        with self.lock:
            self.start_time  = time.time()
            self.fwd_packets = []
            self.bwd_packets = []
            self.syn_count   = 0
            self.fin_count   = 0
            self.rst_count   = 0
            self.psh_count   = 0
            self.ack_count   = 0


# ── Attack type classifier from flow features ────────────────────────────────
def classify_attack_type(features, ip_req_rate):
    """
    Heuristic attack type classifier based on flow characteristics.
    Returns a string like 'DrDoS_UDP', 'DrDoS_LDAP', 'HTTP Flood', etc.
    """
    pkts_s     = features.get(' Flow Packets/s', 0)
    bytes_s    = features.get(' Flow Bytes/s', 0)
    syn_count  = features.get(' SYN Flag Count', 0)
    ack_count  = features.get(' ACK Flag Count', 0)
    avg_size   = features.get(' Average Packet Size', 0)
    fwd_pkts   = features.get(' Total Fwd Packets', 0)
    bwd_pkts   = features.get(' Total Backward Packets', 0)
    iat_mean   = features.get(' Flow IAT Mean', 1)

    # Large packets + high bytes/s → amplification (LDAP/MSSQL/DNS)
    if bytes_s > 100_000 and avg_size > 500:
        if bytes_s > 500_000:
            return 'DrDoS_LDAP'
        return 'DrDoS_MSSQL'

    # High pkt rate + small packets → UDP flood
    if pkts_s > 1000 and avg_size < 200:
        return 'DrDoS_UDP'

    # Many SYN, few ACK → SYN flood
    if syn_count > ack_count * 2 and syn_count > 10:
        return 'SYN Flood'

    # High request rate, normal size → HTTP Flood
    if ip_req_rate > 50 and 100 < avg_size < 2000:
        return 'HTTP Flood'

    # Very low IAT (< 1ms) → Volumetric
    if iat_mean < 0.001 and pkts_s > 500:
        return 'Volumetric Flood'

    # Many small fwd, few bwd → one-way flood
    if fwd_pkts > bwd_pkts * 5:
        return 'DrDoS_UDP'

    return 'DDoS Attack'


# ── Global flow tracker ───────────────────────────────────────────────────────
class FlowTracker:
    def __init__(self, window_sec=WINDOW_SEC):
        self._flows     = {}        # ip → FlowRecord
        self._req_counts= defaultdict(list)  # ip → [timestamps]
        self._lock      = threading.Lock()
        self.window_sec = window_sec
        # Start cleanup thread
        t = threading.Thread(target=self._cleanup_loop, daemon=True)
        t.start()

    def record(self, ip, req_size, resp_size, method='GET', path='/', elapsed_ms=0):
        with self._lock:
            if ip not in self._flows:
                self._flows[ip] = FlowRecord(ip)
            flow = self._flows[ip]

        flow.add_request(req_size, resp_size, method, path, elapsed_ms)

        # Track req rate
        now = time.time()
        with self._lock:
            self._req_counts[ip].append(now)
            # Trim old
            cutoff = now - self.window_sec
            self._req_counts[ip] = [t for t in self._req_counts[ip] if t > cutoff]

    def get_features(self, ip):
        with self._lock:
            flow = self._flows.get(ip)
        if not flow:
            return None
        return flow.compute_features()

    def get_req_rate(self, ip):
        """Requests per second in the last window"""
        now = time.time()
        with self._lock:
            counts = self._req_counts.get(ip, [])
            recent = [t for t in counts if t > now - self.window_sec]
        return len(recent) / self.window_sec

    def reset_flow(self, ip):
        with self._lock:
            if ip in self._flows:
                self._flows[ip].reset()

    def _cleanup_loop(self):
        """Remove stale flows for IPs not seen in 60s"""
        while True:
            time.sleep(30)
            now = time.time()
            with self._lock:
                stale = [ip for ip, flow in self._flows.items()
                         if now - flow.start_time > 60]
                for ip in stale:
                    del self._flows[ip]


_tracker = None

def get_tracker() -> FlowTracker:
    global _tracker
    if _tracker is None:
        _tracker = FlowTracker()
    return _tracker