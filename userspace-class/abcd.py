import joblib
import numpy as np
import socket
import time
import os
import sys
import csv
import pandas as pd

from scapy.all import sniff, get_if_hwaddr
from scapy.layers.inet import IP, TCP, UDP

# =====================
# CONFIGURATION
# =====================
IN_IFACE  = "eth0"
OUT_IFACE = "veth-host"

MODEL_PATH = os.path.expanduser("~/online_detect_qos/classification_model/rf_12p_9f_test.pkl")
LOG_CSV_PATH = "test11111.csv"

CONFIRM_THRESHOLD = 12
FLOW_TIMEOUT_SEC = 30.0

LABEL_NAME_MAP = {
    0: 'BROWSING', 1: 'CHAT', 2: 'FT', 3: 'P2P', 4: 'STREAMING', 5: 'VOIP', 6: 'MAIL'
}

DSCP_MAP = {0: 0, 1: 8, 2: 16, 3: 24, 4: 32, 5: 40, 6: 48}

# Danh sách feature phải khớp 100% với lúc train
FEATS_FLOWS = [
    'fwd_length_last',
    'bwd_length_last',
    'fwd_iat_max',
    'fwd_iat_mean',
    'fwd_iat_min',
    'bwd_iat_sum',
    'bwd_iat_max',
    'bwd_iat_mean',
    'bwd_iat_min',
    'bwd_iat_sum',
    'fwd_length_max',
    'fwd_length_mean',
    'fwd_length_min',
    'bwd_length_sum',
    'bwd_length_max',
    'bwd_length_mean',
    'bwd_length_min',
    'bwd_length_sum',
]

log_msg = lambda msg: print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# =====================
# INITIALIZE CSV LOG
# =====================
if not os.path.exists(LOG_CSV_PATH):
    with open(LOG_CSV_PATH, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            'timestamp', 'src_ip_min', 'src_ip_max', 'proto', 'port_min', 'port_max',
            'predicted_label', 'label_name', 'pkt_count'
        ])

def log_to_csv(key, label, pkt_count):
    with open(LOG_CSV_PATH, 'a', newline='') as f:
        writer = csv.writer(f)
        writer.writerow([
            time.strftime('%Y-%m-%d %H:%M:%S'),
            key[0], key[1], key[2], key[3], key[4],
            label, LABEL_NAME_MAP.get(label, "UNKNOWN"), pkt_count
        ])

# =====================
# LOAD MODEL
# =====================
try:
    pipeline = joblib.load(MODEL_PATH)
    if hasattr(pipeline, "best_estimator_"):
        pipeline = pipeline.best_estimator_

    scaler = pipeline.named_steps.get('scaler') if hasattr(pipeline, "named_steps") else None
    classifier = pipeline.named_steps.get('classifier', pipeline) if hasattr(pipeline, "named_steps") else pipeline
    log_msg("Model & scaler loaded.")
except Exception as e:
    log_msg(f"Error loading model: {e}")
    sys.exit(1)

# =====================
# FLOW STATE
# =====================
flows = {}

def make_biflow_key_and_direction(pkt):
    if IP not in pkt:
        return None, None, None

    ip = pkt[IP]
    proto = ip.proto

    if TCP in pkt:
        sport, dport = int(pkt[TCP].sport), int(pkt[TCP].dport)
    elif UDP in pkt:
        sport, dport = int(pkt[UDP].sport), int(pkt[UDP].dport)
    else:
        return None, None, None

    src_ip = str(ip.src)
    dst_ip = str(ip.dst)

    # symmetric biflow key
    ip_min, ip_max = sorted([src_ip, dst_ip])
    port_min, port_max = sorted([sport, dport])
    key = (ip_min, ip_max, proto, port_min, port_max)

    # hướng hiện tại của packet
    current_5tuple = (src_ip, dst_ip, sport, dport, proto)

    return key, current_5tuple, int(ip.len) + 14

def init_stats():
    return {
        "count": 0,
        "min": 0.0,
        "max": 0.0,
        "sum": 0.0,
        "last": 0.0
    }

def update_stats(stats, value):
    value = float(value)

    if stats["count"] == 0:
        stats["count"] = 1
        stats["min"] = value
        stats["max"] = value
        stats["sum"] = value
        stats["last"] = value
    else:
        stats["count"] += 1
        stats["min"] = min(stats["min"], value)
        stats["max"] = max(stats["max"], value)
        stats["sum"] += value
        stats["last"] = value

def mean_stats(stats):
    return stats["sum"] / stats["count"] if stats["count"] > 0 else 0.0

def init_flow(current_5tuple, now_sec):
    src_ip, dst_ip, sport, dport, proto = current_5tuple
    return {
        "forward_tuple": current_5tuple,   # chiều packet đầu tiên = forward
        "created_at": now_sec,
        "last_seen": now_sec,
        "total_pkts": 0,
        "classified_final": False,
        "label": 0,

        # nhớ thời gian packet cuối từng chiều để tính iat theo chiều
        "fwd_last_ts": None,
        "bwd_last_ts": None,

        # stats
        "fwd_iat": init_stats(),
        "bwd_iat": init_stats(),
        "fwd_len": init_stats(),
        "bwd_len": init_stats(),
    }

def update_flow(pkt):
    key, current_5tuple, pkt_len = make_biflow_key_and_direction(pkt)
    if key is None:
        return None, None

    now_sec = float(pkt.time)

    if key not in flows:
        flows[key] = init_flow(current_5tuple, now_sec)

    f = flows[key]
    f["last_seen"] = now_sec

    # xác định packet này là forward hay backward
    if current_5tuple == f["forward_tuple"]:
        direction = "fwd"
        last_ts_key = "fwd_last_ts"
        iat_stats = f["fwd_iat"]
        len_stats = f["fwd_len"]
    else:
        direction = "bwd"
        last_ts_key = "bwd_last_ts"
        iat_stats = f["bwd_iat"]
        len_stats = f["bwd_len"]

    # tính IAT theo từng chiều
    last_ts = f[last_ts_key]
    current_iat = 0.0 if last_ts is None else (now_sec - last_ts)
    f[last_ts_key] = now_sec

    update_stats(iat_stats, current_iat)
    update_stats(len_stats, pkt_len)
    f["total_pkts"] += 1

    return key, f

def build_features(flow):
    fwd_iat = flow["fwd_iat"]
    bwd_iat = flow["bwd_iat"]
    fwd_len = flow["fwd_len"]
    bwd_len = flow["bwd_len"]

    # dict nền để dễ nhìn
    base = {
        'fwd_length_last': float(fwd_len["last"]),
        'bwd_length_last': float(bwd_len["last"]),
        'fwd_iat_max': float(fwd_iat["max"]),
        'fwd_iat_mean': float(mean_stats(fwd_iat)),
        'fwd_iat_min': float(fwd_iat["min"]),
        'bwd_iat_sum': float(bwd_iat["sum"]),
        'bwd_iat_max': float(bwd_iat["max"]),
        'bwd_iat_mean': float(mean_stats(bwd_iat)),
        'bwd_iat_min': float(bwd_iat["min"]),
        'fwd_length_max': float(fwd_len["max"]),
        'fwd_length_mean': float(mean_stats(fwd_len)),
        'fwd_length_min': float(fwd_len["min"]),
        'bwd_length_sum': float(bwd_len["sum"]),
        'bwd_length_max': float(bwd_len["max"]),
        'bwd_length_mean': float(mean_stats(bwd_len)),
        'bwd_length_min': float(bwd_len["min"]),
    }

    # build đúng thứ tự feature lúc train, kể cả cột lặp
    row = []
    for col in FEATS_FLOWS:
        row.append(base[col])

    df_features = pd.DataFrame([row], columns=FEATS_FLOWS)
    return df_features

def cleanup_expired_flows():
    now = time.time()
    expired_keys = [k for k, v in flows.items() if (now - v["last_seen"]) > FLOW_TIMEOUT_SEC]
    for k in expired_keys:
        del flows[k]

# =====================
# PACKET OUTPUT
# =====================
out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

def apply_dscp_and_send(pkt, label):
    if IP in pkt:
        ip = pkt[IP]
        dscp = DSCP_MAP.get(label, 0)
        ip.tos = (dscp << 2) | (ip.tos & 0x03)

        if hasattr(ip, "chksum"):
            del ip.chksum
        if TCP in pkt and hasattr(pkt[TCP], "chksum"):
            del pkt[TCP].chksum
        if UDP in pkt and hasattr(pkt[UDP], "chksum"):
            del pkt[UDP].chksum

    out_socket.send(bytes(pkt))

# =====================
# PROCESSING
# =====================
def process_packet(pkt):
    try:
        cleanup_expired_flows()

        key, flow = update_flow(pkt)
        if key is None:
            return

        if flow["classified_final"]:
            apply_dscp_and_send(pkt, flow["label"])
            return

        feats = build_features(flow)
        feats_scaled = scaler.transform(feats) if scaler is not None else feats
        pred = int(classifier.predict(feats_scaled)[0])

        flow["label"] = pred

        if flow["total_pkts"] >= CONFIRM_THRESHOLD:
            flow["classified_final"] = True
            log_msg(f"FIXED LABEL: {key} -> {LABEL_NAME_MAP.get(pred, 'UNKNOWN')} (at pkt {flow['total_pkts']})")
            log_to_csv(key, pred, flow["total_pkts"])
        else:
            print(f"Early Detect {key}: {LABEL_NAME_MAP.get(pred, 'UNKNOWN')} (pkt {flow['total_pkts']})", end='\r')

        apply_dscp_and_send(pkt, pred)

    except Exception as e:
        print(f"Error: {e}")

# =====================
# START
# =====================
log_msg(f"Sniffing {IN_IFACE}... Logging to {LOG_CSV_PATH}")
sniff(
    iface=IN_IFACE,
    filter=f"ip and ether dst {get_if_hwaddr(IN_IFACE)}",
    prn=process_packet,
    store=False
)
