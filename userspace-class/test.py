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
LOG_CSV_PATH = "detected_flows_log.csv"

# Ngưỡng chốt kết quả (Sau 12 gói sẽ không predict lại nữa để tiết kiệm CPU)
CONFIRM_THRESHOLD = 12 
FLOW_TIMEOUT_NS = 30 * 1e9

last_pkt_timestamp = None 

# Map nhãn số sang tên dịch vụ (Ông chỉnh lại cho khớp với bộ train của ông)
LABEL_NAME_MAP = {
    0: 'BROWSING', 1: 'CHAT', 2: 'FT', 3: 'P2P', 4: 'STREAMING', 5: 'VOIP', 6: 'MAIL'
}

DSCP_MAP = {0: 0, 1: 8, 2: 16, 3: 24, 4: 32, 5: 40, 6: 48}

# =====================
# INITIALIZE CSV LOG
# =====================
if not os.path.exists(LOG_CSV_PATH):
    with open(LOG_CSV_PATH, 'w', newline='') as f:
        writer = csv.writer(f)
        writer.writerow(['timestamp', 'src_ip', 'dst_ip', 'proto', 'port_1', 'port_2', 'predicted_label', 'label_name', 'pkt_count'])

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
log_msg = lambda msg: print(f"[{time.strftime('%H:%M:%S')}] {msg}")

try:
    pipeline = joblib.load(MODEL_PATH)
    if hasattr(pipeline, "best_estimator_"):
        pipeline = pipeline.best_estimator_
    scaler = pipeline.named_steps.get('scaler') if hasattr(pipeline, "named_steps") else None
    classifier = pipeline.named_steps.get('classifier', pipeline) if hasattr(pipeline, "named_steps") else pipeline
    log_msg("Model & Scaler loaded.")
except Exception as e:
    log_msg(f"Error loading model: {e}"); sys.exit(1)

# =====================
# FLOW LOGIC
# =====================
flows = {}

def get_symmetric_flow_key(pkt):
    if IP not in pkt: return None
    ip = pkt[IP]
    proto = ip.proto
    if TCP in pkt: sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt: sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else: return None
    
    # Sắp xếp để gộp 2 chiều
    ips = sorted([ip.src, ip.dst])
    ports = sorted([sport, dport])
    return (ips[0], ips[1], proto, ports[0], ports[1])

def update_flow(pkt):
    global last_pkt_timestamp
    key = get_symmetric_flow_key(pkt)
    if key is None: return None, None, None

    now_sec = float(pkt.time)
    current_iat = now_sec - last_pkt_timestamp if last_pkt_timestamp else 0.0
    last_pkt_timestamp = now_sec

    pkt_len = pkt[IP].len + 14

    if key not in flows:
        flows[key] = {
            "total_pkts": 0, "last_seen": now_sec, "min_iat": None, "max_iat": 0.0,
            "sum_iat": 0.0, "min_len": pkt_len, "max_len": pkt_len, "sum_len": 0.0,
            "classified_final": False, "label": 0, "current_iat": current_iat
        }

    f = flows[key]
    f["last_seen"] = now_sec
    f["current_iat"] = current_iat

    # Cập nhật thống kê
    if f["total_pkts"] > 0:
        if f["min_iat"] is None or current_iat < f["min_iat"]: f["min_iat"] = current_iat
        if current_iat > f["max_iat"]: f["max_iat"] = current_iat
        f["sum_iat"] += current_iat
    else:
        f["min_iat"] = current_iat; f["max_iat"] = current_iat; f["sum_iat"] = current_iat

    if pkt_len < f["min_len"]: f["min_len"] = pkt_len
    if pkt_len > f["max_len"]: f["max_len"] = pkt_len
    f["sum_len"] += pkt_len
    f["total_pkts"] += 1

    return key, f, pkt_len

def build_features(f, pkt_len):
    # Cần ít nhất 2 gói để có IAT có ý nghĩa, nhưng ta có thể bắt đầu từ gói 1 (IAT=0)
    mean_len = f["sum_len"] / f["total_pkts"]
    mean_iat = f["sum_iat"] / f["total_pkts"]
    
    data = [[
        float(pkt_len), float(f["max_len"]), float(f["min_len"]), float(f["sum_len"]),
        float(mean_len), float(f["max_iat"]), float(f["min_iat"]), float(f["sum_iat"]), float(mean_iat)
    ]]
    feature_names = [
        'current_length', 'max_length', 'min_length', 'sum_length', 'mean_length',
        'max_iat', 'min_iat', 'sum_iat', 'mean_iat'
    ]
    
    df_features = pd.DataFrame(data, columns=feature_names)
        
    return df_features


# =====================
# PROCESSING
# =====================
out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

def process_packet(pkt):
    try:
        key, flow, pkt_len = update_flow(pkt)
        if key is None: return

        # Nếu đã chốt kết quả (đủ 12 gói)
        if flow["classified_final"]:
            apply_dscp_and_send(pkt, flow["label"])
            return

        # Thực hiện dự đoán (Cập nhật liên tục mỗi khi có packet mới)
        feats = build_features(flow, pkt_len)
        feats_scaled = scaler.transform(feats) if scaler else feats
        pred = int(classifier.predict(feats_scaled)[0])
        
        flow["label"] = pred
        
        # Kiểm tra nếu đạt ngưỡng 12 gói thì chốt và ghi log
        if flow["total_pkts"] >= CONFIRM_THRESHOLD:
            flow["classified_final"] = True
            log_msg(f"FIXED LABEL: {key} -> {LABEL_NAME_MAP.get(pred)} (at pkt {flow['total_pkts']})")
            log_to_csv(key, pred, flow["total_pkts"])
        else:
            # Log dự đoán tạm thời (tùy chọn, có thể comment để đỡ rối console)
            print(f"Early Detect {key}: {LABEL_NAME_MAP.get(pred)} (pkt {flow['total_pkts']})", end='\r')

        apply_dscp_and_send(pkt, pred)

    except Exception as e:
        print(f"Error: {e}")

def apply_dscp_and_send(pkt, label):
    if IP in pkt:
        ip = pkt[IP]
        dscp = DSCP_MAP.get(label, 0)
        ip.tos = (dscp << 2) | (ip.tos & 0x03)
        del ip.chksum
        if TCP in pkt: del pkt[TCP].chksum
        if UDP in pkt: del pkt[UDP].chksum
    out_socket.send(bytes(pkt))

# =====================
# START
# =====================
log_msg(f"Sniffing {IN_IFACE}... Logging to {LOG_CSV_PATH}")
sniff(iface=IN_IFACE, filter=f"ip and ether dst {get_if_hwaddr(IN_IFACE)}", prn=process_packet, store=False)
