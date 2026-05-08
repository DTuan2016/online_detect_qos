import joblib
import numpy as np
import socket
import time
import os
import pandas as pd
import csv
import threading
import signal
import sys
import warnings
from scapy.all import sniff, get_if_hwaddr
from scapy.layers.inet import IP, TCP, UDP

# Ẩn các cảnh báo parallel của sklearn/joblib
warnings.filterwarnings("ignore", category=UserWarning)

# =====================
# CONFIG & PATHS
# =====================
IN_IFACE  = "eth0"
OUT_IFACE = "veth-host"
MODEL_PATH = "../classification_model/rf_length_n12.pkl"
LABEL_PATH = "../classification_model/label_encoder_n12.pkl"
CSV_OUT    = "./result_us_2204.csv"

MIN_PKTS_FOR_CLASSIFY = 12
FLOW_TIMEOUT_NS = 30 * 1e9

# Bảng mapping DSCP
DSCP_MAP = {0: 0, 1: 8, 2: 16, 3: 24, 4: 32, 5: 40, 6: 48}

# Đặc trưng chuẩn
FEATURE_COLUMNS = [
    'flow_length_min', 'flow_length_max', 'flow_length_sum',
    'flow_length_mean', 'flow_length_median', 'flow_length_std',
    'flow_length_q1', 'flow_length_q3', 'flow_length_skew', 'flow_length_kurt'
]

# =====================
# INITIALIZATION
# =====================
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

log("Đang tải tài nguyên AI...")
classifier = joblib.load(MODEL_PATH)
label_encoder = joblib.load(LABEL_PATH)

# Ép model chạy đơn luồng để tránh lỗi UserWarning và tăng tốc inference nhỏ lẻ
if hasattr(classifier, 'n_jobs'):
    classifier.n_jobs = 1

flows = {}
CSV_HEADER_WRITTEN = False

# =====================
# UTILS
# =====================
def write_result_to_csv(flow_key, flow, features, label_idx):
    global CSV_HEADER_WRITTEN
    file_exists = os.path.exists(CSV_OUT)
    
    label_name = label_encoder.inverse_transform([label_idx])[0]
    src_ip, dst_ip, proto, sport, dport = flow_key
    
    f_vals = features.iloc[0].to_dict()
    row = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "src_ip": src_ip, "dst_ip": dst_ip, "proto": proto,
        "sport": sport, "dport": dport,
        "total_pkts": flow["total_pkts"],
        **f_vals,
        "predicted_label": label_name
    }

    with open(CSV_OUT, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not file_exists or not CSV_HEADER_WRITTEN:
            writer.writeheader()
            CSV_HEADER_WRITTEN = True
        writer.writerow(row)

def build_feature_vector(flow):
    lens = pd.Series(flow["all_lens"])
    feature_map = {
        'flow_length_min':    float(lens.min()),
        'flow_length_max':    float(lens.max()),
        'flow_length_sum':    float(lens.sum()),
        'flow_length_mean':   float(lens.mean()),
        'flow_length_median': float(lens.median()),
        'flow_length_std':    float(lens.std()) if len(lens) > 1 else 0.0,
        'flow_length_q1':     float(lens.quantile(0.25)),
        'flow_length_q3':     float(lens.quantile(0.75)),
        'flow_length_skew':   float(lens.skew()) if len(lens) > 2 else 0.0,
        'flow_length_kurt':   float(lens.kurtosis()) if len(lens) > 3 else 0.0
    }
    return pd.DataFrame([[feature_map[f] for f in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)

# =====================
# CORE LOGIC
# =====================
def process_packet(pkt):
    try:
        if IP not in pkt: return
        
        ip = pkt[IP]
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        key = (ip.src, ip.dst, ip.proto, sport, dport)

        # QUAN TRỌNG: Kiểm tra xem Training dùng ip.len (IP) hay ip.len+14 (Ethernet)
        pkt_len = ip.len + 14 
        
        if key not in flows:
            flows[key] = {
                "total_pkts": 0,
                "all_lens": [],
                "classified_final": False,
                "last_pred": 0
            }
        
        f = flows[key]

        # Chỉ xử lý Inference và ghi log cho 12 gói đầu tiên
        if not f["classified_final"]:
            f["total_pkts"] += 1
            f["all_lens"].append(pkt_len)
            
            features = build_feature_vector(f)
            pred = int(classifier.predict(features)[0])
            f["last_pred"] = pred
            
            # Ghi lại diễn biến từ gói 1 -> 12
            write_result_to_csv(key, f, features, pred)

            if f["total_pkts"] >= MIN_PKTS_FOR_CLASSIFY:
                f["classified_final"] = True
                label_name = label_encoder.inverse_transform([pred])[0]
                log(f"[STABLE] Flow {ip.src}:{sport} -> {ip.dst}:{dport} chốt nhãn: {label_name}")

        # Rewrite DSCP & Forward (Thực hiện cho mọi gói tin)
        dscp = DSCP_MAP.get(f["last_pred"], 0)
        ip.tos = (dscp << 2) | (ip.tos & 0x03)
        
        # Xóa checksum để Scapy tính lại
        del ip.chksum
        if TCP in pkt: del pkt[TCP].chksum
        if UDP in pkt: del pkt[UDP].chksum
        
        out_socket.send(bytes(pkt))
        
    except Exception as e:
        pass # Tránh crash script khi gặp gói tin lỗi

# =====================
# SIGNAL HANDLER & START
# =====================
def shutdown(sig, frame):
    log("Chương trình đang dừng...")
    out_socket.close()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

# Khởi tạo Socket gửi
out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

log(f"Inference Engine started: {IN_IFACE} -> {OUT_IFACE}")
try:
    sniff(
        iface=IN_IFACE, 
        filter=f"ether dst {get_if_hwaddr(IN_IFACE)}", 
        prn=process_packet, 
        store=False
    )
finally:
    out_socket.close()
