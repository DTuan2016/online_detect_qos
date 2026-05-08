import joblib
import numpy as np
import socket
import time
import os
import pandas as pd
import csv
import signal
import sys
import warnings
from scapy.all import sniff, get_if_hwaddr
from scapy.layers.inet import IP, TCP, UDP

# Ẩn cảnh báo
warnings.filterwarnings("ignore", category=UserWarning)

# =====================
# CONFIG & PATHS
# =====================
IN_IFACE  = "eth0"
OUT_IFACE = "veth-host"
# Cập nhật đường dẫn model mới của bạn tại đây
MODEL_PATH = "../classification_model/rf_length_iat_n12.pkl" 
LABEL_PATH = "../classification_model/label_encoder_n12.pkl"
CSV_OUT    = "./result_us_iat_2404.csv"

MIN_PKTS_FOR_CLASSIFY = 12

# Danh sách feature phải đúng thứ tự như khi Train
FEATURE_COLUMNS = [
    'flow_length_min', 'flow_length_max', 'flow_length_sum',
    'flow_length_mean', 'flow_iat_sum'
]

DSCP_MAP = {0: 0, 1: 8, 2: 16, 3: 24, 4: 32, 5: 40, 6: 48}

# =====================
# INITIALIZATION
# =====================
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

log("Đang tải tài nguyên AI (Length + IAT)...")
classifier = joblib.load(MODEL_PATH)
label_encoder = joblib.load(LABEL_PATH)

if hasattr(classifier, 'n_jobs'):
    classifier.n_jobs = 1

flows = {}
CSV_HEADER_WRITTEN = False

# =====================
# UTILS
# =====================
def build_feature_vector(flow):
    # 1. Xử lý Length
    lens = pd.Series(flow["all_lens"])
    
    # 2. Xử lý IAT (Inter-Arrival Time)
    # IAT là hiệu số giữa các mốc thời gian liên tiếp
    if len(flow["all_times"]) > 1:
        iats = pd.Series(np.diff(flow["all_times"]))
    else:
        iats = pd.Series([0.0])

    feature_map = {
        # Length features
        'flow_length_min':    float(lens.min()),
        'flow_length_max':    float(lens.max()),
        'flow_length_sum':    float(lens.sum()),
        'flow_length_mean':   float(lens.mean()),
        # IAT features
        'flow_iat_sum':       float(iats.sum()),
    }
    
    # Trả về DataFrame với đúng thứ tự cột FEATURE_COLUMNS
    return pd.DataFrame([[feature_map[f] for f in FEATURE_COLUMNS]], columns=FEATURE_COLUMNS)

def write_result_to_csv(flow_key, flow, features, label_idx):
    global CSV_HEADER_WRITTEN
    file_exists = os.path.exists(CSV_OUT)
    label_name = label_encoder.inverse_transform([label_idx])[0]
    src_ip, dst_ip, proto, sport, dport = flow_key

    row = {
        "timestamp": time.strftime('%Y-%m-%d %H:%M:%S'),
        "src_ip": src_ip, "dst_ip": dst_ip, "proto": proto,
        "sport": sport, "dport": dport,
        "total_pkts": flow["total_pkts"],
        **features.iloc[0].to_dict(),
        "predicted_label": label_name
    }

    with open(CSV_OUT, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=row.keys())
        if not file_exists or not CSV_HEADER_WRITTEN:
            writer.writeheader()
            CSV_HEADER_WRITTEN = True
        writer.writerow(row)

# =====================
# CORE LOGIC
# =====================
def process_packet(pkt):
    try:
        if IP not in pkt: return

        now = time.time() # Lấy timestamp ngay khi gói tin đến
        ip = pkt[IP]
        sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
        dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
        key = (ip.src, ip.dst, ip.proto, sport, dport)

        pkt_len = ip.len + 14

        if key not in flows:
            flows[key] = {
                "total_pkts": 0,
                "all_lens": [],
                "all_times": [], # Lưu list các mốc thời gian
                "classified_final": False,
                "last_pred": 0
            }

        f = flows[key]

        if not f["classified_final"]:
            f["total_pkts"] += 1
            f["all_lens"].append(pkt_len)
            f["all_times"].append(now)

            # Tính toán feature bao gồm cả IAT
            features = build_feature_vector(f)
            
            # Dự đoán
            pred = int(classifier.predict(features)[0])
            f["last_pred"] = pred

            # Ghi log CSV
            write_result_to_csv(key, f, features, pred)

            if f["total_pkts"] >= MIN_PKTS_FOR_CLASSIFY:
                f["classified_final"] = True
                label_name = label_encoder.inverse_transform([pred])[0]
                log(f"[STABLE] Flow {ip.src}:{sport} -> {ip.dst}:{dport} => {label_name}")

        # Forwarding & QoS Marking
        dscp = DSCP_MAP.get(f["last_pred"], 0)
        ip.tos = (dscp << 2) | (ip.tos & 0x03)
        
        del ip.chksum
        if TCP in pkt: del pkt[TCP].chksum
        if UDP in pkt: del pkt[UDP].chksum

        out_socket.send(bytes(pkt))

    except Exception:
        pass

# =====================
# START
# =====================
def shutdown(sig, frame):
    log("Đang dừng chương trình...")
    out_socket.close()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

log(f"Inference Engine (IAT Mode) started: {IN_IFACE} -> {OUT_IFACE}")
sniff(
    iface=IN_IFACE,
    filter=f"ether dst {get_if_hwaddr(IN_IFACE)}",
    prn=process_packet,
    store=False
)
