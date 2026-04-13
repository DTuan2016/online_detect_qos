import joblib
import numpy as np
import socket
import time
import os
import sys

from scapy.all import sniff, get_if_hwaddr
from scapy.layers.inet import IP, TCP, UDP

# =====================
# CONFIG
# =====================
IN_IFACE  = "eth0"
OUT_IFACE = "veth-host"

MODEL_PATH = os.path.expanduser(
    "~/online_detect_qos/classification_model/rf_16p_9f_test.pkl"
)

MIN_PKTS_FOR_CLASSIFY = 16
FLOW_TIMEOUT_NS = 30 * 1e9

# Biến toàn cục quan trọng để giả lập tshark frame.time_delta
last_pkt_timestamp = None 

DSCP_MAP = {
    0: 0,  # BROWSING
    1: 8,  # CHAT
    2: 16, # FT
    3: 24, # P2P
    4: 32, # STREAMING
    5: 40, # VOIP
    6: 48, # MAIL
}

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# =====================
# LOAD MODEL
# =====================
try:
    pipeline = joblib.load(MODEL_PATH)
    if hasattr(pipeline, "best_estimator_"):
        pipeline = pipeline.best_estimator_

    scaler = None
    classifier = pipeline

    if hasattr(pipeline, "named_steps"):
        steps = list(pipeline.named_steps.values())
        if len(steps) > 1:
            scaler = steps[0]
            classifier = steps[-1]
        else:
            classifier = steps[0]
    log(f"Model loaded. Classifier: {type(classifier)}")
except Exception as e:
    log(f"Failed to load model: {e}")
    sys.exit(1)

# =====================
# FLOW TABLE
# =====================
flows = {}

def get_flow_key(pkt):
    if IP not in pkt:
        return None
    ip = pkt[IP]
    proto = ip.proto
    sport, dport = 0, 0
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    return (ip.src, ip.dst, proto, sport, dport)

# =====================
# FLOW UPDATE (IAT LOGIC LIKE TSHARK)
# =====================
def update_flow(pkt):
    global last_pkt_timestamp
    key = get_flow_key(pkt)
    if key is None:
        return None, None, None

    # 1. Lấy timestamp gốc từ card mạng (giống frame.time_epoch)
    now_sec = float(pkt.time)

    # 2. Tính IAT kiểu Tshark (Global Delta)
    if last_pkt_timestamp is None:
        current_iat = 0.0
    else:
        # Khoảng cách với gói tin VỪA BAY QUA TRƯỚC ĐÓ (Global)
        current_iat = now_sec - last_pkt_timestamp
    
    # Cập nhật timestamp toàn cục cho gói tiếp theo
    last_pkt_timestamp = now_sec

    # 3. Tính Packet Length (IP Header + Ethernet Overhead)
    pkt_len = pkt[IP].len + 14 

    if key not in flows:
        flows[key] = {
            "total_pkts": 0,
            "last_seen": now_sec,
            "min_iat": None,
            "max_iat": 0.0,
            "sum_iat": 0.0,
            "min_len": pkt_len,
            "max_len": pkt_len,
            "sum_len": 0.0,
            "classified": False,
            "label": None,
            "current_iat": current_iat
        }

    f = flows[key]
    f["last_seen"] = now_sec
    f["current_iat"] = current_iat # Gói đầu của flow vẫn mang IAT so với gói global trước đó

    # 4. Cập nhật thống kê Features
    if f["total_pkts"] > 0:
        if f["min_iat"] is None or current_iat < f["min_iat"]:
            f["min_iat"] = current_iat
        if current_iat > f["max_iat"]:
            f["max_iat"] = current_iat
        f["sum_iat"] += current_iat
    else:
        # Gói đầu tiên của flow: khởi tạo min/max/sum bằng chính iat đó
        f["min_iat"] = current_iat
        f["max_iat"] = current_iat
        f["sum_iat"] = current_iat

    if pkt_len < f["min_len"]: f["min_len"] = pkt_len
    if pkt_len > f["max_len"]: f["max_len"] = pkt_len
    
    f["sum_len"] += pkt_len
    f["total_pkts"] += 1

    return key, f, pkt_len

# =====================
# FEATURE BUILDER (9 FEATURES)
# =====================
def build_feature_vector(flow, pkt_len):
    # Chỉ phân loại khi flow đạt đủ số gói tin (ví dụ 16 gói)
    if flow["total_pkts"] < MIN_PKTS_FOR_CLASSIFY:
        return None

    # Tính toán các giá trị trung bình
    mean_len = float(flow["sum_len"] / flow["total_pkts"])
    
    # Mean IAT lúc này là trung bình của các Global IATs xuất hiện trong flow
    mean_iat = float(flow["sum_iat"] / flow["total_pkts"])

    # THỨ TỰ 9 CỘT: current_length, max_length, min_length, sum_length, mean_length, max_iat, min_iat, sum_iat, mean_iat
    features = np.array([
        float(pkt_len),               # current_length
        float(flow["max_len"]),
        float(flow["min_len"]),
        float(flow["sum_len"]),
        float(mean_len),
        float(flow["max_iat"]),
        float(flow["min_iat"]),
        float(flow["sum_iat"]),
        float(mean_iat)
    ]).reshape(1, -1)

    return features

# =====================
# DSCP & FORWARDING
# =====================
def rewrite_dscp(pkt, predicted_class, flow_key):
    if IP not in pkt:
        return pkt
    ip = pkt[IP]
    dscp = DSCP_MAP.get(predicted_class, 0)
    ecn = ip.tos & 0x03
    ip.tos = (dscp << 2) | ecn

    src_ip, dst_ip, proto, sport, dport = flow_key
    log(f"SET DSCP={dscp} | CLASS={predicted_class} | FLOW: {src_ip}:{sport} -> {dst_ip}:{dport}")

    # Xóa checksum để Scapy tính lại tự động khi gửi
    del ip.chksum
    if TCP in pkt: del pkt[TCP].chksum
    if UDP in pkt: del pkt[UDP].chksum
    return pkt

out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

def cleanup_flows():
    now = float(time.time())
    expired = [k for k, f in flows.items() if (now - f["last_seen"]) > (FLOW_TIMEOUT_NS / 1e9)]
    for k in expired:
        log(f"Flow expired: {k}")
        del flows[k]

# =====================
# MAIN PROCESSOR
# =====================
def process_packet(pkt):
    try:
        key, flow, pkt_len = update_flow(pkt)
        if key is None:
            return

        # Nếu đã phân loại rồi thì chỉ việc gán DSCP và forward
        if flow["classified"]:
            pkt = rewrite_dscp(pkt, flow["label"], key)
            out_socket.send(bytes(pkt))
            return

        # Xây dựng vector đặc trưng
        features = build_feature_vector(flow, pkt_len)
        if features is None:
            # Gói tin chưa đủ số lượng để phân loại, forward bình thường (hoặc drop tùy policy)
            out_socket.send(bytes(pkt))
            return

        # Tiền xử lý (nếu model có scaler)
        features_scaled = scaler.transform(features) if scaler else features

        # Predict
        predicted_class = classifier.predict(features_scaled)[0]
        flow["classified"] = True
        flow["label"] = int(predicted_class)

        log(f">>> Classified Flow {key} as Class {predicted_class}")

        pkt = rewrite_dscp(pkt, flow["label"], key)
        out_socket.send(bytes(pkt))
        
        cleanup_flows()

    except Exception as e:
        log(f"ERROR: {e}")

# =====================
# START SNIFFING
# =====================
log(f"Listening on {IN_IFACE} -> Global IAT Mode -> Forwarding to {OUT_IFACE}")

sniff(
    iface=IN_IFACE,
    filter=f"ip and ether dst {get_if_hwaddr(IN_IFACE)}",
    prn=process_packet,
    store=False
)
