import joblib
import numpy as np
import socket
import time
import os
import sys

from scapy.all import sniff, get_if_hwaddr
from scapy.layers.inet import IP, TCP, UDP

# =====================
# CONFIGURATION
# =====================
IN_IFACE  = "eth0"       # Interface bắt gói tin
OUT_IFACE = "veth-host"  # Interface đẩy gói tin đi sau khi rewrite

MODEL_PATH = os.path.expanduser(
    "~/online_detect_qos/classification_model/rf_12p_9f_test.pkl"
)

MIN_PKTS_FOR_CLASSIFY = 12  # Khớp với tham số -p ông vừa chạy
FLOW_TIMEOUT_NS = 30 * 1e9  # 30 giây timeout cho mỗi luồng

# Bản đồ gán nhãn Class -> Giá trị DSCP
DSCP_MAP = {
    0: 0,   # BROWSING
    1: 8,   # CHAT
    2: 16,  # FT
    3: 24,  # P2P
    4: 32,  # STREAMING
    5: 40,  # VOIP
    6: 48,  # MAIL
}

# Biến toàn cục để tính Global IAT (giống frame.time_delta của Tshark)
last_pkt_timestamp = None 

# =====================
# UTILS
# =====================
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# =====================
# LOAD MODEL & PREPROCESSOR
# =====================
try:
    log(f"Loading model from {MODEL_PATH}...")
    pipeline = joblib.load(MODEL_PATH)
    
    # Xử lý nếu model nằm trong GridSearchCV
    if hasattr(pipeline, "best_estimator_"):
        pipeline = pipeline.best_estimator_

    scaler = None
    classifier = pipeline

    # Tách Scaler nếu model được đóng gói trong Pipeline của sklearn
    if hasattr(pipeline, "named_steps"):
        steps = list(pipeline.named_steps.values())
        if len(steps) > 1:
            scaler = steps[0]
            classifier = steps[-1]
        else:
            classifier = steps[0]
            
    log(f"Model loaded successfully. Type: {type(classifier)}")
except Exception as e:
    log(f"CRITICAL ERROR: Could not load model: {e}")
    sys.exit(1)

# =====================
# FLOW MANAGEMENT
# =====================
flows = {}

def get_symmetric_flow_key(pkt):
    """Tạo key đối xứng để gộp 2 chiều A->B và B->A thành 1"""
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = ip.proto
    sport, dport = 0, 0

    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None

    # Sắp xếp IP và Port để tạo Key duy nhất cho cả 2 chiều
    ip_pair = tuple(sorted([ip.src, ip.dst]))
    port_pair = tuple(sorted([sport, dport]))

    return (ip_pair[0], ip_pair[1], proto, port_pair[0], port_pair[1])

def update_flow(pkt):
    global last_pkt_timestamp
    key = get_symmetric_flow_key(pkt)
    if key is None:
        return None, None, None

    # Lấy timestamp gốc từ card mạng
    now_sec = float(pkt.time)
    
    # 1. Tính Global IAT (Khoảng cách với gói tin vừa bay qua bất kỳ)
    if last_pkt_timestamp is None:
        current_iat = 0.0
    else:
        current_iat = now_sec - last_pkt_timestamp
    last_pkt_timestamp = now_sec

    # 2. Tính độ dài gói (IP Header len + Ethernet Header 14 bytes)
    pkt_len = pkt[IP].len + 14

    # Khởi tạo luồng mới nếu chưa tồn tại
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
        log(f"New Biflow detected: {key}")

    f = flows[key]
    f["last_seen"] = now_sec
    f["current_iat"] = current_iat

    # 3. Cập nhật thống kê đặc trưng (Gộp cả 2 chiều)
    if f["total_pkts"] > 0:
        if f["min_iat"] is None or current_iat < f["min_iat"]:
            f["min_iat"] = current_iat
        if current_iat > f["max_iat"]:
            f["max_iat"] = current_iat
        f["sum_iat"] += current_iat
    else:
        # Gói đầu tiên của luồng
        f["min_iat"] = current_iat
        f["max_iat"] = current_iat
        f["sum_iat"] = current_iat

    if pkt_len < f["min_len"]: f["min_len"] = pkt_len
    if pkt_len > f["max_len"]: f["max_len"] = pkt_len
    
    f["sum_len"] += pkt_len
    f["total_pkts"] += 1

    return key, f, pkt_len

# =====================
# FEATURE BUILDER
# =====================
def build_feature_vector(flow, pkt_len):
    """Xây dựng vector 9 cột chuẩn: current_length, max_len, min_len, sum_len, mean_len, max_iat, min_iat, sum_iat, mean_iat"""
    if flow["total_pkts"] < MIN_PKTS_FOR_CLASSIFY:
        return None

    # Tính các giá trị trung bình
    mean_len = float(flow["sum_len"] / flow["total_pkts"])
    mean_iat = float(flow["sum_iat"] / flow["total_pkts"])

    # Đảm bảo đúng thứ tự cột như lúc Train
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
# PACKET REWRITE & FORWARD
# =====================
def rewrite_and_send(pkt, label, flow_key):
    if IP in pkt:
        ip = pkt[IP]
        dscp_value = DSCP_MAP.get(label, 0)
        ecn = ip.tos & 0x03
        ip.tos = (dscp_value << 2) | ecn

        # Xóa checksum để Scapy tự tính lại
        del ip.chksum
        if TCP in pkt: del pkt[TCP].chksum
        if UDP in pkt: del pkt[UDP].chksum
        
        # Log trạng thái định kỳ hoặc khi có thay đổi
        # log(f"DSCP Set: {dscp_value} (Class {label}) for {flow_key}")

    try:
        out_socket.send(bytes(pkt))
    except Exception as e:
        log(f"Send Error: {e}")

# =====================
# RAW SOCKET SETUP
# =====================
out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

def cleanup_expired_flows():
    now = float(time.time())
    expired = [k for k, f in flows.items() if (now - f["last_seen"]) > (FLOW_TIMEOUT_NS / 1e9)]
    for k in expired:
        log(f"Flow expired & removed: {k}")
        del flows[k]

# =====================
# MAIN PROCESSOR
# =====================
def process_packet(pkt):
    try:
        key, flow, pkt_len = update_flow(pkt)
        if key is None:
            return

        # 1. Nếu luồng này đã được phân loại trước đó
        if flow["classified"]:
            rewrite_and_send(pkt, flow["label"], key)
            return

        # 2. Xây dựng vector đặc trưng để bắt đầu phân loại
        features = build_feature_vector(flow, pkt_len)
        
        if features is None:
            # Chưa đủ 12 gói, cứ forward đi nhưng chưa gắn DSCP ưu tiên
            out_socket.send(bytes(pkt))
            return

        # 3. Chuẩn hóa và dự đoán
        features_scaled = scaler.transform(features) if scaler else features
        prediction = classifier.predict(features_scaled)[0]
        
        flow["label"] = int(prediction)
        flow["classified"] = True
        
        log(f"*** CLASSIFIED: Flow {key} is {prediction} ***")

        # 4. Rewrite gói tin hiện tại và gửi đi
        rewrite_and_send(pkt, flow["label"], key)
        
        # Dọn dẹp các luồng cũ để tránh tràn bộ nhớ
        cleanup_expired_flows()

    except Exception as e:
        log(f"Packet Processing Error: {e}")

# =====================
# START SNIFFING
# =====================
log(f"Inference Engine Started: {IN_IFACE} -> {OUT_IFACE} (Biflow Mode)")

sniff(
    iface=IN_IFACE,
    # Chỉ bắt IP traffic và lọc bớt Broadcast/Multicast nếu cần
    filter=f"ip and ether dst {get_if_hwaddr(IN_IFACE)}", 
    prn=process_packet,
    store=False
)
