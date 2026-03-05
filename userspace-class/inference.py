import joblib
import numpy as np
import socket
import time
import os

from scapy.all import *
from scapy.layers.inet import IP, TCP, UDP

# =====================
# CONFIG
# =====================
IN_IFACE  = "eth0"
OUT_IFACE = "veth-host"
MODEL_PATH = os.path.expanduser(
    "~/online_detect_qos/classification_model/vpn_10p.pkl"
)

MIN_PKTS_FOR_CLASSIFY = 10
FLOW_TIMEOUT_NS = 30 * 1e9   # 30s

DSCP_MAP = {
    0: 0,
    1: 8,
    2: 16,
    3: 24,
    4: 32,
    5: 40,
    6: 48,
}

# =====================
# SIMPLE LOGGER
# =====================
def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# =====================
# LOAD MODEL
# =====================
model = joblib.load(MODEL_PATH)
log("Model loaded")

# =====================
# FLOW TABLE
# =====================
flows = {}

def get_flow_key(pkt):
    if IP not in pkt:
        return None

    ip = pkt[IP]
    proto = ip.proto

    sport = 0
    dport = 0

    if TCP in pkt:
        sport = pkt[TCP].sport
        dport = pkt[TCP].dport
    elif UDP in pkt:
        sport = pkt[UDP].sport
        dport = pkt[UDP].dport

    return (ip.src, ip.dst, proto, sport, dport)


def update_flow(pkt):
    key = get_flow_key(pkt)
    if key is None:
        return None, None

    now = time.time_ns()
    pkt_len = len(pkt)

    if key not in flows:
        flows[key] = {
            "start_ts": now,
            "last_seen": now,
            "total_pkts": 0,
            "total_bytes": 0,
            "min_iat": None,
            "max_iat": 0,
            "sum_iat": 0,
            "min_len": pkt_len,
            "max_len": pkt_len,
            "sum_len": 0,
            "classified": False,
            "label": None
        }
        log(f"New flow: {key}")

    f = flows[key]

    iat = now - f["last_seen"]
    f["last_seen"] = now

    if f["total_pkts"] > 0:
        if f["min_iat"] is None or iat < f["min_iat"]:
            f["min_iat"] = iat
        if iat > f["max_iat"]:
            f["max_iat"] = iat
        f["sum_iat"] += iat

    if pkt_len < f["min_len"]:
        f["min_len"] = pkt_len
    if pkt_len > f["max_len"]:
        f["max_len"] = pkt_len

    f["sum_len"] += pkt_len
    f["total_pkts"] += 1
    f["total_bytes"] += pkt_len

    return key, f


def build_feature_vector(f):
    if f["total_pkts"] < MIN_PKTS_FOR_CLASSIFY:
        return None

    duration = f["last_seen"] - f["start_ts"]
    if duration == 0:
        return None

    mean_len = f["sum_len"] / f["total_pkts"]

    mean_iat = 0
    if f["total_pkts"] > 1:
        mean_iat = f["sum_iat"] / (f["total_pkts"] - 1)

    features = np.array([
        MIN_PKTS_FOR_CLASSIFY,
        f["min_iat"] or 0,
        f["max_iat"],
        duration,
        mean_iat,
        f["min_len"],
        f["max_len"],
        f["total_bytes"],
        mean_len
    ]).reshape(1, -1)

    log(f"Feature vector: {features.flatten()}")

    return features


def rewrite_dscp(pkt, predicted_class):

    if IP not in pkt:
        return pkt

    ip = pkt[IP]

    dscp = DSCP_MAP.get(predicted_class, 0)
    ecn = ip.tos & 0x03
    ip.tos = (dscp << 2) | ecn

    log(f"Set DSCP={dscp} for class={predicted_class}")

    del ip.chksum
    if TCP in pkt:
        del pkt[TCP].chksum
    if UDP in pkt:
        del pkt[UDP].chksum

    return pkt

# =====================
# RAW SOCKET
# =====================
out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

def cleanup_flows():
    now = time.time_ns()
    expired = []

    for key, f in flows.items():
        if now - f["last_seen"] > FLOW_TIMEOUT_NS:
            expired.append(key)

    for key in expired:
        log(f"Flow expired: {key}")
        del flows[key]

def process_packet(pkt):

    key, flow = update_flow(pkt)
    if key is None:
        return

    if flow["classified"]:
        pkt = rewrite_dscp(pkt, flow["label"])
        out_socket.send(bytes(pkt))
        return

    features = build_feature_vector(flow)
    if features is None:
        return

    log(f"Classifying flow: {key}")

    predicted_class = model.predict(features)[0]
    log(f"Predicted class: {predicted_class}")

    flow["classified"] = True
    flow["label"] = predicted_class

    pkt = rewrite_dscp(pkt, predicted_class)
    out_socket.send(bytes(pkt))

    cleanup_flows()

# =====================
# START
# =====================
log(f"Listening on {IN_IFACE} → Forwarding to {OUT_IFACE}")
sniff(iface=IN_IFACE, prn=process_packet, store=False)