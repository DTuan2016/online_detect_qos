import joblib
import numpy as np
import socket
import time
import os

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
# LOGGER
# =====================

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


# =====================
# LOAD MODEL
# =====================

pipeline = joblib.load(MODEL_PATH)

# unwrap GridSearchCV
if hasattr(pipeline, "best_estimator_"):
    pipeline = pipeline.best_estimator_

# detect pipeline
scaler = None
classifier = pipeline

if hasattr(pipeline, "named_steps"):
    steps = list(pipeline.named_steps.values())

    if len(steps) > 1:
        scaler = steps[0]
        classifier = steps[-1]
    else:
        classifier = steps[0]

log(f"Classifier: {type(classifier)}")

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


# =====================
# FLOW UPDATE
# =====================

def update_flow(pkt):

    key = get_flow_key(pkt)

    if key is None:
        return None, None, None

    now = time.time_ns()
    #now = pkt.time
    #pkt_len = len(pkt)

    if IP in pkt:
        # ntohs(ip->tot_len) + 14
        pkt_len = pkt[IP].len + 14 
    else:
        # Trường hợp hiếm (không phải IPv4), giữ nguyên len gốc
        pkt_len = len(pkt)
    
    if key not in flows:

        flows[key] = {
            "start_ts": now,
            "last_seen": now,
            "total_pkts": 0,
            "total_bytes": 0,
            "min_iat": None,
            "max_iat": 0.0,
            "sum_iat": 0.0,
            "min_len": pkt_len,
            "max_len": pkt_len,
            "sum_len": 0.0,
            "classified": False,
            "label": None
        }

        log(f"New flow: {key}")

    f = flows[key]

    iat_ns = now - f["last_seen"]
    iat_sec = iat_ns/1000000000.0
    f["last_seen"] = now

    if f["total_pkts"] > 0:

        if f["min_iat"] is None or iat_sec < f["min_iat"]:
            f["min_iat"] = iat_sec

        if iat_sec > f["max_iat"]:
            f["max_iat"] = iat_sec

        f["sum_iat"] += iat_sec

    if pkt_len < f["min_len"]:
        f["min_len"] = pkt_len

    if pkt_len > f["max_len"]:
        f["max_len"] = pkt_len

    f["sum_len"] += pkt_len
    f["total_pkts"] += 1
    f["total_bytes"] += pkt_len

    return key, f, pkt_len


# =====================
# DEBUG TREE PATH
# =====================

def debug_tree_path(model, features):

    if hasattr(model, "estimators_"):
        tree = model.estimators_[0]
    else:
        tree = model

    tree_ = tree.tree_

    feature = tree_.feature
    threshold = tree_.threshold

    node_indicator = tree.decision_path(features)
    leaf_id = tree.apply(features)

    sample_id = 0

    node_index = node_indicator.indices[
        node_indicator.indptr[sample_id]:
        node_indicator.indptr[sample_id + 1]
    ]

    print("\n===== TREE DEBUG =====")

    for node_id in node_index:

        if leaf_id[sample_id] == node_id:
            print(f"-> Leaf node {node_id}")
            continue

        f_idx = feature[node_id]
        thresh = threshold[node_id]
        value = features[0, f_idx]

        if value <= thresh:
            direction = "LEFT"
        else:
            direction = "RIGHT"

        print(
            f"Node {node_id} | feature[{f_idx}]={value:.3f} "
            f"<= {thresh:.3f} → {direction}"
        )

    print("======================\n")


# =====================
# FEATURE BUILDER
# =====================

def build_feature_vector(flow, pkt_len):

    if flow["total_pkts"] < MIN_PKTS_FOR_CLASSIFY:
        return None

    duration = flow["last_seen"] - flow["start_ts"]

    if duration == 0:
        return None

    mean_len = float(flow["sum_len"] / flow["total_pkts"])

    mean_iat = 0

    if flow["total_pkts"] > 1:
        mean_iat = flow["sum_iat"] / (flow["total_pkts"] - 1)
    # current_length,max_length,min_length,sum_length,mean_length,max_iat,min_iat,sum_iat,mean_iat
    features = np.array([
        pkt_len,
        flow["max_len"],
        flow["min_len"],
        flow["sum_len"],
        mean_len,
        flow["max_iat"],
        flow["min_iat"] or 0,
        flow["sum_iat"],
        mean_iat,
    ]).reshape(1, -1)

    log(f"Feature vector: {features.flatten()}")

    return features


# =====================
# DSCP REWRITE
# =====================

def rewrite_dscp(pkt, predicted_class, flow_key):

    if IP not in pkt:
        return pkt

    ip = pkt[IP]

    dscp = DSCP_MAP.get(predicted_class, 0)
    ecn = ip.tos & 0x03

    ip.tos = (dscp << 2) | ecn

    #log(f"Set DSCP={dscp} for class={predicted_class}")
    src_ip, dst_ip, proto, sport, dport = flow_key
    log(f"SET DSCP={dscp} | CLASS={predicted_class} | FLOW: {src_ip}:{sport} -> {dst_ip}:{dport} ({proto})")

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


# =====================
# FLOW CLEANUP
# =====================

def cleanup_flows():

    now = time.time_ns()

    expired = []

    for key, f in flows.items():

        if now - f["last_seen"] > FLOW_TIMEOUT_NS:
            expired.append(key)

    for key in expired:
        log(f"Flow expired: {key}")
        del flows[key]


# =====================
# PACKET PROCESSOR
# =====================

def process_packet(pkt):

    try:

        key, flow, pkt_len = update_flow(pkt)

        if key is None:
            return

        if flow["classified"]:

            pkt = rewrite_dscp(pkt, flow["label"], key)
            out_socket.send(bytes(pkt))
            return

        features = build_feature_vector(flow, pkt_len)

        if features is None:
            return

        # apply scaler if exists
        if scaler is not None:
            features_scaled = scaler.transform(features)
        else:
            features_scaled = features

        log(f"Classifying flow: {key}")

        debug_tree_path(classifier, features_scaled)

        predicted_class = classifier.predict(features_scaled)[0]
#        debug_full_forest(classifier.model, features, "debug_voip_flow.txt")

        log(f"Predicted class: {predicted_class}")

        flow["classified"] = True
        flow["label"] = predicted_class

        pkt = rewrite_dscp(pkt, predicted_class, key)

        out_socket.send(bytes(pkt))

        cleanup_flows()

    except Exception as e:

        log(f"ERROR: {e}")


# =====================
# START
# =====================

log(f"Listening on {IN_IFACE} → Forwarding to {OUT_IFACE}")

sniff(
    iface=IN_IFACE,
    filter=f"ether dst {get_if_hwaddr(IN_IFACE)}",
    prn=process_packet,
    store=False
)
