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

# =====================================================
# WARNING
# =====================================================
warnings.filterwarnings(
    "ignore",
    category=UserWarning
)
# =====================================================
# CONFIG
# =====================================================
IN_IFACE  = "eth0"
OUT_IFACE = "veth-host"
MODEL_PATH = "../classification_model/rf_length_iat_n12.pkl"
LABEL_PATH = "../classification_model/label_encoder_n12.pkl"
CSV_OUT = "./result_userspace_latency.csv"

MIN_PKTS_FOR_CLASSIFY = 12

# =====================================================
# DSCP MAP
# =====================================================

DSCP_MAP = {
    0: 0,
    1: 8,
    2: 16,
    3: 24,
    4: 32,
    5: 40,
    6: 48
}

# =====================================================
# FEATURE COLUMNS
# =====================================================
FEATURE_COLUMNS = [
    'flow_length_min',
    'flow_length_max',
    'flow_length_sum',
    'flow_length_mean',
    'flow_iat_sum'
]
# =====================================================
# LOAD MODEL
# =====================================================
print("[*] Loading RF model...")
classifier = joblib.load(MODEL_PATH)
label_encoder = joblib.load(LABEL_PATH)
if hasattr(classifier, 'n_jobs'):
    classifier.n_jobs = 1
print("[+] RF model loaded.")
# =====================================================
# GLOBAL FLOWS
# =====================================================
flows = {}
# =====================================================
# CSV INIT
# =====================================================
csv_file = open(
    CSV_OUT,
    "w",
    newline=""
)
csv_writer = csv.writer(csv_file)
csv_writer.writerow([
    "timestamp_ns",
    "src_ip",
    "src_port",
    "dst_ip",
    "dst_port",
    "proto",
    "pkt_id",
    "predicted_label",
    "infer_latency_us",
    "total_latency_us"
])

csv_file.flush()

# =====================================================
# HELPERS
# =====================================================
def log(msg):
    print(
        f"[{time.strftime('%H:%M:%S')}] {msg}"
    )
# =====================================================
# FEATURE EXTRACTION
# =====================================================

def build_feature_vector(flow):
    lens = pd.Series(
        flow["all_lens"]
    )
    if len(flow["all_times"]) > 1:
        iats = pd.Series(np.diff(flow["all_times"]))
    else:
        iats = pd.Series([0.0])
    feature_map = {
        'flow_length_min':
            float(lens.min()),
        'flow_length_max':
            float(lens.max()),
        'flow_length_sum':
            float(lens.sum()),
        'flow_length_mean':
            float(lens.mean()),
        'flow_iat_sum':
            float(iats.sum())
    }
    return pd.DataFrame(
        [[feature_map[f] for f in FEATURE_COLUMNS]],
        columns=FEATURE_COLUMNS
    )
# =====================================================
# PROCESS PACKET
# =====================================================
def process_packet(pkt):
    try:
        if IP not in pkt:
            return
        # =============================================
        # START LATENCY
        # =============================================
        total_t0 = time.monotonic_ns()
        # =============================================
        # FLOW KEY
        # =============================================
        ip = pkt[IP]
        sport = (
            pkt[TCP].sport if TCP in pkt
            else pkt[UDP].sport if UDP in pkt
            else 0
        )
        dport = (
            pkt[TCP].dport if TCP in pkt
            else pkt[UDP].dport if UDP in pkt
            else 0
        )
        key = (
            ip.src,
            ip.dst,
            ip.proto,
            sport,
            dport
        )
        pkt_len = ip.len + 14
        # =============================================
        # CREATE FLOW
        # =============================================
        if key not in flows:
            flows[key] = {
                "total_pkts": 0,
                "all_lens": [],
                "all_times": [],
                "classified_final": False,
                "last_pred": 0
            }
        flow = flows[key]
        # =============================================
        # UPDATE FLOW
        # =============================================
        flow["total_pkts"] += 1
        flow["all_lens"].append(pkt_len)
        pred = flow["last_pred"]
        infer_latency_us = 0.0
        # =============================================
        # EARLY FLOW INFERENCE
        # =============================================
        if not flow["classified_final"]:
            features = build_feature_vector(flow)
            infer_t0 = time.monotonic_ns()
            pred = int(
                classifier.predict(features)[0]
            )
            infer_t1 = time.monotonic_ns()
            infer_latency_us = (
                infer_t1 - infer_t0
            ) / 1000.0
            flow["last_pred"] = pred
            label_name = (
                label_encoder.inverse_transform(
                    [pred]
                )[0]
            )
            # =========================================
            # FINAL DECISION
            # =========================================
            if flow["total_pkts"] >= MIN_PKTS_FOR_CLASSIFY:
                flow["classified_final"] = True
                log(
                    f"[STABLE] "
                    f"{ip.src}:{sport}"
                    f" -> "
                    f"{ip.dst}:{dport} "
                    f"=> {label_name}"
                )
        else:
            label_name = (
                label_encoder.inverse_transform(
                    [pred]
                )[0]
            )
        # =============================================
        # DSCP REWRITE
        # =============================================
        dscp = DSCP_MAP.get(pred, 0)
        ip.tos = (
            (dscp << 2)
            | (ip.tos & 0x03)
        )
        # =============================================
        # RECALC CHECKSUM
        # =============================================
        del ip.chksum
        if TCP in pkt:
            del pkt[TCP].chksum
        if UDP in pkt:
            del pkt[UDP].chksum
        # =============================================
        # FORWARD
        # =============================================
        out_socket.send(
            bytes(pkt)
        )
        # =============================================
        # TOTAL LATENCY
        # =============================================
        total_t1 = time.monotonic_ns()
        total_latency_us = (
            total_t1 - total_t0
        ) / 1000.0
        # =============================================
        # PRINT
        # =============================================
        print(
            f"{ip.src}:{sport}"
            f" -> "
            f"{ip.dst}:{dport} "
            f"| pkt={flow['total_pkts']} "
            f"| label={label_name} "
            f"| infer={infer_latency_us:.2f} us "
            f"| total={total_latency_us:.2f} us"
        )
        # =============================================
        # CSV LOG
        # =============================================
        csv_writer.writerow([
            total_t1,
            ip.src,
            sport,
            ip.dst,
            dport,
            ip.proto,
            flow["total_pkts"],
            label_name,
            infer_latency_us,
            total_latency_us
        ])
        csv_file.flush()

    except Exception as e:
        print("ERR:", e)

# =====================================================
# SIGNAL HANDLER
# =====================================================

def shutdown(sig, frame):
    log("Stopping...")
    csv_file.close()
    out_socket.close()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

# =====================================================
# RAW SOCKET
# =====================================================

out_socket = socket.socket(
    socket.AF_PACKET,
    socket.SOCK_RAW
)

out_socket.bind(
    (OUT_IFACE, 0)
)

# =====================================================
# START
# =====================================================

log(
    f"Userspace classifier started: "
    f"{IN_IFACE} -> {OUT_IFACE}"
)
try:
    sniff(
        iface=IN_IFACE,
        filter=f"ether dst {get_if_hwaddr(IN_IFACE)}",
        prn=process_packet,
        store=False
    )
finally:
    csv_file.close()
    out_socket.close()
