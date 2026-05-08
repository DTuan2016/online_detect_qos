import joblib
import numpy as np
import socket
import time
import os
import pandas as pd
import signal
import sys
import warnings
from scapy.all import sniff, get_if_hwaddr
from scapy.layers.inet import IP, TCP, UDP

warnings.filterwarnings("ignore", category=UserWarning)

# =====================
# CONFIG
# =====================
IN_IFACE  = "eth0"
OUT_IFACE = "veth-host"
MODEL_PATH = "../classification_model/rf_length_iat_n12.pkl"
LABEL_PATH = "../classification_model/label_encoder_n12.pkl"
CSV_OUT = "./result_us_latency.csv"
MIN_PKTS_FOR_CLASSIFY = 12
INTERVAL = 1  # seconds

FEATURE_COLUMNS = [
    'flow_length_min', 'flow_length_max', 'flow_length_sum',
    'flow_length_mean', 'flow_iat_sum'
]

# =====================
# INIT
# =====================
print("[*] Loading RF model...")
classifier = joblib.load(MODEL_PATH)
label_encoder = joblib.load(LABEL_PATH)

if hasattr(classifier, 'n_jobs'):
    classifier.n_jobs = 1

flows = {}

# START CSV WRITE

csv_file = open( CSV_OUT, "w", newline="" )
csv_writer = csv.writer(csv_file)
csv_writer.writerow([ "timestamp_ns", "src_ip", "src_port", "dst_ip", "dst_port", "proto", "pkt_id", "predicted_label", "infer_latency_us", "total_latency_us" ])
csv_file.flush()

def log(msg): 
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")

# metrics window
pkts_cnt = 0
bytes_cnt = 0
flow_cnt = 0
latency_sum_ns = 0

last_time = time.time()

# =====================
# FEATURE
# =====================
def build_feature_vector(flow):
    lens = pd.Series(flow["all_lens"])

    if len(flow["all_times"]) > 1:
        iats = pd.Series(np.diff(flow["all_times"]))
    else:
        iats = pd.Series([0.0])

    return pd.DataFrame([[
        float(lens.min()),
        float(lens.max()),
        float(lens.sum()),
        float(lens.mean()),
        float(iats.sum())
    ]], columns=FEATURE_COLUMNS)

# =====================
# CORE
# =====================
def process_packet(pkt):
    global pkts_cnt, bytes_cnt, flow_cnt, latency_sum_ns, last_time

    if IP not in pkt:
        return

    # ===== START TIME =====
    t0 = time.perf_counter_ns()

    ip = pkt[IP]
    sport = pkt[TCP].sport if TCP in pkt else (pkt[UDP].sport if UDP in pkt else 0)
    dport = pkt[TCP].dport if TCP in pkt else (pkt[UDP].dport if UDP in pkt else 0)
    key = (ip.src, ip.dst, ip.proto, sport, dport)

    pkt_len = ip.len + 14

    if key not in flows:
        flows[key] = {
            "total_pkts": 0,
            "all_lens": [],
            "all_times": []
        }
        flow_cnt += 1

    f = flows[key]

    now = time.time()
    f["total_pkts"] += 1
    f["all_lens"].append(pkt_len)
    f["all_times"].append(now)

    # inference
    features = build_feature_vector(f)
    _ = classifier.predict(features)

    # send
    out_socket.send(bytes(pkt))

    # ===== END TIME =====
    t1 = time.perf_counter_ns()

    latency_ns = t1 - t0

    # update metrics
    pkts_cnt += 1
    bytes_cnt += pkt_len
    latency_sum_ns += latency_ns

    # ===== WINDOW CALC =====
    now_wall = time.time()
    if now_wall - last_time >= INTERVAL:

        duration = now_wall - last_time

        pps = pkts_cnt / duration
        bps = bytes_cnt / duration
        flow_s = flow_cnt / duration

        avg_lat_us = (latency_sum_ns / pkts_cnt) / 1000 if pkts_cnt > 0 else 0

        print(f"PPS: {pps:10.0f} | Bps: {bps:10.0f} | Flow/s: {flow_s:10.0f} | Latency: {avg_lat_us:8.3f} us")

        # reset window
        pkts_cnt = 0
        bytes_cnt = 0
        flow_cnt = 0
        latency_sum_ns = 0
        last_time = now_wall

# =====================
# START
# =====================
def shutdown(sig, frame):
    print("Stopping...")
    out_socket.close()
    sys.exit(0)

signal.signal(signal.SIGINT, shutdown)

out_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
out_socket.bind((OUT_IFACE, 0))

print("Start sniffing...")

sniff(
    iface=IN_IFACE,
    filter=f"ether dst {get_if_hwaddr(IN_IFACE)}",
    prn=process_packet,
    store=False
)
