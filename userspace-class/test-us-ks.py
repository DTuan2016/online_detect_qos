import ctypes
import time
import socket
import struct
import joblib
import pandas as pd
# =========================================================
# LIBBPF
# =========================================================

libbpf = ctypes.CDLL("libbpf.so")

# =========================================================
# CONFIG
# =========================================================

EVENT_MAP = b"/sys/fs/bpf/eth0/events"
FLOW_MAP  = b"/sys/fs/bpf/eth0/xdp_flow_tracking"

FIXED_SHIFT = 16
NUM_PACKET = 12

# =========================================================
# LOAD MODEL
# =========================================================

rf_data = joblib.load(
    "../classification_model/rf_kernel_len_iat.pkl"
)

print(type(rf_data))
print(rf_data.keys())

rf_model = rf_data["model"]

# =========================================================
# STRUCTS
# =========================================================

class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
        ("src_port", ctypes.c_uint16),
        ("dst_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
    ]


class Event(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),

        ("key", FlowKey),

        ("total_pkts", ctypes.c_uint32),

        ("features", ctypes.c_uint64 * 6),
    ]

# =========================================================
# CALLBACK TYPE
# =========================================================

SAMPLE_CB = ctypes.CFUNCTYPE(
    None,
    ctypes.c_void_p,
    ctypes.c_int,
    ctypes.c_void_p,
    ctypes.c_uint32
)

# =========================================================
# OPEN PERF MAP
# =========================================================

libbpf.bpf_obj_get.argtypes = [ctypes.c_char_p]
libbpf.bpf_obj_get.restype = ctypes.c_int

event_fd = libbpf.bpf_obj_get(EVENT_MAP)

if event_fd < 0:
    print("Cannot open perf map")
    exit(1)

print("Perf map fd =", event_fd)

# =========================================================
# CALLBACK
# =========================================================

@SAMPLE_CB
def handle_event(ctx, cpu, data, size):
    FEATURE_NAMES = ["CurrenLength", "SumIat", "MinLen", "MaxLen", "SumLen", "MeanLen" ]
    event = ctypes.cast(
        data,
        ctypes.POINTER(Event)
    ).contents

    t_user = time.monotonic_ns()

    latency_us = (t_user - event.ts) / 1000.0

    features = [
        float(event.features[i]) / (1 << FIXED_SHIFT)
        for i in range(6)
    ]
    X = pd.DataFrame( [features], columns=FEATURE_NAMES )
    #pred = rf_model.predict([features])[0]
    pred = rf_model.predict(X)[0]
    prob = rf_model.predict_proba(X)[0].max()
    #print(
     #   f"pkt={event.total_pkts} "
      #  f"pred={pred} "
       # f"lat={latency_us:.2f} us"
    #)
    print(
	f"pkt={event.total_pkts} "
	f"pred={pred} " 
	f"conf={prob:.3f} " 
	f"lat={latency_us:.2f} us" )

# =========================================================
# PERF BUFFER NEW
# =========================================================

libbpf.perf_buffer__new.restype = ctypes.c_void_p

pb = libbpf.perf_buffer__new(
    event_fd,
    8,
    handle_event,
    None,
    None,
    None
)

if not pb:
    print("perf_buffer__new failed")
    exit(1)

print("Realtime inference started")

# =========================================================
# POLL LOOP
# =========================================================

while True:

    libbpf.perf_buffer__poll(
        pb,
        1
    )
