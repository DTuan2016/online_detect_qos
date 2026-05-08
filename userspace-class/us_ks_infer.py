import time
import ctypes
import joblib
from bcc import libbcc, BPF

# ================= STRUCT DEFINITIONS =================
# FLOW KEY
class FlowKey(ctypes.Structure):
    _fields_ = [
        ("src_ip", ctypes.c_uint32),
	("src_port", ctypes.c_uint16),
        ("dst_ip", ctypes.c_uint32),
        ("dst_port", ctypes.c_uint16),
        ("proto", ctypes.c_uint8),
    ]
# DATA POINT
class DataPoint(ctypes.Structure):
    _fields_ = [
        ("start_ts", ctypes.c_uint64),
        ("last_seen", ctypes.c_uint64),
        ("total_pkts", ctypes.c_uint32),
        ("total_bytes", ctypes.c_uint32),
        ("sum_iat", ctypes.c_uint64),
        ("min_len", ctypes.c_uint32),
        ("max_len", ctypes.c_uint32),
        ("sum_len", ctypes.c_uint64),
        ("mean_len", ctypes.c_uint64),
        ("features", ctypes.c_uint64 * 6), # Mảng 6 phần tử
        ("label", ctypes.c_int32),
        ("classified", ctypes.c_int32),
    ]
# EVENT PUSH
class Event(ctypes.Structure):
    _fields_ = [
        ("ts", ctypes.c_uint64),
        ("key", FlowKey),
        ("total_pkts", ctypes.c_uint32),
        ("features", ctypes.c_uint64 * 6),
    ]
# CONFIG
FIXED_SHIFT = 16
NUM_PACKET = 12

PINNED_MAP_PATH = b"/sys/fs/bpf/eth0/xdp_flow_tracking"

print("Loading RF Model...")
rf_model = joblib.load('../classification_model/rf_kernel_len_iat.pkl')

# ================= BPF MAP CONNECTION =================
print("[*] Opening pinned map...")
map_fd = libbcc.lib.bpf_obj_get(PINNED_MAP_PATH)
if map_fd < 0:
    print(f"Lỗi: Không thể kết nối tới Map {PINNED_MAP_PATH.decode()}")
    print("Vui lòng đảm bảo xdp_loader đã chạy và Map được pin thành công.")
    exit(1)

print(f"Kết nối Map thành công (FD: {map_fd})! Bắt đầu giám sát...")

def ip_to_str(ip):
    return socket.inet_ntoa(struct.pack("I", ip))

def lookup_flow(key):
    dp = DataPoint()

    ret = libbcc.lib.bpf_map_lookup_elem(
	flow_map_fd,
	ctypes.byref(key),
	ctypes.byref(dp)
    )

    if ret != 0:
        return None

    return dp

def update_flow(key, dp):
    libbcc.lib.bpf_map_update_elem(
	flow_map_fd,
	ctypes.byref(key),
	ctypes.byref(dp),
	0
    )

event_counter = 0

def handle_event(cpu, data, size):
    global event_counter

    event = ctypes.cast(
        data,
        ctypes.POINTER(Event)
    ).contents

    event_counter += 1

    # =====================================================
    # LATENCY
    # =====================================================

    t_user = time.time_ns()

    latency_us = (t_user - event.ts) / 1000.0

    # =====================================================
    # FEATURES
    # =====================================================

    features = [
        float(event.features[i]) / (1 << FIXED_SHIFT)
        for i in range(6)
    ]

    # =====================================================
    # RF INFERENCE
    # =====================================================

    pred = rf_model.predict([features])[0]

    prob = max(
        rf_model.predict_proba([features])[0]
    )

    # =====================================================
    # UPDATE FLOW MAP
    # =====================================================

    try:
        dp = flow_map[event.key]

        dp.label = int(pred)

        if event.total_pkts >= NUM_PACKET:
            dp.classified = 1

        flow_map[event.key] = dp

    except KeyError:
        return

    # =====================================================
    # DEBUG
    # =====================================================

    print(
        f"[{event_counter}] "
        f"{ip_to_str(event.key.src_ip)}:{event.key.src_port}"
        f" -> "
        f"{ip_to_str(event.key.dst_ip)}:{event.key.dst_port} "
        f"| pkt={event.total_pkts} "
        f"| pred={pred} "
        f"| conf={prob:.3f} "
        f"| latency={latency_us:.2f} us"
    )

reader = libbcc.PerfBuffer(
    event_map_fd,
    handle_event
)

print("[+] Realtime inference started.")

# =========================================================
# MAIN LOOP
# =========================================================

try:
    while True:
        reader.poll(10)

except KeyboardInterrupt:
    print("\n[!] Stopped.")
