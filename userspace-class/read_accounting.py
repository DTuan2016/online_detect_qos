import ctypes as ct
import time
import os
import csv

LIBBPF = ct.CDLL("libbpf.so")

class Accounting(ct.Structure):
    _fields_ = [
        ("time_in", ct.c_uint64),
        ("proc_time", ct.c_uint64),
        ("total_pkts", ct.c_uint64),
        ("total_bytes", ct.c_uint64),
        ("flow_created", ct.c_uint64),
    ]

bpf_obj_get = LIBBPF.bpf_obj_get
bpf_obj_get.argtypes = [ct.c_char_p]
bpf_obj_get.restype = ct.c_int

bpf_map_lookup_elem = LIBBPF.bpf_map_lookup_elem
bpf_map_lookup_elem.argtypes = [ct.c_int, ct.c_void_p, ct.c_void_p]
bpf_map_lookup_elem.restype = ct.c_int

# --- Config ---
ifname = "eth0"
map_path = f"/sys/fs/bpf/{ifname}/accounting_map".encode()

fd = bpf_obj_get(map_path)
if fd < 0:
    print(f"Lỗi: Không thể mở map tại {map_path.decode()}")
    exit(1)

key = ct.c_uint32(0)
prev = Accounting()
curr = Accounting()

bpf_map_lookup_elem(fd, ct.byref(key), ct.byref(prev))

# --- CSV setup ---
csv_file = open("stats.csv", "w", newline="")
csv_writer = csv.writer(csv_file)

# header
csv_writer.writerow([
    "timestamp",
    "pps",
    "mbps",
    "flow_s",
    "avg_latency_us"
])

print(f"{'PPS':>10} | {'Mbps':>10} | {'Flow/s':>10} | {'Avg Latency':>15}")
print("-" * 55)

try:
    while True:
        time.sleep(1)

        if bpf_map_lookup_elem(fd, ct.byref(key), ct.byref(curr)) != 0:
            continue

        d_pkts = curr.total_pkts - prev.total_pkts
        d_bytes = curr.total_bytes - prev.total_bytes
        d_flows = curr.flow_created - prev.flow_created
        d_time_ns = curr.proc_time - prev.proc_time

        pps = d_pkts
        mbps = (d_bytes * 8) / 1_000_000.0
        flow_s = d_flows

        if d_pkts > 0:
            avg_lat_us = (d_time_ns / d_pkts) / 1000.0
        else:
            avg_lat_us = 0.0

        # in ra màn hình
        print(f"{pps:10d} | {mbps:10.2f} | {flow_s:10d} | {avg_lat_us:12.3f} us")

        # ghi CSV
        csv_writer.writerow([
            time.time(),   # timestamp unix
            pps,
            mbps,
            flow_s,
            avg_lat_us
        ])

        csv_file.flush()  # đảm bảo không mất dữ liệu nếu Ctrl+C

        ct.memmove(ct.byref(prev), ct.byref(curr), ct.sizeof(Accounting))

except KeyboardInterrupt:
    print("\nĐã dừng giám sát.")
    csv_file.close()