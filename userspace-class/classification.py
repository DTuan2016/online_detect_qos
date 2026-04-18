import joblib
import numpy as np
import time
import os
import re
import argparse
import csv
import signal
from datetime import datetime, timezone
from pathlib import Path

try:
    from scapy.all import sniff
    from scapy.layers.inet import IP, TCP, UDP
    _SCAPY_IMPORT_ERROR = None
except ModuleNotFoundError as e:
    sniff = None
    IP = TCP = UDP = None
    _SCAPY_IMPORT_ERROR = e

# =====================
# CONFIG
# =====================
IN_IFACE  = "eth0"

MIN_PKTS_FOR_CLASSIFY = 10
FLOW_TIMEOUT_NS = 30 * 1e9

# Fixed-point config (must match common_kern_user.h)
FIXED_SHIFT = 16
FIXED_SCALE = 1 << FIXED_SHIFT

# CSV paths: keep everything next to this script
SCRIPT_DIR = Path(__file__).resolve().parent
LIVE_CSV_NAME = "online_flows.csv"

DSCP_MAP = {
    0: 0,
    1: 8,
    2: 16,
    3: 24,
    4: 32,
    5: 40,
    6: 48,
}

CLASS_MAP = {
    0: "BROWSING",
    1: "CHAT",
    2: "FT",
    3: "P2P",
    4: "STREAMING",
    5: "VOIP",
    6: "MAIL",
}

# =====================
# LOGGER
# =====================

def log(msg):
    print(f"[{time.strftime('%H:%M:%S')}] {msg}")


# =====================
# LOAD MODEL
# =====================

def _repo_root() -> Path:
    # inference.py lives in <repo>/userspace-class/
    return Path(__file__).resolve().parents[1]


def _pick_vpn_model_path(model_dir: Path, min_pkts: int) -> Path:
    preferred = model_dir / f"vpn_{min_pkts}p.pkl"
    if preferred.exists():
        return preferred

    candidates = sorted(model_dir.glob("vpn_*p.pkl"))
    if not candidates:
        raise FileNotFoundError(
            f"No vpn_*.pkl found in {model_dir}. Expected at least {preferred.name}."
        )

    def extract_p(p: Path) -> int | None:
        m = re.match(r"^vpn_(\d+)p\.pkl$", p.name)
        return int(m.group(1)) if m else None

    scored = []
    for c in candidates:
        p = extract_p(c)
        if p is not None:
            scored.append((p, c))

    if scored:
        # Closest to requested min_pkts; if tie pick larger p.
        scored.sort(key=lambda t: (abs(t[0] - min_pkts), -t[0]))
        return scored[0][1]

    # Fallback: just pick lexicographically last file
    return candidates[-1]


def _parse_args():
    parser = argparse.ArgumentParser(
        description="Online QoS inference (VPN classifier) with CSV export."
    )
    parser.add_argument("--in-iface", default=IN_IFACE)
    parser.add_argument(
        "--min-pkts",
        type=int,
        default=MIN_PKTS_FOR_CLASSIFY,
        help="Packets required before classifying a flow.",
    )
    parser.add_argument(
        "--model",
        default=os.environ.get("MODEL_PATH") or os.environ.get("MODEL"),
        help="Path to .pkl model (overrides auto selection).",
    )
    parser.add_argument(
        "--model-dir",
        # Use an absolute path so sudo does not change ~ to /root
        default=str(Path("/home/quocanh24/online_detect_qos/classification_model").resolve()),
        help="Directory containing vpn_*.pkl models (used for auto selection). "
             "Default: /home/quocanh24/online_detect_qos/classification_model",
    )
    parser.add_argument(
        "--no-debug-tree",
        action="store_true",
        help="Disable printing tree path debug for each classification.",
    )
    parser.add_argument(
        "--export-on-exit",
        action="store_true",
        help="Export CSV snapshot automatically when the program exits.",
    )
    return parser.parse_args()


ARGS = _parse_args()

IN_IFACE = ARGS.in_iface
MIN_PKTS_FOR_CLASSIFY = ARGS.min_pkts

if ARGS.model:
    MODEL_PATH = Path(os.path.expanduser(ARGS.model)).resolve()
else:
    MODEL_PATH = _pick_vpn_model_path(Path(ARGS.model_dir), MIN_PKTS_FOR_CLASSIFY).resolve()

log(f"Using model: {MODEL_PATH}")

pipeline = joblib.load(str(MODEL_PATH))

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


def _init_live_csv():
    """
    Clear/create the online_flows.csv file at program start.
    """
    out_dir = _results_csv_dir()
    out_dir.mkdir(parents=True, exist_ok=True)
    live_path = out_dir / LIVE_CSV_NAME
    if live_path.exists():
        try:
            live_path.unlink()
        except OSError:
            pass


# =====================
# CSV EXPORT (on-demand)
# =====================

_csv_header = [
    "ts_iso",
    "ts_ns",
    "model_path",
    "in_iface",
    "src_ip",
    "dst_ip",
    "proto",
    "sport",
    "dport",
    "total_pkts",
    "total_bytes",
    "current_len",
    "max_len",
    "min_len",
    "sum_len_bytes",
    "mean_len",
    "max_iat_s",
    "min_iat_s",
    "duration_ns",
    "mean_iat_s",
    "predicted_class",
    "dscp",
    "predicted_class_name",
]

def _results_csv_dir() -> Path:
    """
    Directory where CSV files (live and final) are stored.
    We keep them in the same folder as this script.
    """
    return SCRIPT_DIR

def export_csv_snapshot(reason: str = "manual") -> Path:
    """
    Export current classified flows to a new timestamped CSV file under results/csv/.
    Triggered manually via SIGUSR1 or automatically on exit (optional).
    """
    out_dir = _results_csv_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    ts_tag = datetime.now().strftime("%Y%m%d_%H%M%S")
    if reason == "exit":
        # Final CSV when the program stops
        out_path = out_dir / f"final_{ts_tag}.csv"
    else:
        # Manual/snapshot exports while running
        out_path = out_dir / f"detect_{ts_tag}_{reason}.csv"

    ts_ns = time.time_ns()
    ts_iso = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()

    rows_written = 0
    with open(out_path, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_csv_header)
        writer.writeheader()

        for flow_key, flow in flows.items():
            if not flow.get("classified"):
                continue
            if flow.get("features") is None:
                continue

            src_ip, dst_ip, proto, sport, dport = flow_key
            flat = list(flow["features"])
            (
                min_iat_fixed,
                max_iat_fixed,
                sum_iat_fixed,
                mean_iat_fixed,
                min_len_fixed,
                max_len_fixed,
                sum_len_fixed,
                mean_len_fixed,
                current_len_fixed,
            ) = flat

            # Convert back from fixed-point for human-readable CSV
            min_iat_s = min_iat_fixed / FIXED_SCALE
            max_iat_s = max_iat_fixed / FIXED_SCALE
            sum_iat_s = sum_iat_fixed / FIXED_SCALE
            mean_iat_s = mean_iat_fixed / FIXED_SCALE

            min_len = min_len_fixed / FIXED_SCALE
            max_len = max_len_fixed / FIXED_SCALE
            sum_len_bytes = sum_len_fixed / FIXED_SCALE
            mean_len = mean_len_fixed / FIXED_SCALE
            current_len = current_len_fixed / FIXED_SCALE

            predicted_class = flow.get("label")
            dscp = (
                DSCP_MAP.get(int(predicted_class), 0)
                if predicted_class is not None
                else 0
            )
            class_name = (
                CLASS_MAP.get(int(predicted_class), "")
                if predicted_class is not None
                else ""
            )

            writer.writerow(
                {
                    "ts_iso": ts_iso,
                    "ts_ns": ts_ns,
                    "model_path": str(MODEL_PATH),
                    "in_iface": IN_IFACE,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "proto": proto,
                    "sport": sport,
                    "dport": dport,
                    "total_pkts": flow["total_pkts"],
                    "total_bytes": flow["total_bytes"],
                    "current_len": current_len,
                    "max_len": max_len,
                    "min_len": min_len,
                    "sum_len_bytes": sum_len_bytes,
                    "mean_len": mean_len,
                    "max_iat_s": max_iat_s,
                    "min_iat_s": min_iat_s,
                    "duration_ns": flow["last_seen"] - flow["start_ts"],
                    "mean_iat_s": mean_iat_s,
                    "predicted_class": int(predicted_class)
                    if predicted_class is not None
                    else "",
                    "dscp": dscp,
                    "predicted_class_name": class_name,
                }
            )
            rows_written += 1

    log(f"Exported {rows_written} flows to CSV: {out_path}")
    return out_path


def _append_flow_to_live_csv(flow_key, flow):
    """
    Append a single classified flow to a persistent CSV file that is updated
    online while the program runs.
    """
    out_dir = _results_csv_dir()
    out_dir.mkdir(parents=True, exist_ok=True)

    csv_path = out_dir / LIVE_CSV_NAME
    is_new = not csv_path.exists()

    ts_ns = time.time_ns()
    ts_iso = datetime.fromtimestamp(ts_ns / 1e9, tz=timezone.utc).isoformat()

    src_ip, dst_ip, proto, sport, dport = flow_key
    flat = list(flow["features"])
    (
        min_iat_fixed,
        max_iat_fixed,
        sum_iat_fixed,
        mean_iat_fixed,
        min_len_fixed,
        max_len_fixed,
        sum_len_fixed,
        mean_len_fixed,
        current_len_fixed,
    ) = flat

    # Convert back from fixed-point for human-readable CSV
    min_iat_s = min_iat_fixed / FIXED_SCALE
    max_iat_s = max_iat_fixed / FIXED_SCALE
    sum_iat_s = sum_iat_fixed / FIXED_SCALE
    mean_iat_s = mean_iat_fixed / FIXED_SCALE

    min_len = min_len_fixed / FIXED_SCALE
    max_len = max_len_fixed / FIXED_SCALE
    sum_len_bytes = sum_len_fixed / FIXED_SCALE
    mean_len = mean_len_fixed / FIXED_SCALE
    current_len = current_len_fixed / FIXED_SCALE

    predicted_class = flow.get("label")
    dscp = (
        DSCP_MAP.get(int(predicted_class), 0)
        if predicted_class is not None
        else 0
    )
    class_name = (
        CLASS_MAP.get(int(predicted_class), "") if predicted_class is not None else ""
    )

    with open(csv_path, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=_csv_header)
        if is_new:
            writer.writeheader()

        writer.writerow(
            {
                "ts_iso": ts_iso,
                "ts_ns": ts_ns,
                "model_path": str(MODEL_PATH),
                "in_iface": IN_IFACE,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "proto": proto,
                "sport": sport,
                "dport": dport,
                "total_pkts": flow["total_pkts"],
                "total_bytes": flow["total_bytes"],
                "current_len": current_len,
                "max_len": max_len,
                "min_len": min_len,
                "sum_len_bytes": sum_len_bytes,
                "mean_len": mean_len,
                "max_iat_s": max_iat_s,
                "min_iat_s": min_iat_s,
                "duration_ns": flow["last_seen"] - flow["start_ts"],
                "mean_iat_s": mean_iat_s,
                "predicted_class": int(predicted_class)
                if predicted_class is not None
                else "",
                "dscp": dscp,
                "predicted_class_name": class_name,
            }
        )

    log(f"Appended flow {flow_key} to live CSV: {csv_path}")

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
            "label": None,
            "features": None,
        }

        log(f"New flow: {key}")

    f = flows[key]

    iat = now - f["last_seen"]
    f["last_seen"] = now

    if f["total_pkts"] > 0:

        if f["min_iat"] is None or iat < f["min_iat"]:
            f["min_iat"] = iat / 1000000000

        if iat > f["max_iat"]:
            f["max_iat"] = iat / 1000000000

        f["sum_iat"] += iat / 1000000000

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

    # float-domain features (seconds, bytes)
    mean_len = flow["sum_len"] / flow["total_pkts"]

    mean_iat = 0.0
    if flow["total_pkts"] > 1:
        mean_iat = flow["sum_iat"] / (flow["total_pkts"] - 1)

    min_iat = flow["min_iat"] or 0.0
    max_iat = flow["max_iat"]
    sum_iat = flow["sum_iat"]

    min_len = flow["min_len"]
    max_len = flow["max_len"]
    sum_len = flow["sum_len"]
    cur_len = pkt_len

    def to_fixed(x: float) -> int:
        return int(round(x * FIXED_SCALE))

    # Order must match kernel / training:
    # min_iat, max_iat, sum_iat, mean_iat,
    # min_length, max_length, sum_length, mean_length, current_length
    features_fixed = np.array(
        [
            to_fixed(min_iat),
            to_fixed(max_iat),
            to_fixed(sum_iat),
            to_fixed(mean_iat),
            to_fixed(min_len),
            to_fixed(max_len),
            to_fixed(sum_len),
            to_fixed(mean_len),
            to_fixed(cur_len),
        ],
        dtype=np.int64,
    ).reshape(1, -1)

    log(f"Feature vector (fixed-point): {features_fixed.flatten()}")

    return features_fixed


# =====================
# DSCP REWRITE
# =====================

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

        if not ARGS.no_debug_tree:
            debug_tree_path(classifier, features_scaled)

        predicted_class = classifier.predict(features_scaled)[0]

        log(f"Predicted class: {predicted_class}")

        flow["classified"] = True
        flow["label"] = predicted_class
        flow["features"] = features.reshape(-1).tolist()

        # Append this classified flow to a live CSV that is continuously updated.
        _append_flow_to_live_csv(key, flow)

        cleanup_flows()

    except Exception as e:

        log(f"ERROR: {e}")


# =====================
# START
# =====================

# Ensure live CSV is cleared/created at the beginning of each run.
_init_live_csv()

log(f"PID: {os.getpid()}")
log(f"Listening on {IN_IFACE} (detect only). Send SIGUSR1 to export CSV snapshot.")
log(f"CSV folder: {_results_csv_dir()}")

def _handle_sigusr1(signum, frame):
    try:
        export_csv_snapshot("manual")
    except Exception as e:
        log(f"ERROR exporting CSV: {e}")


def _handle_exit(signum, frame):
    try:
        if ARGS.export_on_exit:
            export_csv_snapshot("exit")
    finally:
        raise SystemExit(0)


signal.signal(signal.SIGUSR1, _handle_sigusr1)
signal.signal(signal.SIGINT, _handle_exit)
signal.signal(signal.SIGTERM, _handle_exit)

if sniff is None:
    raise SystemExit(
        "scapy is required to sniff packets. Install it (e.g. `pip install scapy`) "
        f"and retry. Original error: {_SCAPY_IMPORT_ERROR}"
    )

sniff(
    iface=IN_IFACE,
    prn=process_packet,
    store=False
)