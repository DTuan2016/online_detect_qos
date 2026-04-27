import os
import argparse
import joblib
import numpy as np
import pandas as pd
from math import log2
from bcc import BPF
import ctypes
import subprocess
import sys
from bcc import libbcc

class Node(ctypes.Structure):
    _fields_ = [
        ("left_idx", ctypes.c_int),
        ("right_idx", ctypes.c_int),
        ("split_value", ctypes.c_int),  # fixed thường là int
        ("feature_idx", ctypes.c_int),
        ("is_leaf", ctypes.c_uint32),
        ("label", ctypes.c_int),
        ("tree_idx", ctypes.c_int),
    ]

def load_nodes_to_map(df: pd.DataFrame, MAP_PATH: str):
    map_fd = libbcc.lib.bpf_obj_get(MAP_PATH.encode())
    if map_fd < 0:
        raise OSError(f"Failed to open pinned map at {MAP_PATH}")

    print(f"[LOAD] Opened pinned map: {MAP_PATH}")
    print(f"[LOAD] Total nodes: {len(df)}")

    # Khong can reset_index(drop=True) nua vi ta dung map_key truc tiep
    
    for _, row in df.iterrows():
        # FIX: Su dung map_key da duoc can chinh de lam key cho BPF Map
        key = int(row["map_key"]).to_bytes(4, "little", signed=False)

        val = (
            int(row["left_idx"]).to_bytes(4, "little", signed=True) +
            int(row["right_idx"]).to_bytes(4, "little", signed=True) +
            int(row["split_value"]).to_bytes(8, "little", signed=False) +
            int(row["feature_idx"]).to_bytes(4, "little", signed=True) +
            int(row["is_leaf"]).to_bytes(4, "little", signed=False) +
            int(row["label"]).to_bytes(4, "little", signed=True) +
            int(row["tree_idx"]).to_bytes(4, "little", signed=True)
        )

        ret = libbcc.lib.bpf_update_elem(map_fd, key, val, 0)
        if ret != 0:
            print(f"[LOAD] Failed at index {row['map_key']}")

    print("[LOAD] All nodes inserted successfully.")


SCALE_BITS = 16
SCALE = 1 << SCALE_BITS

def unwrap_model(model):
    """
    Tự động unwrap nếu model là:
    - GridSearchCV
    - Pipeline
    """
    from sklearn.model_selection import GridSearchCV
    from sklearn.pipeline import Pipeline

    # Nếu là GridSearchCV
    if isinstance(model, GridSearchCV):
        print("[INFO] Detected GridSearchCV → using best_estimator_")
        model = model.best_estimator_

    # Nếu là Pipeline
    if isinstance(model, Pipeline):
        print("[INFO] Detected Pipeline → extracting last step")
        model = model.steps[-1][1]

    return model

# ============================================================
# FIXED POINT
# ============================================================

def float_to_fixed_u64(value: float, scale_bits: int = SCALE_BITS) -> int:
    scaled = int(value * (1 << scale_bits))
    return max(scaled, 0)

# ============================================================
# READ MODEL + EXTRACT META
# ============================================================

def extract_model_info(model):
    if not hasattr(model, "estimators_"):
        raise ValueError("Model chưa fit hoặc không phải RandomForestClassifier.")

    max_tree = len(model.estimators_)
    max_nodes_per_tree = 0
    max_depth = 0

    for est in model.estimators_:
        tree = est.tree_
        max_nodes_per_tree = max(max_nodes_per_tree, tree.node_count)
        max_depth = max(max_depth, tree.max_depth)

    return max_tree, max_nodes_per_tree, max_depth


# ============================================================
# MODEL → DATAFRAME
# ============================================================

def dump_random_forest(model_path: str):
    if not os.path.exists(model_path):
        raise FileNotFoundError(model_path)

    data = joblib.load(model_path)
    
    if isinstance(data, dict) and "model" in data:
        print("[INFO] Detected dict format → extracting model")
        model = data["model"]
    else:
        model = data

    model = unwrap_model(model)

    if not hasattr(model, "estimators_"):
        raise ValueError("Model không phải RandomForestClassifier đã fit.")

    max_tree, max_nodes_per_tree, max_depth = extract_model_info(model)

    rows = []
    classes = list(model.classes_)
    label_map = {c: i for i, c in enumerate(classes)}

    # FIX: Loai bo viec khoi tao global_offset = 0 o day

    for tree_idx, estimator in enumerate(model.estimators_):
        tree = estimator.tree_
        node_count = tree.node_count

        # FIX: Tinh offset co dinh cho moi cay, dam bao khop 100% voi C code
        global_offset = tree_idx * max_nodes_per_tree

        for node_idx in range(node_count):
            left = tree.children_left[node_idx]
            right = tree.children_right[node_idx]
            is_leaf = int(left == -1 and right == -1)

            # Convert local index → global map index
            if left != -1:
                left += global_offset
            if right != -1:
                right += global_offset

            label = -1
            if is_leaf:
                value = tree.value[node_idx].flatten()
                if value.sum() > 0:
                    label_name = classes[int(np.argmax(value))]
                    label = label_map[label_name]

            rows.append({
                "map_key": global_offset + node_idx, # FIX: Them key ro rang de dua vao bpf map
                "tree_idx": tree_idx,
                "feature_idx": int(tree.feature[node_idx]),
                "split_value": float_to_fixed_u64(
                    float(tree.threshold[node_idx])
                ),
                "left_idx": int(left),
                "right_idx": int(right),
                "is_leaf": is_leaf,
                "label": label,
            })

        # FIX: Loai bo global_offset += node_count o day de tranh cac cay bi ep sat vao nhau

    df = pd.DataFrame(rows)

    return df, max_tree, max_nodes_per_tree, max_depth


# ============================================================
# HEADER GENERATOR
# ============================================================

def generate_common_header(
    output_path: str,
    max_tree: int,
    max_nodes: int,
    max_depth: int,
    max_features: int,
    num_packets: int,
    redirect_if : int,
):

    header = f"""#ifndef COMMON_KERNEL_USER_H
#define COMMON_KERNEL_USER_H

#include <linux/types.h>

/* Fixed-point configuration */
#define FIXED_SHIFT         {SCALE_BITS}
#define FIXED_SCALE         {SCALE}
#define MAX_TREES           {max_tree}
#define MAX_NODE_PER_TREE   {max_nodes}
#define MAX_FEATURES        {max_features}
#define MAX_DEPTH           {max_depth}
#define TOTAL_NODES         {max_tree * max_nodes}
#define NUM_PACKET          {num_packets}
#define REDIRECT_INTERFACE  {redirect_if}
#define MAX_FLOW_SAVED      1000000
#define NUM_LABELS          7
#define NS_TO_SEC_FIXED(x) ((__u32)(((x) << 16) / 1000000000ULL))

//current_length,max_length,min_length,sum_length,mean_length,max_iat,min_iat,sum_iat,mean_iat

#define FEATURE_CUR_LEN     0
#define FEATURE_SUM_IAT     1
#define FEATURE_MIN_LEN     2
#define FEATURE_MAX_LEN     3
#define FEATURE_SUM_LEN     4
#define FEATURE_MEAN_LEN    5

typedef __u64               fixed;

/* Latency statistics structure */
typedef struct {{
    __u64 time_in;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u64 total_pkts;
    __u64 total_bytes;
}} accounting;

/* Flow key structure */
struct flow_key {{
    __u32   src_ip;
    __u16   src_port;
    __u32   dst_ip;
    __u16   dst_port;
    __u8    proto;
}} __attribute__((packed));

/* Definition of a datapoint or a flow (accounting) */
typedef struct {{
    __u64   start_ts;             /* Timestamp of first packet */
    __u64   last_seen;            /* Timestamp of last packet */
    __u32   total_pkts;           /* Total packet count */
    __u32   total_bytes;          /* Total byte count */
    __u64   sum_iat;
    /*PACKET LENGTH FEATURES*/
    __u32   min_len;          /* Maximum packet length */
    __u32   max_len;          /* Minimum packet length */
    __u64   sum_len;
    fixed   mean_len;
    fixed   features[MAX_FEATURES];
    int     votes[NUM_LABELS];
    int     classified;
    int     label;
}} __attribute__((packed)) data_point;

// /* Definition of feature vector to calculate RF */
// struct feat_vec {{
//     fixed features[MAX_FEATURES];
// }};

/* Definition of a Node of Decision Tree */
typedef struct {{
    int     left_idx;
    int     right_idx;
    fixed   split_value;
    int     feature_idx;
    __u32   is_leaf;
    int     label;
    int     tree_idx;
}} Node;

/* Convert float (as double in user space) to fixed-point */
static __always_inline fixed fixed_from_float(double value)
{{
    return (__u64)(value * (double)FIXED_SCALE);
}}

/* Convert fixed-point to float */
static __always_inline double fixed_to_float(fixed value)
{{
    return (double)value / (double)FIXED_SCALE;
}}

static __always_inline fixed fixed_from_uint(__u64 value)
{{
    return value << FIXED_SHIFT;
}}

static __always_inline __u64 fixed_to_uint(fixed value)
{{
    return value >> FIXED_SHIFT;
}}

static __always_inline fixed fixed_add(fixed a, fixed b)
{{
    return a + b;
}}

static __always_inline fixed fixed_sub(fixed a, fixed b)
{{
    return (a > b) ? (a - b) : 0;
}}

static __always_inline fixed fixed_mul(fixed a, fixed b)
{{
    /* Use 128-bit intermediate to prevent overflow */
    __u64 a_int = a >> FIXED_SHIFT;
    __u64 a_frac = a & ((1ULL << FIXED_SHIFT) - 1);
    __u64 b_int = b >> FIXED_SHIFT;
    __u64 b_frac = b & ((1ULL << FIXED_SHIFT) - 1);
    
    __u64 result_int = a_int * b_int;
    __u64 result_frac = (a_int * b_frac + a_frac * b_int) >> FIXED_SHIFT;
    __u64 result_frac_frac = (a_frac * b_frac) >> (FIXED_SHIFT * 2);
    
    return (result_int << FIXED_SHIFT) + result_frac + result_frac_frac;
}}

static __always_inline fixed fixed_div(fixed a, fixed b)
{{
    if (b == 0)
        return 0;
    
    /* Shift dividend left to maintain precision */
    __u64 shifted_a = a << FIXED_SHIFT;
    return shifted_a / b;
}}

static __always_inline fixed fixed_sqrt(fixed value)
{{
    if (value == 0)
        return 0;

    fixed x = value;
    fixed two = fixed_from_uint(2);
    
    // #pragma unroll
    for (int i = 0; i < 10; i++) {{
        fixed x_squared = fixed_div(value, x);
        x = fixed_div(fixed_add(x, x_squared), two);
    }}
    
    return x;
}}

static __always_inline fixed fixed_abs(fixed value)
{{
    /* For unsigned __u64, this is just the value itself */
    return value;
}}

static __always_inline int fixed_compare(fixed a, fixed b)
{{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}}


static __always_inline fixed fixed_log2(__u64 x)
{{
    if (x == 0)
        return 0;

    __u64 int_part = 0;
    __u64 tmp = x;
    
    while (tmp >>= 1)
        int_part++;

    __u64 base = 1ULL << int_part;
    __u64 remainder = x - base;

    __u64 frac = (remainder << FIXED_SHIFT) / base;
    
    return (int_part << FIXED_SHIFT) | frac;
}}

static __always_inline fixed fixed_ln(__u64 x)
{{
    if (x == 0)
        return 0;
    
    fixed log2_val = fixed_log2(x);
    fixed ln2 = 177;
    
    return fixed_mul(log2_val, ln2);
}}

static __always_inline fixed fixed_exp(fixed x)
{{
    fixed result = FIXED_SCALE; 
    fixed term = FIXED_SCALE;  
    
    // #pragma unroll
    for (int i = 1; i <= 6; i++) {{
        term = fixed_mul(term, x);
        term = fixed_div(term, fixed_from_uint(i));
        result = fixed_add(result, term);
    }}
    
    return result;
}}

static __always_inline fixed fixed_pow(fixed base, __u32 exp)
{{
    fixed result = FIXED_SCALE;
    
    // #pragma unroll
    for (__u32 i = 0; i < exp && i < 16; i++) {{
        result = fixed_mul(result, base);
    }}
    
    return result;
}}

#endif /*COMMON_KERN_USER_H*/
"""

    with open(output_path, "w") as f:
        f.write(header)

    print("[HEADER] Generated:", output_path)
    print("[HEADER] Trees:", max_tree)
    print("[HEADER] Max nodes/tree:", max_nodes)
    print("[HEADER] Max depth:", max_depth)


# ============================================================
# MAIN
# ============================================================
def run(cmd, cwd=None):
    print(f"\n[RUN] {cmd}")
    result = subprocess.run(
        cmd,
        shell=True,
        cwd=os.path.expanduser(cwd) if cwd else None
    )
    if result.returncode != 0:
        print(f"Lỗi khi chạy: {cmd}")
        sys.exit(1)

def main():

    parser = argparse.ArgumentParser(
        description="Auto-extract RandomForest info from model"
    )
    parser.add_argument("--model", required=True, help="Path to model.pkl")
    parser.add_argument("--iface", required=True, help="Interface to attach prog")
    parser.add_argument("--rd_if", required=False, default=7, help="Interface to attach prog")
    parser.add_argument("--nb_packet", required=True, help="Add your number of packets")
    parser.add_argument(
        "--output_header",
        default="../include/common_kern_user.h",
        help="Output header path",
    )

    args = parser.parse_args()
    NUM_PACKET = args.nb_packet
    IFACE = args.iface
    redirect_if = args.rd_if
    df, max_tree, max_nodes_per_tree, max_depth = dump_random_forest(
        args.model
    )

    data = joblib.load(args.model)

    if isinstance(data, dict) and "model" in data:
        print("[INFO] Extracting model from dict...")
        model = data["model"]
        feature_names = data.get("features", [])
    else:
        model = data
        feature_names = []

    max_features = model.n_features_in_
    classes = list(model.classes_)
    
    print("\n[LABEL INFO]")
    print("Number of labels:", len(classes))
    
    print("\n[FEATURE INFO]")
    print("Number of features:", max_features)

    if feature_names:
        print("Feature order:")
        for i, f in enumerate(feature_names):
            print(f"{i}: {f}")

    for i, c in enumerate(classes):
        print(f"Label {i}: {c}")

    generate_common_header(
        args.output_header,
        max_tree,
        max_nodes_per_tree,
        max_depth,
        max_features,
        NUM_PACKET,
        redirect_if,
    )

    print("\n[MODEL INFO]")
    print("Trees:", max_tree)
    print("Max nodes per tree:", max_nodes_per_tree)
    print("Max depth:", max_depth)
    print("Features:", max_features)
    print("Total nodes:", len(df))
    # Load BPF program
    BUILD_DIR = "~/online_detect_qos/build"
    XDP_LOADER_PATH = os.path.expanduser("~/online_detect_qos/build/xdp_loader")

    # build
    run("make", cwd=BUILD_DIR)

    # load XDP
    run(f"sudo {XDP_LOADER_PATH} -S --dev {IFACE} --progname classification")
    # Load nodes into map
    MAP_PATH = f"/sys/fs/bpf/{IFACE}/xdp_randforest_nodes"
    # fd = os.open(MAP_PATH, os.O_RDWR)
    load_nodes_to_map(df, MAP_PATH)

    print("[INFO] Nodes loaded into xdp_randforest_nodes map")


if __name__ == "__main__":
    main()
