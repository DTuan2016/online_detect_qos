#!/usr/bin/env python3
"""
dump_rf.py — Export RandomForest sang QuickScorer format
         và generate common_kern_user.h cho XDP BPF program.

Kiến trúc (theo paper Lucchese et al. 2015 + document 9/10):
  - Toàn bộ QS data nằm trong 1 struct qsDataStruct
  - threshold[] sorted tăng dần theo feature
  - QS_FEATURE macro scan threshold, AND bitvector khi FALSE node
  - msb_index(v[h]) = exit leaf
  - v[] init = 111...1 trước mỗi inference
"""

import os
import sys
import argparse
import subprocess
import joblib
import numpy as np

# ============================================================
# FIXED POINT  (phải khớp với FIXED_SHIFT trong header)
# ============================================================
FIXED_SHIFT = 16
FIXED_SCALE = 1 << FIXED_SHIFT

def to_fixed(value: float) -> int:
    """float → Q16 fixed-point (unsigned)"""
    return max(int(value * FIXED_SCALE), 0)

# ============================================================
# MODEL UNWRAP
# ============================================================

def unwrap_model(model):
    try:
        from sklearn.model_selection import GridSearchCV
        if isinstance(model, GridSearchCV):
            print("[INFO] GridSearchCV → best_estimator_")
            model = model.best_estimator_
    except ImportError:
        pass
    try:
        from sklearn.pipeline import Pipeline
        if isinstance(model, Pipeline):
            print("[INFO] Pipeline → last step")
            model = model.steps[-1][1]
    except ImportError:
        pass
    return model

def load_model(model_path: str):
    if not os.path.exists(model_path):
        raise FileNotFoundError(model_path)
    data = joblib.load(model_path)
    if isinstance(data, dict) and "model" in data:
        model         = data["model"]
        feature_names = data.get("features", [])
        label_names   = data.get("labels", [])
    else:
        model         = data
        feature_names = []
        label_names   = []
    model = unwrap_model(model)
    if not hasattr(model, "estimators_"):
        raise ValueError("Not a fitted RandomForestClassifier.")
    return model, feature_names, label_names

# ============================================================
# BITVECTOR HELPERS
# ============================================================

def get_leaf_order(tree) -> list:
    """Lá theo thứ tự trái→phải (in-order traversal)"""
    leaves = []
    def inorder(nid):
        l = tree.children_left[nid]
        r = tree.children_right[nid]
        if l == -1:
            leaves.append(nid)
            return
        inorder(l)
        inorder(r)
    inorder(0)
    return leaves

def build_node_bitvector(tree, node_id: int, leaf_pos: dict, n_leaves: int) -> int:
    """
    node bitvector: bit j = 0 nếu leaf j nằm trong LEFT subtree của node_id.
    Khi node là FALSE (feat < thresh), AND v[h] với bitvector này
    → loại bỏ các lá ở left subtree khỏi candidate set.
    """
    left_leaf_nids = set()
    def dfs(nid):
        l = tree.children_left[nid]
        r = tree.children_right[nid]
        if l == -1:
            left_leaf_nids.add(nid)
            return
        dfs(l); dfs(r)
    dfs(tree.children_left[node_id])

    bv = (1 << n_leaves) - 1      # start: tất cả bit = 1
    for leaf_nid in left_leaf_nids:
        j = leaf_pos.get(leaf_nid, -1)
        if 0 <= j < n_leaves:
            bv &= ~(1 << j)        # clear bit j
    return bv & ((1 << n_leaves) - 1)

# ============================================================
# QUICKSCORER EXPORT
# ============================================================

def export_quickscorer(model_path: str, n_features: int):
    """
    Trả về:
      thresholds   : list[fixed]  — tất cả threshold, sorted theo feature
      bitvectors   : list[int]    — node bitvector tương ứng
      tree_ids     : list[int]    — cây sở hữu entry đó
      offsets      : list[int]    — offsets[k] = start của feature k (len = n_features+1)
      leaves_flat  : list[int]    — label của lá, group theo cây
      num_leaves   : list[int]    — số lá của từng cây
      lambda_      : int          — max leaves/tree (padded to power of 2 ≤ 64)
      n_trees      : int
    """
    model, _, _ = load_model(model_path)
    classes      = list(model.classes_)
    label_map    = {c: i for i, c in enumerate(classes)}
    n_trees      = len(model.estimators_)

    # Xác định lambda (max leaves, padded to power of 2, ≤ 64)
    max_leaves = 0
    for est in model.estimators_:
        t = est.tree_
        n_lv = int(np.sum(t.children_left == -1))
        max_leaves = max(max_leaves, n_lv)
    lambda_ = 1
    while lambda_ < max_leaves and lambda_ < 64:
        lambda_ *= 2
    lambda_ = min(lambda_, 64)

    # Per-feature buckets: list of (threshold_fixed, tree_id, bitvector)
    feature_buckets = [[] for _ in range(n_features)]

    # Leaves
    leaves_flat = []
    num_leaves  = []

    for tree_idx, estimator in enumerate(model.estimators_):
        tree      = estimator.tree_
        leaf_order = get_leaf_order(tree)
        leaf_pos   = {nid: j for j, nid in enumerate(leaf_order)}
        n_lv       = len(leaf_order)
        num_leaves.append(n_lv)

        # Leaf labels
        for leaf_nid in leaf_order:
            value = tree.value[leaf_nid].flatten()
            if value.sum() > 0:
                lbl = label_map[classes[int(np.argmax(value))]]
            else:
                lbl = 0
            leaves_flat.append(lbl)
        # Pad to lambda_
        leaves_flat.extend([0] * (lambda_ - n_lv))

        # Internal nodes → feature buckets
        for nid in range(tree.node_count):
            if tree.children_left[nid] == -1:
                continue  # leaf
            feat_id   = int(tree.feature[nid])
            threshold = to_fixed(float(tree.threshold[nid]))
            bv        = build_node_bitvector(tree, nid, leaf_pos, lambda_)
            if 0 <= feat_id < n_features:
                feature_buckets[feat_id].append((threshold, tree_idx, bv))

    # Sort mỗi bucket tăng dần theo threshold
    for k in range(n_features):
        feature_buckets[k].sort(key=lambda x: x[0])

    # Flatten
    thresholds  = []
    bitvectors  = []
    tree_ids    = []
    offsets     = []

    for k in range(n_features):
        offsets.append(len(thresholds))
        for (thr, tid, bv) in feature_buckets[k]:
            thresholds.append(thr)
            tree_ids.append(tid)
            bitvectors.append(bv)
    offsets.append(len(thresholds))  # sentinel

    print(f"[QS] n_trees={n_trees}, lambda={lambda_}, "
          f"max_leaves={max_leaves}, total_nodes={len(thresholds)}")
    return (thresholds, bitvectors, tree_ids, offsets,
            leaves_flat, num_leaves, lambda_, n_trees)

# ============================================================
# HEADER GENERATOR
# ============================================================

def generate_header(output_path: str,
                    model_path: str,
                    n_features: int,
                    feature_names: list,
                    label_names: list,
                    flow_level_pkts: int,
                    flow_level_dur_ns: int,
                    max_flow_saved: int,
                    redirect_if: int):

    (thresholds, bitvectors, tree_ids, offsets,
     leaves_flat, num_leaves, lambda_, n_trees) = export_quickscorer(model_path, n_features)

    n_nodes  = len(thresholds)
    n_leaves = len(leaves_flat)

    # --- C arrays ---
    def c_array_u64(name, data, type_="fixed"):
        lines = [f"static const {type_} {name}[{len(data)}] = {{"]
        chunk = 8
        for i in range(0, len(data), chunk):
            row = data[i:i+chunk]
            lines.append("  " + ", ".join(
                f"{v}ULL" if type_ == "fixed" or type_ == "BITVECTOR_TYPE"
                else str(v)
                for v in row
            ) + ",")
        lines[-1] = lines[-1].rstrip(",")
        lines.append("};")
        return "\n".join(lines)

    def c_array_u16(name, data):
        lines = [f"static const __u16 {name}[{len(data)}] = {{"]
        chunk = 16
        for i in range(0, len(data), chunk):
            row = data[i:i+chunk]
            lines.append("  " + ", ".join(str(v) for v in row) + ",")
        lines[-1] = lines[-1].rstrip(",")
        lines.append("};")
        return "\n".join(lines)

    def c_array_u8(name, data):
        lines = [f"static const __u8 {name}[{len(data)}] = {{"]
        chunk = 16
        for i in range(0, len(data), chunk):
            row = data[i:i+chunk]
            lines.append("  " + ", ".join(str(v) for v in row) + ",")
        lines[-1] = lines[-1].rstrip(",")
        lines.append("};")
        return "\n".join(lines)

    # Leaf bases (start index của từng cây trong leaves_flat)
    leaf_bases = []
    acc = 0
    for nl in num_leaves:
        leaf_bases.append(acc)
        acc += lambda_  # padded

    # Offsets defines
    offset_defines = "\n".join(
        f"#define QS_OFFSETS_{k}  {offsets[k]}"
        for k in range(n_features + 1)
    )

    # Leaf base defines
    leaf_base_defines = "\n".join(
        f"#define QS_LEAF_BASE_{h}  {leaf_bases[h]}"
        for h in range(n_trees)
    )

    # Num leaves defines
    num_leaves_defines = "\n".join(
        f"#define QS_NUM_LEAVES_{h}  {num_leaves[h]}"
        for h in range(n_trees)
    )

    # QS_VOTE_BLOCK macro — dùng trong qs_vote_all
    vote_block_macro = r"""
#define QS_VOTE_BLOCK(H) do {                                          \
    BITVECTOR_TYPE _ei = (BITVECTOR_TYPE)(__u8)msb_index(tree->v[H]); \
    if (_ei < QS_NUM_LEAVES_##H) {                                     \
        __u64 _li = QS_LEAF_BASE_##H + _ei;                           \
        if (_li < QS_NUM_LEAVES)                                       \
            votes += tree->leaves[_li];                                \
    }                                                                  \
} while (0)"""

    # QS_FEATURE macro
    qs_feature_macro = r"""
/* QS_FEATURE: scan threshold[START..END) tăng dần.
 * feat_value < threshold[i]  →  node là FALSE  →  AND bitvector vào v[h].
 * Break ngay khi feat_value >= threshold[i]  →  node TRUE  →  dừng.  */
#define QS_FEATURE(IDX, START, END) do {                              \
    fixed _fv = fv.features[IDX];                                     \
    for (int _i = (START); _i < (END); _i++) {                        \
        if (_fv < tree->threshold[_i]) {                              \
            __u16 _h = tree->tree_ids[_i];                            \
            if (_h < QS_NUM_TREES)                                    \
                tree->v[_h] &= tree->bitvectors[_i];                  \
        } else break;                                                 \
    }                                                                 \
} while (0)"""

    # Feature index defines
    feat_defines = "\n".join(
        f"#define FEATURE_{fn.upper().replace(' ', '_')}  {i}"
        for i, fn in enumerate(feature_names)
    ) if feature_names else "\n".join(
        f"#define FEATURE_{i}  {i}" for i in range(n_features)
    )

    header = f"""#ifndef COMMON_KERN_USER_H
#define COMMON_KERN_USER_H

#include <stdint.h>
#include <linux/types.h>

/* ============================================================
 * GENERAL
 * ============================================================ */
#define MAX_FLOW_SAVED          {max_flow_saved}
#define FLOW_LEVEL_PKTS         {flow_level_pkts}
#define FLOW_LEVEL_DUR_NS       {flow_level_dur_ns}
#define REDIRECT_INTERFACE      {redirect_if}

/* ============================================================
 * QUICKSCORER CONFIGURATION
 * Ref: Lucchese et al., QuickScorer, SIGIR 2015
 *
 * QS_NUM_TREES  : số cây trong Random Forest
 * QS_NUM_NODES  : tổng internal nodes (= len(thresholds[]))
 * QS_NUM_LEAVES : tổng entries trong leaves[] (= n_trees * lambda)
 * QS_LAMBDA     : max leaves/tree (power of 2, ≤ 64)
 * MAX_FEATURES  : số features
 * ============================================================ */
#define QS_NUM_TREES            {n_trees}
#define MAX_FEATURES            {n_features}
#define QS_NUM_NODES            {n_nodes}
#define QS_NUM_LEAVES           {n_leaves}
#define QS_LAMBDA               {lambda_}

/* Feature index mapping */
{feat_defines}

/* ============================================================
 * FIXED-POINT  Q{FIXED_SHIFT}
 * ============================================================ */
#define FIXED_SHIFT             {FIXED_SHIFT}
#define FIXED_SCALE             {FIXED_SCALE}
typedef __u64 fixed;

static __always_inline fixed fixed_from_uint(__u64 v) {{ return v << FIXED_SHIFT; }}
static __always_inline __u64 fixed_to_uint(fixed v)   {{ return v >> FIXED_SHIFT; }}

/* ============================================================
 * BITVECTOR  (u64, ≤ 64 leaves per tree)
 * ============================================================ */
typedef __u64 BITVECTOR_TYPE;

/* msb_index: vị trí bit CAO nhất đang set (= exit leaf index).
 * Dùng De Bruijn multiplication — không có __builtin_clz trong BPF.  */
static __always_inline BITVECTOR_TYPE msb_index(BITVECTOR_TYPE x) {{
    static const __u8 index[64] = {{
        0,  1,  2, 57,  3, 61, 58, 47,  4, 62, 52, 59, 49, 48,  5, 32,
       63, 53, 50, 33, 60, 46, 51, 36,  6, 39, 44, 38, 37, 43, 35,  7,
       54, 40, 41, 34, 42, 31, 30, 29, 28, 27, 26, 25, 24, 23, 22, 21,
       20, 19, 18, 17, 16, 15, 14, 13, 12, 11, 10,  9,  8, 55, 56, 45
    }};
    if (x == 0) return 0;
    x |= x >> 1;  x |= x >> 2;  x |= x >> 4;
    x |= x >> 8;  x |= x >> 16; x |= x >> 32;
    return index[((x * 0x7EDD5E59A4E28C2ULL) >> 58) & 0x3f];
}}

/* ============================================================
 * STRUCTS
 * ============================================================ */

typedef struct {{
    __u64 time_in;
    __u64 proc_time;
    __u64 total_pkts;
    __u64 total_bytes;
}} accounting;

struct flow_key {{
    __u32  src_ip;
    __u16  src_port;
    __u32  dst_ip;
    __u16  dst_port;
    __u8   proto;
}} __attribute__((packed));

/* Per-flow statistics */
typedef struct {{
    __u64  start_ts;
    __u64  last_seen;
    __u64  min_IAT;
    __u32  total_pkts;
    __u32  max_pkt_len;
    __u32  min_pkt_len;
    __u32  total_bytes;
    int    label;
}} data_point;

/* Feature vector passed to QuickScorer inference */
struct feat_vec {{
    fixed features[MAX_FEATURES];
}};

/* QuickScorer data — 1 instance nằm trong BPF map qs_forest.
 * Layout:
 *   threshold[i]  : fixed-point threshold, sorted asc per feature block
 *   bitvectors[i] : node bitvector (bit j=0 → leaf j in LEFT subtree)
 *   v[h]          : result bitvector tree h, init=111...1, AND on FALSE node
 *   tree_ids[i]   : cây sở hữu entry i
 *   num_leaves_per_tree[h]: số lá thực tế của cây h
 *   leaves[h*lambda+j]    : label của lá j của cây h (0 hoặc 1)
 */
struct qsDataStruct {{
    fixed          threshold[QS_NUM_NODES];
    BITVECTOR_TYPE bitvectors[QS_NUM_NODES];
    BITVECTOR_TYPE v[QS_NUM_TREES];
    __u16          tree_ids[QS_NUM_NODES];
    __u8           num_leaves_per_tree[QS_NUM_TREES];
    __u8           leaves[QS_NUM_LEAVES];
}};

/* ============================================================
 * QUICKSCORER STATIC DATA  (pre-computed offline)
 * ============================================================ */

{c_array_u64("_qs_threshold", thresholds, "fixed")}

{c_array_u64("_qs_bitvectors", bitvectors, "BITVECTOR_TYPE")}

{c_array_u16("_qs_tree_ids", tree_ids)}

{c_array_u8("_qs_num_leaves_per_tree", num_leaves)}

{c_array_u8("_qs_leaves", leaves_flat)}

/* ============================================================
 * OFFSETS: vị trí bắt đầu của từng feature trong threshold[]
 * offsets[k]   = start của feature k
 * offsets[k+1] = end   của feature k  (exclusive)
 * ============================================================ */
{offset_defines}

/* ============================================================
 * LEAF BASES: vị trí bắt đầu của từng cây trong leaves[]
 * ============================================================ */
{leaf_base_defines}

/* ============================================================
 * NUM LEAVES PER TREE
 * ============================================================ */
{num_leaves_defines}

/* ============================================================
 * MACROS
 * ============================================================ */
{qs_feature_macro}

{vote_block_macro}

#ifndef XDP_ACTION_MAX
#define XDP_ACTION_MAX (XDP_REDIRECT + 1)
#endif

#endif /* COMMON_KERN_USER_H */
"""

    with open(output_path, "w") as f:
        f.write(header)
    print(f"[HEADER] Written: {output_path}")
    print(f"[HEADER] QS_NUM_NODES={n_nodes}, QS_NUM_LEAVES={n_leaves}, "
          f"QS_LAMBDA={lambda_}, QS_NUM_TREES={n_trees}")

# ============================================================
# RUNNER
# ============================================================

def run(cmd, cwd=None):
    print(f"\n[RUN] {cmd}")
    r = subprocess.run(cmd, shell=True,
                       cwd=os.path.expanduser(cwd) if cwd else None)
    if r.returncode != 0:
        print(f"[ERROR] {cmd}")
        sys.exit(1)

# ============================================================
# MAIN
# ============================================================

def main():
    parser = argparse.ArgumentParser(
        description="Export RandomForest → QuickScorer header cho XDP BPF"
    )
    parser.add_argument("--model",          required=True,
                        help="Path to model.pkl / model.joblib")
    parser.add_argument("--n_features",     required=True, type=int,
                        help="Số features (phải khớp với model)")
    parser.add_argument("--feature_names",  nargs="*", default=[],
                        help="Tên feature theo thứ tự (tùy chọn)")
    parser.add_argument("--label_names",    nargs="*", default=[],
                        help="Tên label (tùy chọn)")
    parser.add_argument("--flow_pkts",      default=12,    type=int,
                        help="FLOW_LEVEL_PKTS (default=6)")
    parser.add_argument("--flow_dur_ns",    default=100,  type=int,
                        help="FLOW_LEVEL_DUR_NS (default=100)")
    parser.add_argument("--max_flows",      default=100000, type=int,
                        help="MAX_FLOW_SAVED (default=2000)")
    parser.add_argument("--redirect_if",    default=7,    type=int,
                        help="Interface index để redirect (default=9)")
    parser.add_argument("--output_header",
                        default="../include/common_kern_user.h",
                        help="Path output header C")
    parser.add_argument("--build_dir",      default=None,
                        help="Build directory (chạy make nếu có)")
    args = parser.parse_args()

    model, feature_names_from_pkl, label_names_from_pkl = load_model(args.model)
    feature_names = args.feature_names or feature_names_from_pkl
    label_names   = args.label_names   or label_names_from_pkl

    print(f"\n[MODEL] trees={len(model.estimators_)}, "
          f"features={model.n_features_in_}")
    print(f"[MODEL] classes={list(model.classes_)}")

    generate_header(
        output_path      = args.output_header,
        model_path       = args.model,
        n_features       = args.n_features,
        feature_names    = feature_names,
        label_names      = label_names,
        flow_level_pkts  = args.flow_pkts,
        flow_level_dur_ns= args.flow_dur_ns,
        max_flow_saved   = args.max_flows,
        redirect_if      = args.redirect_if,
    )

    if args.build_dir:
        run("make", cwd=args.build_dir)

if __name__ == "__main__":
    main()