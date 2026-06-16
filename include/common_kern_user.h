#ifndef __COMMON_KERN_USER_H
#define __COMMON_KERN_USER_H

// #include <linux/types.h>

/* ── Tunable constants ─────────────────────────────────────── */
#define MAX_FLOW_SAVED   65536
#define MAX_FEATURES     6
#define FIXED_SHIFT      16          /* Q16 fixed-point          */
#define REDIRECT_INTERFACE 1

/* ── Feature indices ──────────────────────────────────────── */
#define FEATURE_CUR_LEN   0
#define FEATURE_SUM_IAT   1
#define FEATURE_MIN_LEN   2
#define FEATURE_MAX_LEN   3
#define FEATURE_SUM_LEN   4
#define FEATURE_MEAN_LEN  5

#define NUM_SNAPSHOTS    6
static const __u32 SNAPSHOT_AT[NUM_SNAPSHOTS] = {8, 12, 16, 18, 24, 32};

/* ── Flow key ─────────────────────────────────────────────── */
struct flow_key {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8  proto;
    __u8  pad[3];
};

typedef struct {
    __u64 features[NUM_SNAPSHOTS][MAX_FEATURES];
    __u32 captured;
} flow_snapshot;

typedef struct {
    __u64 start_ts;
    __u64 last_seen;
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 sum_iat;

    __u64 min_len;
    __u64 max_len;
    __u64 sum_len;
    __u64 mean_len;

    __s32 label;
    __u32 classified;

    __u64 features[MAX_FEATURES];

    flow_snapshot snapshots;

} data_point;

/* ── Global accounting ────────────────────────────────────── */
typedef struct {
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 flow_created;
    __u64 time_in;
    __u64 proc_time;
} accounting;

/* ── Fixed-point helper (usable from both kernel and user) ── */
static inline __u64 fixed_from_uint(__u64 v) { return v << FIXED_SHIFT; }

#endif /* __COMMON_KERN_USER_H */