#ifndef COMMON_KERNEL_USER_H
#define COMMON_KERNEL_USER_H

#include <linux/types.h>

/* Fixed-point configuration */
// #define MAX_TREES           300
// #define MAX_NODE_PER_TREE   987
// #define MAX_DEPTH           28
// #define TOTAL_NODES         296100
#define FIXED_SHIFT         16
#define FIXED_SCALE         65536
#define MAX_FEATURES        6
#define NUM_PACKET          12
#define REDIRECT_INTERFACE  6
#define MAX_FLOW_SAVED      1000000
#define NUM_LABELS          7
#define NS_TO_SEC_FIXED(x) ((__u32)(((x) << 16) / 1000000000ULL))

#define FEATURE_CUR_LEN     0
#define FEATURE_SUM_IAT     1
#define FEATURE_MIN_LEN     2
#define FEATURE_MAX_LEN     3
#define FEATURE_SUM_LEN     4
#define FEATURE_MEAN_LEN    5

typedef __u64               fixed;

typedef struct {
    __u64 time_in;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u64 total_pkts;
    __u64 total_bytes;
    __u64 flow_created;
} accounting;

/* Flow key structure */
struct flow_key {
    __u32   src_ip;
    __u16   src_port;
    __u32   dst_ip;
    __u16   dst_port;
    __u8    proto;
} __attribute__((packed));

/* Definition of a datapoint or a flow (accounting) */
typedef struct {
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
} __attribute__((packed)) data_point;

static __always_inline fixed fixed_from_uint(__u64 value)
{
    return value << FIXED_SHIFT;
}

#endif /*COMMON_KERN_USER_H*/
