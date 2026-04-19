#ifndef COMMON_KERNEL_USER_H
#define COMMON_KERNEL_USER_H

#include <linux/types.h>

/* Fixed-point configuration */
#define FIXED_SHIFT         16
#define FIXED_SCALE         65536
#define MAX_TREES           300
#define MAX_NODE_PER_TREE   1251
#define MAX_FEATURES        5
#define MAX_DEPTH           31
#define TOTAL_NODES         375300
#define NUM_PACKET          12
#define REDIRECT_INTERFACE  10
#define MAX_FLOW_SAVED      1000000
#define NUM_LABELS          7
#define NS_TO_SEC_FIXED(x) ((__u32)(((x) << 16) / 1000000000ULL))

//current_length,max_length,min_length,sum_length,mean_length,max_iat,min_iat,sum_iat,mean_iat

#define FEATURE_CUR_LEN     0
#define FEATURE_MIN_LEN     1
#define FEATURE_MAX_LEN     2
#define FEATURE_SUM_LEN     3
#define FEATURE_MEAN_LEN    4

typedef __u64               fixed;

/* Latency statistics structure */
typedef struct {
    __u64 time_in;
    __u64 proc_time;  /*proc_time += time_out - time_in*/
    __u64 total_pkts;
    __u64 total_bytes;
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
    /*PACKET LENGTH FEATURES*/
    __u32   min_len;          /* Maximum packet length */
    __u32   max_len;          /* Minimum packet length */
    __u32   sum_len;
    __u32   mean_len;
    fixed   features[MAX_FEATURES];
    int     classified;
    int     label;
} data_point;

// /* Definition of feature vector to calculate RF */
// struct feat_vec {
//     fixed features[MAX_FEATURES];
// };

/* Definition of a Node of Decision Tree */
typedef struct {
    int     left_idx;
    int     right_idx;
    fixed   split_value;
    int     feature_idx;
    __u32   is_leaf;
    int     label;
    int     tree_idx;
} Node;

/* Convert float (as double in user space) to fixed-point */
static __always_inline fixed fixed_from_float(double value)
{
    return (__u64)(value * (double)FIXED_SCALE);
}

/* Convert fixed-point to float */
static __always_inline double fixed_to_float(fixed value)
{
    return (double)value / (double)FIXED_SCALE;
}

static __always_inline fixed fixed_from_uint(__u64 value)
{
    return value << FIXED_SHIFT;
}

static __always_inline __u64 fixed_to_uint(fixed value)
{
    return value >> FIXED_SHIFT;
}

static __always_inline fixed fixed_add(fixed a, fixed b)
{
    return a + b;
}

static __always_inline fixed fixed_sub(fixed a, fixed b)
{
    return (a > b) ? (a - b) : 0;
}

static __always_inline fixed fixed_mul(fixed a, fixed b)
{
    /* Use 128-bit intermediate to prevent overflow */
    __u64 a_int = a >> FIXED_SHIFT;
    __u64 a_frac = a & ((1ULL << FIXED_SHIFT) - 1);
    __u64 b_int = b >> FIXED_SHIFT;
    __u64 b_frac = b & ((1ULL << FIXED_SHIFT) - 1);
    
    __u64 result_int = a_int * b_int;
    __u64 result_frac = (a_int * b_frac + a_frac * b_int) >> FIXED_SHIFT;
    __u64 result_frac_frac = (a_frac * b_frac) >> (FIXED_SHIFT * 2);
    
    return (result_int << FIXED_SHIFT) + result_frac + result_frac_frac;
}

static __always_inline fixed fixed_div(fixed a, fixed b)
{
    if (b == 0)
        return 0;
    
    /* Shift dividend left to maintain precision */
    __u64 shifted_a = a << FIXED_SHIFT;
    return shifted_a / b;
}

static __always_inline fixed fixed_sqrt(fixed value)
{
    if (value == 0)
        return 0;

    fixed x = value;
    fixed two = fixed_from_uint(2);
    
    // #pragma unroll
    for (int i = 0; i < 10; i++) {
        fixed x_squared = fixed_div(value, x);
        x = fixed_div(fixed_add(x, x_squared), two);
    }
    
    return x;
}

static __always_inline fixed fixed_abs(fixed value)
{
    /* For unsigned __u64, this is just the value itself */
    return value;
}

static __always_inline int fixed_compare(fixed a, fixed b)
{
    if (a < b) return -1;
    if (a > b) return 1;
    return 0;
}


static __always_inline fixed fixed_log2(__u64 x)
{
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
}

static __always_inline fixed fixed_ln(__u64 x)
{
    if (x == 0)
        return 0;
    
    fixed log2_val = fixed_log2(x);
    fixed ln2 = 177;
    
    return fixed_mul(log2_val, ln2);
}

static __always_inline fixed fixed_exp(fixed x)
{
    fixed result = FIXED_SCALE; 
    fixed term = FIXED_SCALE;  
    
    // #pragma unroll
    for (int i = 1; i <= 6; i++) {
        term = fixed_mul(term, x);
        term = fixed_div(term, fixed_from_uint(i));
        result = fixed_add(result, term);
    }
    
    return result;
}

static __always_inline fixed fixed_pow(fixed base, __u32 exp)
{
    fixed result = FIXED_SCALE;
    
    // #pragma unroll
    for (__u32 i = 0; i < exp && i < 16; i++) {
        result = fixed_mul(result, base);
    }
    
    return result;
}

#endif /*COMMON_KERN_USER_H*/
