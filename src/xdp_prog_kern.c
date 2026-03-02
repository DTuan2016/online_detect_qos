// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"

#define NANOSEC_PER_SEC 1000000000ULL

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ================= MAPS ================= */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_HASH);
    __type(key, struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
} xdp_flow_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, accounting);
    __uint(max_entries, 1);
} accounting_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_TREES * MAX_NODE_PER_TREE);
    __type(key, __u32);
    __type(value, Node);
} xdp_randforest_nodes SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 10);
    __type(key, __u32);
    __type(value, __u32);
} prog_array SEC(".maps");

struct forest_vote {
    int votes[NUM_LABELS];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct forest_vote);
} forest_vote_map SEC(".maps");

/* ================= PACKET PARSING ================= */
static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(0x88cc))
        return -2; // drop LLDP

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;

    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(icmp + 1) > data_end)
            return -1;
    }

    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end) return -1;
        key->src_port = tcph->source;
        key->dst_port = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end) return -1;
        key->src_port = udph->source;
        key->dst_port = udph->dest;
    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }

    key->src_port = bpf_ntohs(key->src_port);
    key->dst_port = bpf_ntohs(key->dst_port);
    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

/* ================= TREE INFERENCE ================= */
static __always_inline int predict_one_tree(__u32 root_idx, data_point *dp)
{
    __u32 node_idx = root_idx;

    #pragma unroll MAX_DEPTH
    for (int depth = 0; depth < MAX_DEPTH; depth++) {
        if (node_idx >= (MAX_TREES * MAX_NODE_PER_TREE)) {
            return 0;
        }

        Node *node = bpf_map_lookup_elem(&xdp_randforest_nodes, &node_idx);
        if (!node){
            return 0;
        }
        if (node->is_leaf) {
            // bpf_printk("NODE LA: idx=%u, label=%d", node_idx, node->label);
            return node->label;
        }
        // bpf_printk("Tree %d, Depth %d, NodeIdx=%u, Left=%d, Right=%d, Split=%llu, Feature=%d, IsLeaf=%u, Label=%d",
        //                 node->tree_idx, depth, node_idx, node->left_idx, node->right_idx,
        //                 node->split_value, node->feature_idx, node->is_leaf, node->label);
        __u32 f_idx = node->feature_idx;
        if (f_idx >= MAX_FEATURES){
            return 0;   
        }
        fixed f_val = dp->features[f_idx];
        fixed split = node->split_value;

        __u32 next_idx;
        if (f_val <= split) {
            next_idx = node->left_idx;
        } else {
            next_idx = node->right_idx;
        }

        if (next_idx == (__u32)-1 || next_idx >= (MAX_TREES * MAX_NODE_PER_TREE)) {
            return 0;
        }

        node_idx = next_idx;
    }
    // bpf_printk("Reached MAX_DEPTH: root_idx=%u", root_idx);
    return 0;
}

/* ================= RANDOM FOREST ================= */
static __always_inline int predict_forest(data_point *dp)
{
    int votes[NUM_LABELS] = {};

    #pragma unroll 25
    for (__u32 t = 0; t < 25; t++) {
        __u32 root_key = t * MAX_NODE_PER_TREE;
        int pred = predict_one_tree(root_key, dp);

        if (pred >= 0 && pred < NUM_LABELS)
            votes[pred]++;
    }

    /* Argmax */
    int best_label = 0;
    int best_vote = votes[0];

    #pragma unroll
    for (int i = 1; i < NUM_LABELS; i++) {
        if (votes[i] > best_vote) {
            best_vote = votes[i];
            best_label = i;
        }
    }

    return best_label;
}

static __always_inline void update_ipv4_csum_u8(struct iphdr *iph,
                                                __u8 old_val,
                                                __u8 new_val)
{
    __u32 check = (__u32)~iph->check & 0xFFFF;

    check += (__u32)(~old_val) & 0xFF;
    check += (__u32)new_val;

    check = (check & 0xFFFF) + (check >> 16);
    check = (check & 0xFFFF) + (check >> 16);

    iph->check = ~((__u16)check);
}

static __always_inline int rewrite_packet(struct xdp_md *ctx, __u8 label)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return XDP_PASS;

    /* ===== Map label → DSCP ===== */
    static const __u8 dscp_table[7] = {
        0,   // label 0
        8,   // label 1
        16,  // label 2
        24,  // label 3
        32,  // label 4
        40,  // label 5
        48   // label 6
    };

    if (label >= 7)
        return XDP_PASS;

    __u8 old_tos = iph->tos;
    __u8 ecn = old_tos & 0x03;

    __u8 new_tos = (dscp_table[label] << 2) | ecn;

    if (old_tos == new_tos)
        return XDP_PASS;

    iph->tos = new_tos;

    update_ipv4_csum_u8(iph, old_tos, new_tos);

    return XDP_PASS;
}

/* ================= FLOW STATS ================= */
static __always_inline int update_stats(struct flow_key *key,
                                                struct xdp_md *ctx)
{
    __u64 ts_ns = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)((void *)(long)ctx->data_end) -
                             (__u8 *)((void *)(long)ctx->data));

    int detect = 0;
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);
    if (!dp) {
        data_point zero = {};
        zero.start_ts = ts_ns;
        zero.last_seen = ts_ns;
        zero.min_IAT = 0xFFFFFFFFFFFFFFFFULL;
        zero.total_pkts = 1;
        zero.max_pkt_len = pkt_len;
        zero.min_pkt_len = pkt_len;
        zero.total_bytes = pkt_len;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY) != 0)
            return XDP_PASS;

        return XDP_PASS;
    }

    __u64 iat_ns = (dp->last_seen > 0 && ts_ns >= dp->last_seen) ? ts_ns - dp->last_seen : 0;

    __sync_fetch_and_add(&dp->total_pkts, 1);
    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    if (iat_ns > 0 && iat_ns < dp->min_IAT)
        dp->min_IAT = iat_ns;
    if (pkt_len > dp->max_pkt_len)
        dp->max_pkt_len = pkt_len;
    if (pkt_len < dp->min_pkt_len)
        dp->min_pkt_len = pkt_len;

    dp->last_seen = ts_ns;

    dp->features[QS_FEATURE_FLOW_DURATION] = fixed_from_uint(dp->last_seen - dp->start_ts);
    dp->features[QS_FEATURE_TOTAL_FWD_PACKET] = fixed_from_uint(dp->total_pkts);
    dp->features[QS_FEATURE_TOTAL_LENGTH_OF_FWD_PACKET] = fixed_from_uint(dp->total_bytes);
    dp->features[QS_FEATURE_FWD_PACKET_LENGTH_MAX] = fixed_from_uint(dp->max_pkt_len);
    dp->features[QS_FEATURE_FWD_PACKET_LENGTH_MIN] = fixed_from_uint(dp->min_pkt_len);
    dp->features[QS_FEATURE_FWD_IAT_MIN] = fixed_from_uint(dp->min_IAT);

    if((dp->features[QS_FEATURE_FLOW_DURATION]) == FLOW_LEVEL_DUR_NS || (dp->features[QS_FEATURE_TOTAL_FWD_PACKET] >= FLOW_LEVEL_PKTS)){
        detect = 1;
    }

    return detect;
}

static __always_inline int process_stage(struct xdp_md *ctx,
                                         data_point *dp,
                                         __u32 stage_id,
                                         __u32 tree_start,
                                         __u32 tree_count)
{
    __u32 key = 0;
    struct forest_vote *fv =
        bpf_map_lookup_elem(&forest_vote_map, &key);

    if (!fv)
        return XDP_PASS;

#pragma unroll
    for (int t = 0; t < 25; t++) {
        if (t >= tree_count)
            break;

        __u32 root = (tree_start + t) * MAX_NODE_PER_TREE;
        int pred = predict_one_tree(root, dp);

        if (pred >= 0 && pred < NUM_LABELS)
            fv->votes[pred]++;
    }

    /* tail call next stage */
    __u32 next = stage_id + 1;
    bpf_printk("JUMP_TO_STAGE_%d", next);
    bpf_tail_call(ctx, &prog_array, next);

    /* nếu tail call fail */
    return XDP_PASS;
}

static __always_inline data_point *get_dp_from_ctx(struct xdp_md *ctx)
{
    struct flow_key key = {};
    __u64 pkt_len = 0;

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret < 0)
        return NULL;

    data_point *dp =
        bpf_map_lookup_elem(&xdp_flow_tracking, &key);

    return dp;
}

SEC("xdp")
int stage0(struct xdp_md *ctx)
{
    bpf_printk("HERE_IS_STAGE_0");
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
    {
        bpf_printk("GET_DP_FAIL");
        return XDP_PASS;
    }
        
    bpf_printk("GET_DP_SUCCESS");
    return process_stage(ctx, dp, 0, 0, 25);
}

SEC("xdp")
int stage1(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 1, 25, 25);
}

SEC("xdp")
int stage2(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 2, 50, 25);
}

SEC("xdp")
int stage3(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 3, 75, 25);
}

SEC("xdp")
int stage4(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 4, 100, 25);
}

SEC("xdp")
int stage5(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 5, 125, 25);
}

SEC("xdp")
int stage6(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 6, 150, 25);
}

SEC("xdp")
int stage7(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 7, 175, 25);
}

SEC("xdp")
int stage8(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    return process_stage(ctx, dp, 8, 200, 25);
}

SEC("xdp")
int stage9(struct xdp_md *ctx)
{
    data_point *dp = get_dp_from_ctx(ctx);
    if (!dp)
        return XDP_PASS;

    __u32 key = 0;
    struct forest_vote *fv =
        bpf_map_lookup_elem(&forest_vote_map, &key);

    if (!fv)
        return XDP_PASS;

    /* Argmax */
    int best_label = 0;
    int best_vote = fv->votes[0];

#pragma unroll
    for (int i = 1; i < NUM_LABELS; i++) {
        if (fv->votes[i] > best_vote) {
            best_vote = fv->votes[i];
            best_label = i;
        }
    }

    /* reset votes */
#pragma unroll
    for (int i = 0; i < NUM_LABELS; i++)
        fv->votes[i] = 0;

    rewrite_packet(ctx, best_label);
    __u32 other_interface = 9;
    // bpf_redirect(other_interface, 0);
   
    return bpf_redirect(other_interface, 0);
}

/* ================= XDP ENTRY ================= */
SEC("xdp")
int classification(struct xdp_md *ctx)
{
    bpf_printk("START CLASSIFICATION");
    struct flow_key key = {};
    __u64 pkt_len = 0;
    __u32 vote_key = 0;

    struct forest_vote *fv;
    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    bpf_printk("DONE PARSE PACKET");

    if (ret == -2)      /* LLDP */
        return XDP_DROP;

    if (ret < 0)
        return XDP_PASS;

    int detect = update_stats(&key, ctx);
    bpf_printk("DONE UPDATE STATS");
    if (detect == 0) {
        return XDP_PASS;
    }
    else{
        fv = bpf_map_lookup_elem(&forest_vote_map, &vote_key);
        if (!fv)
            return XDP_PASS;

    #pragma unroll
        for (int i = 0; i < NUM_LABELS; i++)
            fv->votes[i] = 0;

        bpf_printk("JUMP_TO_STAGE_0");
        bpf_tail_call(ctx, &prog_array, 0);
        return XDP_PASS;
    }
}

char LICENSE[] SEC("license") = "GPL";