// SPDX-License-Identifier: GPL-2.0
// Pipeline:
//   xdp_anomaly_detector()
//     → parse_packet_get_data()
//     → update_stats()  [cập nhật flow stats]
//       → nếu đủ ngưỡng: predict_forest()  [QS inference]
//         → XDP_DROP nếu attack, XDP_PASS/redirect nếu benign
//
// QuickScorer Algorithm 2 (Lucchese et al. 2015):
//   v[h] = 111...1  (init: all leaves are candidates)
//   For each feature k, scan threshold[offsets[k]..offsets[k+1]):
//     if feat < threshold[i]:  v[tree_ids[i]] &= bitvectors[i]
//     else: break              (sorted asc → remaining all TRUE)
//   exit_leaf[h] = msb_index(v[h])
//   label = leaves[leaf_base[h] + exit_leaf[h]]

// #include <linux/bpf.h>
// #include <bpf/bpf_helpers.h>
// #include <linux/if_ether.h>
// #include <linux/ip.h>
// #include <linux/tcp.h>
// #include <linux/udp.h>
// #include <linux/icmp.h>
// #include <linux/in.h>
// #include <bpf/bpf_endian.h>
#include "vmlinux.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#include "common_kern_user.h"

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ================================================================
 * BPF MAPS
 * ================================================================ */

/* Per-flow tracking (PERCPU để tránh lock) */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_HASH);
    __type(key,         struct flow_key);
    __type(value,       data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
} xdp_flow_tracking SEC(".maps");

/* Flows bị drop (attack) */
struct {
    __uint(type,        BPF_MAP_TYPE_PERCPU_HASH);
    __type(key,         struct flow_key);
    __type(value,       data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
} xdp_flow_dropped SEC(".maps");

/* QuickScorer model: 1 entry, toàn bộ qsDataStruct
 * (không cần 6 map riêng → tránh bpf_map_lookup trong inner loop) */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       struct qsDataStruct);
} qs_forest SEC(".maps");

/* Accounting / latency */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       accounting);
} accounting_map SEC(".maps");

/* Tổng số flow đã tạo */
struct {
    __uint(type,        BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key,         __u32);
    __type(value,       __u32);
} flow_counter SEC(".maps");


/* ================================================================
 * PACKET PARSING
 * ================================================================ */

static __always_inline int
parse_packet_get_data(struct xdp_md *ctx,
                      struct flow_key *key,
                      __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(0x88cc))
        return -2;  /* LLDP → drop */

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;

    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp =
            (struct icmphdr *)((__u8 *)iph + iph->ihl * 4);
        if ((void *)(icmp + 1) > data_end)
            return -1;

        /* Whitelist ICMP loopback */
        __u32 src = bpf_ntohl(iph->saddr);
        __u32 dst = bpf_ntohl(iph->daddr);
        if ((src == 0xC0A83203 && dst == 0xC0A83204 && icmp->type == 8) ||
            (src == 0xC0A83204 && dst == 0xC0A83203 && icmp->type == 0) ||
            (src == 0xC0A8331E  || dst == 0xC0A8331E))
            return 1;  /* pass silently */

        key->src_port = 0;
        key->dst_port = 0;

    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph =
            (struct tcphdr *)((__u8 *)iph + iph->ihl * 4);
        if ((void *)(tcph + 1) > data_end) return -1;
        key->src_port = bpf_ntohs(tcph->source);
        key->dst_port = bpf_ntohs(tcph->dest);

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph =
            (struct udphdr *)((__u8 *)iph + iph->ihl * 4);
        if ((void *)(udph + 1) > data_end) return -1;
        key->src_port = bpf_ntohs(udph->source);
        key->dst_port = bpf_ntohs(udph->dest);

    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }

    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}


/* ================================================================
 * QUICKSCORER — Step 2: vote
 *
 * Với mỗi cây h:
 *   exit_leaf = msb_index(v[h])  (bit CAO nhất = leftmost candidate)
 *   label = leaves[leaf_base[h] + exit_leaf]
 *   votes += label
 *
 * Dùng QS_VOTE_BLOCK macro (defined trong header) để verifier
 * thấy constant index cho mỗi cây.
 * ================================================================ */

static __always_inline __u64
qs_vote_all(struct qsDataStruct *tree)
{
    __u64 votes = 0;

    /* Expand 70 cây bằng macro để verifier xử lý được */
    #pragma unroll
    for (int h = 0; h < QS_NUM_TREES; h++) {
        BITVECTOR_TYPE exit_leaf_idx =
            (BITVECTOR_TYPE)(__u8)msb_index(tree->v[h]);

        __u8 num_leaves = tree->num_leaves_per_tree[h];
        if (exit_leaf_idx >= num_leaves)
            continue;

        /* leaf_base = h * QS_LAMBDA (uniform padding) */
        __u64 leaf_base  = (__u64)h * QS_LAMBDA;
        __u64 leaf_index = leaf_base + exit_leaf_idx;

        if (leaf_index >= QS_NUM_LEAVES)
            continue;

        votes += tree->leaves[leaf_index];
    }

    return votes;
}


/* ================================================================
 * QUICKSCORER INFERENCE
 *
 * 1. Reset v[h] = 111...1 cho tất cả cây
 * 2. QS_FEATURE cho từng feature (macro trong header)
 * 3. qs_vote_all → majority vote
 * ================================================================ */

static __always_inline int
predict_forest(struct feat_vec fv)
{
    __u32 key = 0;
    struct qsDataStruct *tree =
        bpf_map_lookup_elem(&qs_forest, &key);
    if (!tree)
        return 0;

    /* Reset v[] = 111...1 */
    #pragma unroll
    for (int h = 0; h < QS_NUM_TREES; h++)
        tree->v[h] = ~(BITVECTOR_TYPE)0;

    /* QS Step 1: xử lý từng feature
     * QS_FEATURE(feature_idx, offset_start, offset_end) */
    QS_FEATURE(0, QS_OFFSETS_0, QS_OFFSETS_1);
    QS_FEATURE(1, QS_OFFSETS_1, QS_OFFSETS_2);
    QS_FEATURE(2, QS_OFFSETS_2, QS_OFFSETS_3);
    QS_FEATURE(3, QS_OFFSETS_3, QS_OFFSETS_4);
    QS_FEATURE(4, QS_OFFSETS_4, QS_OFFSETS_5);
    QS_FEATURE(5, QS_OFFSETS_5, QS_OFFSETS_6);

    /* QS Step 2: vote */
    __u64 votes = qs_vote_all(tree);

    return (votes > (QS_NUM_TREES / 2)) ? 1 : 0;
}


/* ================================================================
 * FLOW STATS UPDATE
 *
 * Returns:
 *   XDP_PASS  — benign hoặc chưa đủ ngưỡng
 *   XDP_DROP  — attack detected
 * ================================================================ */

static __always_inline int
update_stats(struct flow_key *key, struct xdp_md *ctx)
{
    __u64 ts_ns   = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)(long)ctx->data_end -
                            (__u8 *)(long)ctx->data);
    int ret = XDP_PASS;

    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);

    if (!dp) {
        /* Flow mới: khởi tạo */
        data_point z     = {};
        z.start_ts       = ts_ns;
        z.last_seen      = ts_ns;
        z.min_IAT        = 0xFFFFFFFFFFFFFFFFULL;
        z.total_pkts     = 1;
        z.max_pkt_len    = (__u32)pkt_len;
        z.min_pkt_len    = (__u32)pkt_len;
        z.total_bytes    = (__u32)pkt_len;
        z.label          = -1;

        if (bpf_map_update_elem(&xdp_flow_tracking, key, &z, BPF_ANY) != 0)
            return ret;

        __u32 idx  = 0;
        __u32 *cnt = bpf_map_lookup_elem(&flow_counter, &idx);
        if (cnt)
            __sync_fetch_and_add(cnt, 1);

        return ret;
    }

    /* Flow đã tồn tại: cập nhật stats */
    __u64 iat = (ts_ns >= dp->last_seen) ? ts_ns - dp->last_seen : 0;
    if (iat > 0 && iat < dp->min_IAT)
        dp->min_IAT = iat;

    if ((__u32)pkt_len > dp->max_pkt_len) dp->max_pkt_len = (__u32)pkt_len;
    if ((__u32)pkt_len < dp->min_pkt_len) dp->min_pkt_len = (__u32)pkt_len;

    dp->last_seen = ts_ns;

    /* BPF XADD: không dùng return value */
    __sync_fetch_and_add(&dp->total_pkts,  1);
    __sync_fetch_and_add(&dp->total_bytes, (__u32)pkt_len);

    /* Kiểm tra ngưỡng phân loại */
    __u64 flow_dur = dp->last_seen - dp->start_ts;
    if (dp->total_pkts  >= FLOW_LEVEL_PKTS ||
        flow_dur        >= FLOW_LEVEL_DUR_NS) {

        struct feat_vec fv = {};
        fv.features[0] = fixed_from_uint(flow_dur);
        fv.features[1] = fixed_from_uint(dp->total_pkts);
        fv.features[2] = fixed_from_uint(dp->total_bytes);
        fv.features[3] = fixed_from_uint(dp->max_pkt_len);
        fv.features[4] = fixed_from_uint(dp->min_pkt_len);
        fv.features[5] = fixed_from_uint(dp->min_IAT);

        int pred  = predict_forest(fv);
        dp->label = pred;

        if (pred == 0) {
            ret = XDP_PASS;
        } else {
            ret = XDP_DROP;
            bpf_map_update_elem(&xdp_flow_dropped, key, dp, BPF_ANY);
        }

        bpf_map_update_elem(&xdp_flow_tracking, key, dp, BPF_ANY);
    }

    return ret;
}


/* ================================================================
 * XDP ENTRY — anomaly detector
 * ================================================================ */

SEC("xdp")
int xdp_anomaly_detector(struct xdp_md *ctx)
{
    struct flow_key key     = {};
    __u64           pkt_len = 0;
    __u32           key_ac  = 0;

    accounting *ac = bpf_map_lookup_elem(&accounting_map, &key_ac);
    if (!ac)
        return XDP_PASS;

    ac->time_in = bpf_ktime_get_ns();

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);
    if (ret == -2) return XDP_DROP;   /* LLDP        */
    if (ret ==  1) return XDP_PASS;   /* ICMP whitelist */
    if (ret <   0) return XDP_PASS;

    ret = update_stats(&key, ctx);

    __u64 time_out  = bpf_ktime_get_ns();
    ac->proc_time  += time_out - ac->time_in;
    ac->total_bytes += pkt_len;
    ac->total_pkts  += 1;
    bpf_map_update_elem(&accounting_map, &key_ac, ac, BPF_ANY);

    if (ret == XDP_DROP)
        return XDP_DROP;

    return bpf_redirect(REDIRECT_INTERFACE, 0);
}


/* ================================================================
 * XDP ENTRY — stats only (mirror / second interface)
 * ================================================================ */

SEC("xdp")
int stats(struct xdp_md *ctx)
{
    struct flow_key key     = {};
    __u64           pkt_len = 0;
    __u32           key_ac  = 0;

    accounting *ac = bpf_map_lookup_elem(&accounting_map, &key_ac);
    if (!ac)
        return XDP_PASS;

    ac->time_in = bpf_ktime_get_ns();

    if (parse_packet_get_data(ctx, &key, &pkt_len) != 0)
        return XDP_PASS;

    __u64 time_out = bpf_ktime_get_ns();
    __sync_fetch_and_add(&ac->proc_time,   time_out - ac->time_in);
    __sync_fetch_and_add(&ac->total_pkts,  1);
    __sync_fetch_and_add(&ac->total_bytes, pkt_len);

    bpf_map_update_elem(&accounting_map, &key_ac, ac, BPF_ANY);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";