// SPDX-License-Identifier: GPL-2.0
// #include "vmlinux.h"
#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/icmp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <stdbool.h>

#include "common_kern_user.h"

#define ETH_P_IP        0x0800
#define NANOSEC_PER_SEC 1000000000ULL

#ifndef lock_xadd
#define lock_xadd(ptr, val) ((void)__sync_fetch_and_add((ptr), (val)))
#endif

/* ================= EVENT STRUCT ================= */
/* Cấu trúc event đẩy lên userspace qua perf_event */
struct event {
    __u64 ts;
    struct flow_key key;
    __u64 total_pkts; /* Sẽ là 8, 12, 16, 18, 24, hoặc 32 */
    __u64 features[MAX_FEATURES];
};

/* ================= MAPS ================= */
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u32));
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key,   struct flow_key);
    __type(value, data_point);
    __uint(max_entries, MAX_FLOW_SAVED);
} xdp_flow_tracking SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key,   __u32);
    __type(value, accounting);
    __uint(max_entries, 1);
} accounting_map SEC(".maps");

/* ================= PACKET PARSING ================= */

static __always_inline int parse_packet_get_data(struct xdp_md *ctx,
                                                 struct flow_key *key,
                                                 __u64 *pkt_len)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    /* --- Ethernet --- */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return -1;

    if (eth->h_proto == bpf_htons(0x88cc))
        return -2;  /* drop LLDP */

    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return -1;

    /* --- IPv4 --- */
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
        return -1;

    key->src_ip = iph->saddr;
    key->dst_ip = iph->daddr;
    key->proto  = iph->protocol;

    /* --- Transport --- */
    if (iph->protocol == IPPROTO_ICMP) {
        struct icmphdr *icmp = (struct icmphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(icmp + 1) > data_end)
            return -1;
        key->src_port = 0;
        key->dst_port = 0;

    } else if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = (struct tcphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(tcph + 1) > data_end)
            return -1;

        /* Bỏ qua DNS */
        if (tcph->source == bpf_htons(53) || tcph->dest == bpf_htons(53))
            return -1;

        key->src_port = bpf_ntohs(tcph->source);
        key->dst_port = bpf_ntohs(tcph->dest);

    } else if (iph->protocol == IPPROTO_UDP) {
        struct udphdr *udph = (struct udphdr *)((__u8 *)iph + (iph->ihl * 4));
        if ((void *)(udph + 1) > data_end)
            return -1;

        /* Bỏ qua DNS */
        if (udph->source == bpf_htons(53) || udph->dest == bpf_htons(53))
            return -1;

        key->src_port = bpf_ntohs(udph->source);
        key->dst_port = bpf_ntohs(udph->dest);

    } else {
        key->src_port = 0;
        key->dst_port = 0;
    }

    *pkt_len = (__u64)((__u8 *)data_end - (__u8 *)data);
    return 0;
}

/* ================= UPDATE STATS & DETECTION ================= */

static __always_inline int update_stats(struct flow_key *key,
                                        struct xdp_md   *ctx,
                                        accounting      *ac)
{
    __u64 ts_ns  = bpf_ktime_get_ns();
    __u64 pkt_len = (__u64)((__u8 *)(long)ctx->data_end -
                             (__u8 *)(long)ctx->data);

    int status = 0;
    data_point *dp = bpf_map_lookup_elem(&xdp_flow_tracking, key);

    /* --- Luồng MỚI --- */
    if (!dp) {
        data_point zero = {};

        zero.start_ts    = ts_ns;
        zero.last_seen   = ts_ns;
        zero.total_pkts  = 1;
        zero.total_bytes = pkt_len;
        zero.sum_iat     = 0;

        zero.min_len  = pkt_len;
        zero.max_len  = pkt_len;
        zero.sum_len  = pkt_len;
        zero.mean_len = pkt_len << FIXED_SHIFT;

        zero.label      = -1;
        zero.classified = 0;

        /* Khởi tạo features đầu tiên */
        zero.features[FEATURE_CUR_LEN]  = fixed_from_uint(pkt_len);
        zero.features[FEATURE_SUM_IAT]  = 0;
        zero.features[FEATURE_MIN_LEN]  = fixed_from_uint(pkt_len);
        zero.features[FEATURE_MAX_LEN]  = fixed_from_uint(pkt_len);
        zero.features[FEATURE_SUM_LEN]  = fixed_from_uint(pkt_len);
        zero.features[FEATURE_MEAN_LEN] = zero.mean_len;

        int ret = bpf_map_update_elem(&xdp_flow_tracking, key, &zero, BPF_ANY);
        if (ret == 0)
            __sync_fetch_and_add(&ac->flow_created, 1);

        return XDP_PASS;
    }

    /* --- Luồng ĐÃ TỒN TẠI --- */

    /* Cập nhật số gói / bytes */
    __sync_fetch_and_add(&dp->total_pkts, 1);
    __u64 new_total_pkts = dp->total_pkts;

    __sync_fetch_and_add(&dp->total_bytes, pkt_len);

    /* Inter-Arrival Time */
    if (ts_ns >= dp->last_seen) {
        __u64 iat_ns = ts_ns - dp->last_seen;
        if (iat_ns > 0)
            dp->sum_iat += iat_ns;
    }

    /* Độ dài gói */
    if (pkt_len < dp->min_len) dp->min_len = pkt_len;
    if (pkt_len > dp->max_len) dp->max_len = pkt_len;
    dp->sum_len  += pkt_len;
    dp->mean_len  = (dp->sum_len << FIXED_SHIFT) / new_total_pkts;

    dp->last_seen = ts_ns;

    /* Cập nhật feature array hiện tại */
    dp->features[FEATURE_CUR_LEN]  = fixed_from_uint(pkt_len);
    dp->features[FEATURE_SUM_IAT]  = (dp->sum_iat << FIXED_SHIFT) / NANOSEC_PER_SEC;
    dp->features[FEATURE_MIN_LEN]  = fixed_from_uint(dp->min_len);
    dp->features[FEATURE_MAX_LEN]  = fixed_from_uint(dp->max_len);
    dp->features[FEATURE_SUM_LEN]  = fixed_from_uint(dp->sum_len);
    dp->features[FEATURE_MEAN_LEN] = dp->mean_len;

    /* -------------------------------------------------------
     * SNAPSHOT & DETECTION LOGIC
     * Bắt chính xác tại các mốc: 8, 12, 16, 18, 24, 32
     * ------------------------------------------------------- */
    bool trigger_event = false;

    /* Dùng unroll để Verifier cho phép duyệt qua mảng SNAPSHOT_AT */
    #pragma unroll
    for (int i = 0; i < NUM_SNAPSHOTS; i++) {
        if (new_total_pkts == SNAPSHOT_AT[i]) {
            trigger_event = true;

            #pragma unroll
            for (int j = 0; j < MAX_FEATURES; j++) {
                dp->snapshots.features[i][j] = dp->features[j];
            }
            dp->snapshots.captured |= (1 << i);
            break;
        }
    }

    if (trigger_event) {
        struct event evt = {};
        evt.ts         = ts_ns;
        evt.key        = *key;
        evt.total_pkts = new_total_pkts;

        #pragma unroll
        for (int i = 0; i < MAX_FEATURES; i++) {
            evt.features[i] = dp->features[i];
        }

        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU,
                              &evt, sizeof(evt));
        status = 1;
    }

    if (new_total_pkts > SNAPSHOT_AT[NUM_SNAPSHOTS - 1] && dp->classified == 1)
        status = 2;

    return status;
}

/* ================= XDP ENTRY POINT ================= */

SEC("xdp")
int classification(struct xdp_md *ctx)
{
    struct flow_key key    = {};
    __u64           pkt_len = 0;
    __u32           key_ac  = 0;

    accounting *ac = bpf_map_lookup_elem(&accounting_map, &key_ac);
    if (!ac)
        return XDP_PASS;

    ac->time_in = bpf_ktime_get_ns();

    int ret = parse_packet_get_data(ctx, &key, &pkt_len);

    if (ret == -2)
        return XDP_DROP;

    if (ret < 0)
        return XDP_PASS;

    int status = update_stats(&key, ctx, ac);

    __u64 done_ts   = bpf_ktime_get_ns();
    ac->proc_time  += done_ts - ac->time_in;
    ac->total_bytes += pkt_len;
    ac->total_pkts  += 1;

    return XDP_PASS; 
}

char LICENSE[] SEC("license") = "GPL";
