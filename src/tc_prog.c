// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_dscp_classifier(struct __sk_buff *skb)
{
    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return TC_ACT_OK;

    /* Parse IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;

    /* Extract DSCP (first 6 bits of TOS) */
    __u8 dscp = ip->tos >> 2;

    /* Map DSCP to priority (0–7 typical) */
    __u32 prio = 0;

    if (dscp == 40)                             // VoIP
        prio = 3;
    else if (dscp == 8 || dscp == 32)           // Streaming, Chat
        prio = 2;
    else if (dscp == 0 || dscp == 48)           // Browsing, Mail
        prio = 1;
    else                                        // FT, P2P
        prio = 0;                              

    /* Set skb priority */
    skb->priority = prio;

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";