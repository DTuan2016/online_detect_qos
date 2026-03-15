// SPDX-License-Identifier: GPL-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>

SEC("tc")
int tc_dscp_classifier(struct __sk_buff *skb)
{
    bpf_printk("TC: Packet received on eth1\n");

    void *data     = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    /* Parse Ethernet */
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end){
	bpf_printk("TC: Drop - Eth header boundary\n");
        return TC_ACT_OK;
    }

    //__u16 proto = bpf_ntohs(eth->h_proto);
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        bpf_printk("TC: Skip - Not IPv4 (Proto: 0x%x)\n", eth->h_proto);
	return TC_ACT_OK;
    }
    /* Parse IPv4 */
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end){
	bpf_printk("TC: Drop - IP header boundary\n");
        return TC_ACT_OK;
    }

    /* Extract DSCP (first 6 bits of TOS) */
    __u8 dscp = ip->tos >> 2;

    /* Map DSCP to priority (0–7 typical) */
    __u32 classid = 0;

    if (dscp == 40)                             // VoIP
        classid = 0x10010;
    else if (dscp == 8 || dscp == 32)           // Streaming, Chat
        classid = 0x10020;
    else if (dscp == 0 || dscp == 48)           // Browsing, Mail
        classid = 0x10030;
    else                                        // FT, P2P
        classid = 0x10040;                              

    /* Set skb priority */
    skb->priority = classid;
    bpf_printk("TC Debug: DSCP=%u -> ClassID=0x%x\n", dscp, classid);

    return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
