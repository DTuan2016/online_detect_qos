// SPDX-License-Identifier: GPL-2.0
//
// xdp_dump.c — Dump xdp_flow_tracking map to CSV
//
// Usage: ./xdp_dump <ifname> <output.csv>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "common_kern_user.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

static void print_flow_csv(FILE *f,
                           const struct flow_key *key,
                           const data_point *dp)
{
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr saddr = { .s_addr = key->src_ip };
    struct in_addr daddr = { .s_addr = key->dst_ip };

    inet_ntop(AF_INET, &saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &daddr, dst_ip, sizeof(dst_ip));

    fprintf(f,
        "%s,%u,%s,%u,%u,"       /* src_ip, src_port, dst_ip, dst_port, proto */
        "%llu,%llu,"            /* features[CUR_LEN], sum_iat                */
        "%llu,%llu,"            /* total_pkts, total_bytes                   */
        "%u,%u,%llu,%llu,"      /* min_len, max_len, sum_len, mean_len       */
        "%d\n",                 /* label                                     */
        src_ip, key->src_port,
        dst_ip, key->dst_port,
        (unsigned int)key->proto,
        (unsigned long long)dp->features[FEATURE_CUR_LEN],
        (unsigned long long)dp->sum_iat,
        (unsigned long long)dp->total_pkts,
        (unsigned long long)dp->total_bytes,
        dp->min_len, dp->max_len,
        (unsigned long long)dp->sum_len,
        (unsigned long long)dp->mean_len,
        dp->label
    );
}

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <output.csv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname  = argv[1];
    const char *outfile = argv[2];

    /* Open pinned map */
    char map_path[PATH_MAX];
    snprintf(map_path, PATH_MAX, "/sys/fs/bpf/%s/xdp_flow_tracking", ifname);

    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "bpf_obj_get(%s): %s\n", map_path, strerror(errno));
        return EXIT_FAILURE;
    }

    /* Open output file */
    FILE *f = fopen(outfile, "w");
    if (!f) {
        fprintf(stderr, "fopen(%s): %s\n", outfile, strerror(errno));
        return EXIT_FAILURE;
    }

    /* CSV header */
    fprintf(f,
        "SrcIP,SrcPort,DstIP,DstPort,Proto,"
        "CurLen,SumIat,"
        "TotalPkts,TotalBytes,"
        "MinLen,MaxLen,SumLen,MeanLen,"
        "Label\n"
    );

    /* Iterate map */
    struct flow_key key = {}, next_key;
    data_point dp;
    unsigned long count = 0;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &dp) == 0) {
            print_flow_csv(f, &next_key, &dp);
            count++;
        }
        key = next_key;
    }

    fflush(f);
    fclose(f);

    printf("[DUMP] %lu flows → %s\n", count, outfile);
    return EXIT_SUCCESS;
}