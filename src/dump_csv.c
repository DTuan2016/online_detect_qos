// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "common_kern_user.h"

const char *pin_basedir = "/sys/fs/bpf";

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ================= CSV PRINT ================= */

static void print_flow_csv(FILE *f, const struct flow_key *key, const data_point *dp) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr saddr = { .s_addr = key->src_ip };
    struct in_addr daddr = { .s_addr = key->dst_ip };

    inet_ntop(AF_INET, &saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &daddr, dst_ip, sizeof(dst_ip));

    fprintf(f, "%s,%u,%s,%u,%u,%llu,%llu,%u,%u,%u,%u,%llu,%d\n",
        src_ip, key->src_port,
        dst_ip, key->dst_port,
        key->proto,
        (unsigned long long)dp->features[0],
	(unsigned long long)dp->sum_iat,
        dp->total_pkts,
        dp->min_len,
        dp->max_len,
        dp->sum_len,
        (unsigned long long)dp->mean_len,
        dp->label
    );
}

static void print_node_csv(FILE *f, __u32 key, const Node *node) {
    fprintf(f, "%u,%u,%d,%d,%u,%lld,%u,%d\n",
        key,                    // global index
        node->tree_idx,         // tree index
        node->left_idx,
        node->right_idx,
        node->feature_idx,
        (long long)node->split_value,
        node->is_leaf,
        node->label
    );
}

/* ================= DUMP FUNCTIONS ================= */

static void dump_flow_map_to_csv(int map_fd, FILE *f) {
    struct flow_key key = {}, next_key;
    data_point dp;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &dp) == 0) {
            print_flow_csv(f, &next_key, &dp);
        }
        key = next_key;
    }
    fflush(f);
}

static void dump_node_map_to_csv(int map_fd, FILE *f) {
    __u32 key = 0, next_key;
    Node node;

    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &node) == 0) {
            print_node_csv(f, next_key, &node);
        }
        key = next_key;
    }
    fflush(f);
}

/* ================= MAIN ================= */

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <ifname> <flows.csv> <nodes.csv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *flows_filename = argv[2];
    const char *nodes_filename = argv[3];

    char pin_dir[PATH_MAX];
    snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);

    /* ================= OPEN FLOW MAP ================= */
    char flow_map_path[PATH_MAX];
    snprintf(flow_map_path, PATH_MAX, "%s/%s", pin_dir, "xdp_flow_tracking");

    int flow_fd = bpf_obj_get(flow_map_path);
    if (flow_fd < 0) {
        perror("bpf_obj_get flow");
        return EXIT_FAILURE;
    }

    /* ================= OPEN NODE MAP ================= */
    char node_map_path[PATH_MAX];
    snprintf(node_map_path, PATH_MAX, "%s/%s", pin_dir, "xdp_randforest_nodes");

    int node_fd = bpf_obj_get(node_map_path);
    if (node_fd < 0) {
        perror("bpf_obj_get nodes");
        return EXIT_FAILURE;
    }

    /* ================= OPEN FILES ================= */
    FILE *f_flows = fopen(flows_filename, "w");
    if (!f_flows) {
        perror("fopen flows");
        return EXIT_FAILURE;
    }

    FILE *f_nodes = fopen(nodes_filename, "w");
    if (!f_nodes) {
        perror("fopen nodes");
        return EXIT_FAILURE;
    }

    /* ================= HEADERS ================= */
    fprintf(f_flows,
        "SrcIP,SrcPort,DstIP,DstPort,Proto,CurrentLength,SumIat,TotalPkts,MinLen,MaxLen,SumLen,MeanLen,Label\n");

    fprintf(f_nodes,
        "NodeIdx,TreeIdx,Left,Right,FeatureIdx,SplitValue,IsLeaf,Label\n");

    /* ================= DUMP ================= */
    dump_flow_map_to_csv(flow_fd, f_flows);
    dump_node_map_to_csv(node_fd, f_nodes);

    fclose(f_flows);
    fclose(f_nodes);

    printf("Dumped:\n");
    printf("  Flows -> %s\n", flows_filename);
    printf("  Nodes -> %s\n", nodes_filename);

    return EXIT_SUCCESS;
}
