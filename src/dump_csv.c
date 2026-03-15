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

int open_bpf_map_file(const char *pin_dir,
                      const char *mapname,
                      struct bpf_map_info *info);

const char *pin_basedir = "/sys/fs/bpf";
#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/* ================= CSV PRINT ================= */
// static void print_node_csv(FILE *f, __u32 key, const Node *node) {
//     fprintf(f, "%u,%d,%d,%d,%d,%lld,%d,%d,%d\n",
//             key,
//             node->tree_idx,
//             node->left_idx,
//             node->right_idx,
//             node->feature_idx,
//             node->split_value,
//             node->is_leaf,
//             node->label,
//             0);
// }

static void print_flow_csv(FILE *f, const struct flow_key *key, const data_point *dp) {
    char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
    struct in_addr saddr = { .s_addr = key->src_ip };
    struct in_addr daddr = { .s_addr = key->dst_ip };

    inet_ntop(AF_INET, &saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &daddr, dst_ip, sizeof(dst_ip));

    fprintf(f, "%s,%u,%s,%u,%u,%u,%llu,%llu,%llu,%llu,%u,%u,%u,%u,%d\n",
        src_ip,
        key->src_port,
        dst_ip,
        key->dst_port,
        key->proto,
	dp->total_pkts,
	dp->min_iat,
	dp->max_iat,
	dp->sum_iat,
	dp->mean_iat,
	dp->min_len,
	dp->max_len,
	dp->sum_len,
	dp->mean_len,
        dp->label
    );
}

/* ================= DUMP MAPS ================= */
// static void dump_nodes_to_csv(int map_fd, FILE *f) {
//     __u32 key = 0, next_key;
//     Node node;

//     while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
//         if (bpf_map_lookup_elem(map_fd, &next_key, &node) == 0) {
//             print_node_csv(f, next_key, &node);
//         }
//         key = next_key;
//     }
//     fflush(f);
// }

static void dump_flow_map_to_csv(int map_fd, FILE *f) {
    struct flow_key key, next_key;
    data_point dp;

    memset(&key, 0, sizeof(key));
    while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &dp) == 0) {
            print_flow_csv(f, &next_key, &dp);
        }
        key = next_key;
    }
    fflush(f);
}

/* ================= MAIN ================= */
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <flows_out.csv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *flows_filename = argv[2];

    struct bpf_map_info info = {0};
    char pin_dir[PATH_MAX];
    snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, ifname);

    char map_path[PATH_MAX];
    snprintf(map_path, PATH_MAX, "%s/%s", pin_dir, "xdp_flow_tracking");

    int map_fd_flows = bpf_obj_get(map_path);
    if (map_fd_flows < 0) {
        perror("bpf_obj_get");
        fprintf(stderr, "ERR: cannot open map %s\n", map_path);
        return EXIT_FAILURE;
    }
    FILE *f_flows = fopen(flows_filename, "w");
    if (!f_flows) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    /* Header CSV */
    fprintf(f_flows, "SrcIP,SrcPort,DstIP,DstPort,Proto,TotalPkts,MinIat,MaxIat,SumIat,MeanIat,MinLen,MaxLen,SumLen,MeanLen,Label\n");

    dump_flow_map_to_csv(map_fd_flows, f_flows);

    fclose(f_flows);

    printf("Dumped xdp_flow_tracking -> %s\n", flows_filename);

    return EXIT_SUCCESS;
}
