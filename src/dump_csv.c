// SPDX-License-Identifier: GPL-2.0
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "common_kern_user.h"

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

const char *pin_basedir = "/sys/fs/bpf";

/* ================= CSV PRINT ================= */

static void print_flow_csv(FILE *f,
                           const struct flow_key *key,
                           const data_point *dp)
{
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];

    struct in_addr saddr = { .s_addr = key->src_ip };
    struct in_addr daddr = { .s_addr = key->dst_ip };

    inet_ntop(AF_INET, &saddr, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &daddr, dst_ip, sizeof(dst_ip));

    /* 1. In thông tin cơ bản của flow */
    fprintf(f, "%s,%u,%s,%u,%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%d,%u,%u",
            src_ip,
            key->src_port,
            dst_ip,
            key->dst_port,
            key->proto,
            dp->total_pkts,
            dp->total_bytes,
            dp->sum_iat,
            dp->min_len,
            dp->max_len,
            dp->sum_len,
            dp->mean_len >> 16,  /* Giải mã Q16 cho giá trị trung bình gốc */
            dp->label,
            dp->classified,
            dp->snapshots.captured
    );

    /* 2. In Features hiện tại (CurFeat) - Giải mã từ Q16 */
    for (int i = 0; i < MAX_FEATURES; i++) {
        fprintf(f, ",%llu", dp->features[i] >> 16);
    }

    /* 3. In Snapshots (Áp dụng Forward Fill / Padding nếu chưa đạt mốc) */
    for (int s = 0; s < NUM_SNAPSHOTS; s++) {
        // Kiểm tra xem mốc snapshot thứ s đã được chụp ở Kernel chưa
        int is_captured = dp->snapshots.captured & (1 << s);
        
        for (int i = 0; i < MAX_FEATURES; i++) {
            if (is_captured) {
                /* Nếu đã đạt mốc: Ghi nhận đặc trưng đã được đóng băng tại mốc đó */
                fprintf(f, ",%llu", dp->snapshots.features[s][i] >> 16);
            } else {
                /* LOGIC ĐẮP DỮ LIỆU: Nếu chưa đạt mốc, lấy luôn đặc trưng hiện tại 
                   (CurFeat) thế chỗ vào để vector dữ liệu không bị khuyết ô trống */
                fprintf(f, ",%llu", dp->features[i] >> 16); 
            }
        }
    }
    
    fprintf(f, "\n");
}

/* ================= DUMP MAP ================= */

static void dump_flow_map_to_csv(int map_fd, FILE *f)
{
    struct flow_key key;
    struct flow_key next_key;
    data_point dp;

    int ret;

    /* Lấy key đầu tiên trong bảng băm LRU */
    ret = bpf_map_get_next_key(map_fd, NULL, &key);
    if (ret < 0)
        return;

    while (1) {
        if (bpf_map_lookup_elem(map_fd, &key, &dp) == 0) {
            print_flow_csv(f, &key, &dp);
        }

        ret = bpf_map_get_next_key(map_fd, &key, &next_key);
        if (ret < 0)
            break;

        key = next_key;
    }

    fflush(f);
}

/* ================= MAIN ================= */

int main(int argc, char **argv)
{
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <ifname> <flows_out.csv>\n", argv[0]);
        return EXIT_FAILURE;
    }

    const char *ifname = argv[1];
    const char *flows_filename = argv[2];

    char pin_dir[PATH_MAX];
    char map_path[PATH_MAX];

    /* Tạo đường dẫn pin_dir an toàn */
    int ret = snprintf(pin_dir, sizeof(pin_dir),
                       "%s/%s", pin_basedir, ifname);
    if (ret < 0 || ret >= (int)sizeof(pin_dir)) {
        fprintf(stderr, "pin_dir too long\n");
        return EXIT_FAILURE;
    }

    /* Tạo đường dẫn map an toàn */
    ret = snprintf(map_path, sizeof(map_path),
                   "%s/%s", pin_dir, "xdp_flow_tracking");
    if (ret < 0 || ret >= (int)sizeof(map_path)) {
        fprintf(stderr, "map_path too long\n");
        return EXIT_FAILURE;
    }

    /* Lấy file descriptor của BPF Map */
    int map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        perror("bpf_obj_get");
        fprintf(stderr, "ERR: cannot open map %s\n", map_path);
        return EXIT_FAILURE;
    }

    FILE *f = fopen(flows_filename, "w");
    if (!f) {
        perror("fopen");
        return EXIT_FAILURE;
    }

    /* ---------------------------------------------------------
     * DYNAMIC CSV HEADER
     * Tự động tạo tiêu đề cột tương thích hoàn toàn với dữ liệu xuất
     * --------------------------------------------------------- */
    fprintf(f, "SrcIP,SrcPort,DstIP,DstPort,Proto,TotalPkts,TotalBytes,SumIAT,MinLen,MaxLen,SumLen,MeanLen,Label,Classified,CapturedMask");

    // Tạo Header cho các cột tính năng hiện tại
    for (int i = 0; i < MAX_FEATURES; i++) {
        fprintf(f, ",CurFeat_%d", i);
    }

    // Tạo Header cho các cột tính năng tại các mốc Snapshot cố định
    int snap_pkts[] = {8, 12, 16, 18, 24, 32};
    for (int s = 0; s < NUM_SNAPSHOTS; s++) {
        for (int i = 0; i < MAX_FEATURES; i++) {
            fprintf(f, ",Snap%d_Feat%d", snap_pkts[s], i);
        }
    }
    fprintf(f, "\n");

    /* Tiến hành đọc map và ghi dữ liệu ra file CSV */
    dump_flow_map_to_csv(map_fd, f);

    fclose(f);

    printf("Dumped xdp_flow_tracking -> %s (with Forward-Fill Padding)\n", flows_filename);

    return EXIT_SUCCESS;
}
