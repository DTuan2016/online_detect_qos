#ifndef XDP_LOADER_H
#define XDP_LOADER_H
#include <getopt.h>

#include <errno.h>
#include <linux/if_link.h>
#include <linux/magic.h>

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <xdp/libxdp.h>
#include <xdp/prog_dispatcher.h>

#include <linux/types.h>
#include <net/if.h>
#include <stdbool.h>
#include <xdp/libxdp.h>

struct xdp_program {
  /* one of prog or prog_fd should be set */
  struct bpf_program  *bpf_prog;
  struct bpf_object   *bpf_obj;
  struct btf          *btf;
  enum bpf_prog_type  prog_type;
  int     prog_fd;
  int     link_fd;
  char    *prog_name;
  char    *attach_name;
  __u8    prog_tag[BPF_TAG_SIZE];
  __u32   prog_id;
  __u64   load_time;
  bool    from_external_obj;
  bool    is_frags;
  unsigned int run_prio;
  unsigned int chain_call_actions; /* bitmap */

  /* for building list of attached programs to multiprog */
  struct xdp_program *next;
};

#endif // XDP_LOADER_H