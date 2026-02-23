/* SPDX-License-Identifier: GPL-2.0 */
static const char *__doc__ = "XDP loader\n"
	" - Allows selecting BPF program --progname name to XDP-attach to --dev\n";

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdlib.h>

#include <net/if.h>
#include <linux/if_link.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
// #include "xdp_sample.h"
#include "cmd_line.h"
#include "xdp_loader.h"

static const char *default_filename = "xdp_prog_kern.o";

static const struct option_wrapper long_options[] = {

	{{"help",        no_argument,		NULL, 'h' },
	 "Show help", false},

	{{"dev",         required_argument,	NULL, 'd' },
	 "Operate on device <ifname>", "<ifname>", true},

	{{"skb-mode",    no_argument,		NULL, 'S' },
	 "Install XDP program in SKB (AKA generic) mode"},

	{{"native-mode", no_argument,		NULL, 'N' },
	 "Install XDP program in native mode"},

	{{"auto-mode",   no_argument,		NULL, 'A' },
	 "Auto-detect SKB or native mode"},

	{{"force",       no_argument,		NULL, 'F' },
	 "Force install, replacing existing program on interface"},

	{{"unload",      no_argument,		NULL, 'U' },
	 "Unload XDP program instead of loading"},

	{{"quiet",       no_argument,		NULL, 'q' },
	 "Quiet mode (no output)"},

	{{"filename",    required_argument,	NULL,  1  },
	 "Load program from <file>", "<file>"},

	{{"progname",    required_argument,	NULL,  2  },
	 "Load program from function <name> in the ELF file", "<name>"},

	{{0, 0, NULL,  0 }, NULL, false}
};

#ifndef PATH_MAX
#define PATH_MAX	4096
#endif

const char *pin_basedir =  "/sys/fs/bpf";
const char *map_name    =  "xdp_flow_tracking";

int verbose = 1;

struct xdp_program *load_bpf_and_xdp_attach(struct config *cfg)
{
	int prog_fd = -1;
	int err;

	DECLARE_LIBBPF_OPTS(bpf_object_open_opts, opts);
	DECLARE_LIBXDP_OPTS(xdp_program_opts, xdp_opts, 0);

	xdp_opts.open_filename = cfg->filename;
	xdp_opts.prog_name = cfg->progname;
	xdp_opts.opts = &opts;
	struct xdp_program *prog = xdp_program__create(&xdp_opts);
	err = libxdp_get_error(prog);
	if (err) {
		char errmsg[1024];
		libxdp_strerror(err, errmsg, sizeof(errmsg));
		fprintf(stderr, "ERR: loading program: %s\n", errmsg);
		exit(EXIT_FAIL_BPF);
	}
	err = xdp_program__attach(prog, cfg->ifindex, cfg->attach_mode, 0);
	if (err)
		exit(err);

	prog_fd = xdp_program__fd(prog);
	if (prog_fd < 0) {
		fprintf(stderr, "ERR: xdp_program__fd failed: %s\n", strerror(errno));
		exit(EXIT_FAIL_BPF);
	}

	return prog;
}

int pin_maps_in_bpf_object(struct bpf_object *bpf_obj, const char *subdir){
    char map_filename[PATH_MAX];
	char pin_dir[PATH_MAX];
	int err, len;

    memset(pin_dir, 0, sizeof(pin_dir));
	len = snprintf(pin_dir, PATH_MAX, "%s/%s", pin_basedir, subdir);
	if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}

	len = snprintf(map_filename, PATH_MAX, "%s/%s/%s",
		       pin_basedir, subdir, map_name);
	if (len < 0) {
		fprintf(stderr, "ERR: creating map_name\n");
		return EXIT_FAIL_OPTION;
	}

	/* Existing/previous XDP prog might not have cleaned up */
	if (access(map_filename, F_OK ) != -1 ) {
		if (verbose)
			printf(" - Unpinning (remove) prev maps in %s/\n",
			       pin_dir);

		/* Basically calls unlink(3) on map_filename */
		err = bpf_object__unpin_maps(bpf_obj, pin_dir);
		if (err) {
			fprintf(stderr, "ERR: UNpinning maps in %s\n", pin_dir);
			return EXIT_FAIL_BPF;
		}
	}
	if (verbose)
		printf(" - Pinning maps in %s/\n", pin_dir);

	/* This will pin all maps in our bpf_object */
	err = bpf_object__pin_maps(bpf_obj, pin_dir);
	if (err)
		return EXIT_FAIL_BPF;

	return 0;
}

int remove_pin_dir(const char *path)
{
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "rm -rf %s", path);
    return system(cmd);
}

int main(int argc, char **argv){
    struct xdp_program * program;

    int err, len;
    struct config cfg = {
        .attach_mode = XDP_MODE_SKB,
        .ifindex     = -1,
        .do_unload   = false,
	};

    strncpy(cfg.filename, default_filename, sizeof(cfg.filename));
	parse_cmdline_args(argc, argv, long_options, &cfg, __doc__);

    if (cfg.ifindex == -1) {
		fprintf(stderr, "ERR: required option --dev missing\n\n");
		usage(argv[0], __doc__, long_options, (argc == 1));
		return EXIT_FAIL_OPTION;
	}

    char pin_dir[PATH_MAX];
	memset(pin_dir, 0, sizeof(pin_dir));
	len = snprintf(pin_dir, sizeof(pin_dir), "%s/%s", pin_basedir, cfg.ifname);

    if (len < 0) {
		fprintf(stderr, "ERR: creating pin dirname\n");
		return EXIT_FAIL_OPTION;
	}
	strncpy(cfg.pin_dir, pin_dir, sizeof(cfg.pin_dir) - 1);
	cfg.pin_dir[sizeof(cfg.pin_dir) - 1] = '\0';

    if (cfg.do_unload) {

        if (verbose)
            printf("Unloading XDP program on %s\n", cfg.ifname);

        err = bpf_xdp_detach(cfg.ifindex, cfg.attach_mode, NULL);
        if (err) {
            fprintf(stderr, "ERR: unloading XDP program: %s\n",
                    strerror(-err));
            return EXIT_FAIL_BPF;
        }

        if (verbose)
            printf("Success: XDP program detached from %s\n",
                cfg.ifname);
        remove_pin_dir(cfg.pin_dir);
		const char *xdp_path_dir = "/sys/fs/bpf/xdp";
		remove_pin_dir(xdp_path_dir);
        
        return EXIT_OK;
    }

	program = load_bpf_and_xdp_attach(&cfg);
	if (!program)
		return EXIT_FAIL_BPF;

	if (verbose) {
		printf("Success: Loaded BPF-object(%s) and used program(%s)\n",
		       cfg.filename, cfg.progname);
		printf(" - XDP prog attached on device:%s(ifindex:%d)\n",
		       cfg.ifname, cfg.ifindex);
	}

	/* Use the --dev name as subdir for exporting/pinning maps */
	err = pin_maps_in_bpf_object(xdp_program__bpf_obj(program), cfg.ifname);
	if (err) {
		fprintf(stderr, "ERR: pinning maps\n");
		return err;
	}

    if (len < 0) {
        fprintf(stderr, "ERR: creating pin dirname\n");
        return EXIT_FAIL_OPTION;
    }

    return EXIT_OK;
}