// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Hengqi Chen */
#include <signal.h>
#include <unistd.h>
#include <malloc.h>
#include <linux/limits.h>
#include "usdtmem.skel.h"

static volatile sig_atomic_t exiting;

static void sig_int(int signo) { exiting = 1; }

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

static void usdtmem_trigger() { mallopt(M_CHECK_ACTION, 0x07); }

static void show_help(const char *progname)
{
    printf("Usage: %s [-p <pid> ] [-h]\n", progname);
}

int main(int argc, char **argv)
{
    struct usdtmem_bpf *skel;
    int err;
    int argp = 0;
    int filter_pid = -1;

    while ((argp = getopt(argc, argv, "hp:c:")) != -1) {
        switch (argp) {
        case 'p':
            filter_pid = atoi(optarg);
            break;
        case 'h':
        default:
            show_help(argv[0]);
            return 1;
        }
    }
    if (filter_pid <= 0) filter_pid = getpid();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    libbpf_set_print(libbpf_print_fn);

    skel = usdtmem_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    skel->bss->my_pid = filter_pid;

    err = usdtmem_bpf__load(skel);
    if (!skel) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        return 1;
    }
    /*
     * Auto attach by libbpf, libbpf should be able to find libc.so in your
     * system. By default, auto attach does NOT specify pid, so we do pid
     * filtering in BPF program
     */
    err = usdtmem_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        err = errno;
        fprintf(stderr, "can't set signal handler: %s\n", strerror(errno));
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    while (!exiting) {
        /* trigger our BPF programs */
        usdtmem_trigger();
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    usdtmem_bpf__destroy(skel);
    return -err;
}
