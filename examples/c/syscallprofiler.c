// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Baodong Chen */
#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "syscallprofiler.skel.h"
#include "syscallprofiler.h"
#ifdef __x86_64__
#include "syscall_table/x86_64/syscall_table.h"
#endif

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

static void show_help(const char *progname)
{
    printf("Usage: %s [-p <pid> -c <syscall>] [-h]\n", progname);
}

int main(int argc, char **argv)
{
    struct syscallprofiler_bpf *skel;
    int err;
    int argp = 0;
    int filter_pid = -1;
    /* Profiling write() syscall from our process by default */
    uint32_t filter_syscall = SYS_write;

    while ((argp = getopt(argc, argv, "hp:c:")) != -1) {
        switch (argp) {
        case 'p':
            filter_pid = atoi(optarg);
            break;
        case 'c':
            filter_syscall = (uint32_t)atoi(optarg);
            break;
        case 'h':
        default:
            show_help(argv[0]);
            return 1;
        }
    }
    if (filter_pid <= 0) filter_pid = getpid();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = syscallprofiler_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    /* Fill parameters for BPF program */
    skel->bss->filter_pid = filter_pid;         /* Process to profiling  */
    skel->bss->filter_syscall = filter_syscall; /* Syscall to profiling  */

    /* Load & verify BPF programs */
    err = syscallprofiler_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = syscallprofiler_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    uint32_t counter = 0;
    for (;;) {
        /* trigger our BPF program */
        fprintf(stderr, ".");
        if (counter % 10 == 0) {
            uint32_t key = 0;
            struct hist hists;
            int r = bpf_map__lookup_elem(skel->maps.hists, &key, sizeof(key),
                                         &hists, sizeof(hists), 0);
            if (r == 0) {
                printf("\nprofiling syscall=%u(%s) for pid %d:\n\t\tMicro"
                       "seconds\t : Count\n",
                       filter_syscall, syscall_name(filter_syscall),
                       filter_pid);
                __u64 total = 0;
                for (int i = 0; i < MAX_SLOTS; ++i) {
                    total += hists.slots[i];
                }
                for (int i = 0; i < MAX_SLOTS; ++i) {
                    if (hists.slots[i] != 0) {
                        printf("\t[%8llu\t%8llu]: %8llu (%.02f%%)\n",
                               (i == 0) ? 0 : (1ull << i),
                               (1ull << (i + 1)) - 1, hists.slots[i],
                               hists.slots[i] * 100.0 / total);
                    }
                }
                printf("---------------------------------| Total=%llu\n",
                       total);
            }
        }
        counter++;
        sleep(1);
    }

cleanup:
    syscallprofiler_bpf__destroy(skel);
    return -err;
}
