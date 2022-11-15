// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Baodong Chen */
#include <bpf/libbpf.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "syscallprofiler.skel.h"
#include "syscallprofiler.h"
#include "syscall_table/syscall_table.h"

static int __verbose = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

static void show_help(const char *progname)
{
    printf("Usage: %s [-p <pid> -c <syscall no> -n <syscall name>] [-v] [-h]\n",
           progname);
}

struct syscall_info_t {
    uint32_t syscall;
    uint64_t count;
};

static int __compare_syscall_info(const void *p1, const void *p2)
{
    const struct syscall_info_t *i1 = p1;
    const struct syscall_info_t *i2 = p2;
    if (i1->count > i2->count) return -1;
    if (i1->count < i2->count) return 1;
    return 0;
}

static size_t __collect_syscall_infos(const struct hist *hists,
                                      struct syscall_info_t *infos)
{
    size_t num = 0;
    for (uint32_t syscall = 0; syscall < MAX_SYSCALLS; ++syscall) {
        __u64 total = 0;
        for (int i = 0; i < MAX_SLOTS; ++i) {
            total += hists->slots[syscall][i];
        }
        if (total == 0) continue;
        infos[num].syscall = syscall;
        infos[num].count = total;
        num++;
    }
    qsort(infos, num, sizeof(struct syscall_info_t), __compare_syscall_info);
    return num;
}

static void __show_hist(const struct hist *hists, uint32_t syscall,
                        pid_t filter_pid)
{
    __u64 total = 0;
    for (int i = 0; i < MAX_SLOTS; ++i) {
        total += hists->slots[syscall][i];
    }
    if (total == 0) return;
    printf("\nprofiling syscall=%u(%s) for pid %d:\n\t\tMicro"
           "seconds\t : Count\n",
           syscall, syscall_name(syscall), filter_pid);
    for (int i = 0; i < MAX_SLOTS; ++i) {
        if (hists->slots[syscall][i] != 0) {
            printf("\t[%8llu\t%8llu]: %8llu (%.02f%%)\n",
                   (i == 0) ? 0 : (1ull << i), (1ull << (i + 1)) - 1,
                   hists->slots[syscall][i],
                   hists->slots[syscall][i] * 100.0 / total);
        }
    }
    printf("---------------------------------| Total=%llu\n", total);
}

int main(int argc, char **argv)
{
    struct syscallprofiler_bpf *skel;
    int err;
    int argp = 0;
    /* Profiling write() syscall from our process by default */
    uint32_t filter_syscall = SYS_write;
    int filter_pid = 0;
    uint32_t __flags = 0;

    while ((argp = getopt(argc, argv, "hvp:c:n:")) != -1) {
        switch (argp) {
        case 'p':
            filter_pid = atoi(optarg);
            break;
        case 'c':
            filter_syscall = (uint32_t)atoi(optarg);
            break;
        case 'n':
            filter_syscall = syscall_no(optarg);
            if (filter_syscall == UINT32_MAX) {
                fprintf(stderr, "Invalid syscall name '%s'\n", optarg);
                return 1;
            }
            break;
        case 'v':
            __verbose = 1;
            __flags |= FLAG_ENABLE_BPF_PRINTK;
            break;
        case 'h':
        default:
            show_help(argv[0]);
            return 1;
        }
    }
    if (filter_pid == 0) filter_pid = getpid();

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    if (__verbose) libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = syscallprofiler_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    /* Fill parameters for BPF program */
    skel->bss->filter_pid = filter_pid;         /* Process to profiling  */
    skel->bss->filter_syscall = filter_syscall; /* Syscall to profiling  */
    skel->bss->__flags = __flags;

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
        if (counter % 10 == 0) {
            uint32_t key = 0;
            struct hist hists;
            int r = bpf_map__lookup_elem(skel->maps.hists, &key, sizeof(key),
                                         &hists, sizeof(hists), 0);
            if (r != 0) {
                fprintf(stderr, "bpf_map__lookup_elem error, r=%d\n", r);
                goto cleanup;
            }
            if (filter_syscall != UINT32_MAX) {
                __show_hist(&hists, filter_syscall, filter_pid);
            } else {
                struct syscall_info_t infos[MAX_SYSCALLS];
                size_t num = __collect_syscall_infos(&hists, infos);
                for (size_t i = 0; i < num; ++i) {
                    uint32_t syscall = infos[i].syscall;
                    __show_hist(&hists, syscall, filter_pid);
                }
            }
        }
        counter++;
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    syscallprofiler_bpf__destroy(skel);
    return -err;
}
