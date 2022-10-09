// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2022 Baodong Chen */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscallprofiler.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

pid_t filter_pid = 0;
__u32 filter_syscall = 0;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, __u64);
    __type(value, __u64);
    __uint(max_entries, 1024);
} clocks SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, __u32);
    __type(value, struct hist);
    __uint(max_entries, 1);
} hists SEC(".maps");

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 id = ctx->args[1];
    if (id != filter_syscall) return 0;

    __u64 pid = bpf_get_current_pid_tgid();
    if (filter_pid > 0 && (pid_t)(pid >> 32) != filter_pid) return 0;

    /**
     * https://github.com/DavadDi/bpf_study/blob/master/the-art-of-writing-ebpf-programs-a-primer/index.md
     * The System V ABI mandates the protocol for exchanging arguments
     * during a system call invocation between user and kernel, and the exchange
     * happens via CPU registers. In particular, the convention is:
     * User-level applications use as integer registers for passing the sequence
     *  %rdi, %rsi, %rdx, %rcx, %r8 and %r9.
     * The kernel interface uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.
     */
    struct pt_regs *regs = (struct pt_regs *)ctx->args[0];

    __u64 ts = bpf_ktime_get_ns();
    bpf_map_update_elem(&clocks, &pid, &ts, BPF_ANY);

    return 0;
}

static __always_inline __u64 log2(__u32 v)
{
    __u32 shift, r;

    r = (v > 0xFFFF) << 4;
    v >>= r;
    shift = (v > 0xFF) << 3;
    v >>= shift;
    r |= shift;
    shift = (v > 0xF) << 2;
    v >>= shift;
    r |= shift;
    shift = (v > 0x3) << 1;
    v >>= shift;
    r |= shift;
    r |= (v >> 1);

    return r;
}

static __always_inline __u64 log2l(__u64 v)
{
    __u32 hi = v >> 32;
    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

// File exists
#ifndef EEXIST
#define EEXIST 17
#endif

static __always_inline void *map_lookup_or_try_init(void *map, const void *key,
                                                    const void *init)
{
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key);
    if (val) return val;

    err = bpf_map_update_elem(map, key, init, BPF_NOEXIST);
    if (err && err != -EEXIST) return 0;

    return bpf_map_lookup_elem(map, key);
}

static __always_inline void *map_lookup_and_delete(void *map, const void *key)
{
    void *val = bpf_map_lookup_elem(map, key);
    if (val) bpf_map_delete_elem(map, key);
    return val;
}

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *args = (struct pt_regs *)ctx->args[0];
    __u64 id = BPF_CORE_READ(args, orig_ax);
    if (id != filter_syscall) return 0;

    __u64 pid = bpf_get_current_pid_tgid();
    if (filter_pid > 0 && (pid_t)(pid >> 32) != filter_pid) return 0;

    __u64 *tsp = map_lookup_and_delete(&clocks, &pid);
    if (!tsp) return 0;

    struct hist initial_hist = {};
    __u32 index = 0;
    struct hist *hp = map_lookup_or_try_init(&hists, &index, &initial_hist);
    if (!hp) return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000; /* micro-second */
    __u64 slot = log2l(delta);
    if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
    uint64_t counter = __sync_fetch_and_add(&hp->slots[slot], 1);
    if (counter % 10 == 0) {
        bpf_printk(
            "sys_exit: pid=%d filter_syscall=%u delta=%lu slots[%lu]=%lu\n",
            pid, filter_syscall, delta, slot, counter);
    }

    return 0;
}
