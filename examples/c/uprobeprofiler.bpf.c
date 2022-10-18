// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Baodong Chen */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "uprobeprofiler.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

uint32_t __flags = 0;

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

typedef __u64 stack_trace_t[MAX_STACK_DEPTH];

struct {
    __uint(type, BPF_MAP_TYPE_STACK_TRACE);
    __uint(max_entries, MAX_STACK_NUM);
    __type(key, __u32);
    __type(value, stack_trace_t);
} stackmap SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_STACK_NUM);
    __type(key, __u32);
    __type(value, __u64);
} countsmap SEC(".maps");

static __always_inline __u32 collect_userstack_trace(struct pt_regs *ctx)
{
    __u32 stackid = bpf_get_stackid(ctx, &stackmap,
                                    BPF_F_USER_STACK | BPF_F_FAST_STACK_CMP);
    if ((int)stackid < 0) {
        bpf_printk("bpf_get_stackid error, stackid=%d\n", stackid);
    }
    return stackid;
}

SEC("uprobe")
int BPF_KPROBE(uprobeprofiler)
{
    __u64 pid = bpf_get_current_pid_tgid();
    if (__flags & FLAG_ENABLE_BPF_PRINTK) {
        bpf_printk("uprobe: parm=(%lx %lx %lx %lx %lx)", PT_REGS_PARM1(ctx),
                   PT_REGS_PARM2(ctx), PT_REGS_PARM3(ctx), PT_REGS_PARM4(ctx),
                   PT_REGS_PARM5(ctx));
    }
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

static __always_inline void reflesh_peek(struct hist *hp, __u64 delta,
                                         __u32 stackid)
{
    size_t i, j;
    for (i = 0; i < ARRAY_SIZE(hp->peek); ++i) {
        if (delta >= hp->peek[i].delta) {
            break;
        }
    }
    if (i == ARRAY_SIZE(hp->peek)) return;
    for (j = ARRAY_SIZE(hp->peek) - 1; j > i; --j) {
        hp->peek[j] = hp->peek[j - 1];
    }
    hp->peek[i].delta = delta;
    hp->peek[i].stackid = stackid;
}

SEC("uretprobe")
int BPF_KRETPROBE(uretprobeprofiler)
{
    __u64 pid = bpf_get_current_pid_tgid();
    __u64 *tsp = map_lookup_and_delete(&clocks, &pid);
    if (!tsp) return 0;

    __u32 userstack = -1;
    if (__flags & FLAG_COLLECT_USER_STACK) {
        userstack = collect_userstack_trace(ctx);
        if ((int)userstack >= 0) {
            __u64 *val = bpf_map_lookup_elem(&countsmap, &userstack);
            if (val) {
                (*val)++;
            } else {
                __u64 one = 1;
                bpf_map_update_elem(&countsmap, &userstack, &one, BPF_NOEXIST);
            }
        }
    }

    struct hist initial_hist = {};
    __u32 index = 0;
    struct hist *hp = map_lookup_or_try_init(&hists, &index, &initial_hist);
    if (!hp) return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000; /* micro-second */
    reflesh_peek(hp, delta, userstack);
    __u64 slot = log2l(delta);
    if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
    uint64_t counter = __sync_fetch_and_add(&hp->slots[slot], 1);
    if (__flags & FLAG_ENABLE_BPF_PRINTK) {
        bpf_printk("uretprobe: stackid=%u delta=%lu slots[%lu]=%lu ret=%lx\n",
                   userstack, delta, slot, counter, PT_REGS_RC(ctx));
    }

    return 0;
}
