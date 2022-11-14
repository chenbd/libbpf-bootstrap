// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2022 Baodong Chen */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "syscallprofiler.h"
#include "syscall_table/syscall_id.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

pid_t filter_pid = 0;
__u32 filter_syscall = 0;
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

static struct hist initial_hist = {0};
struct timespec;

static inline void sys_enter_write(int fd, const void *buf, size_t _count)
{
    size_t count = _count;
    uint8_t _buf[16] = {0};
    char tmp[56] = {0};
    if (count > sizeof(_buf)) count = sizeof(_buf);
    bpf_core_read_user(_buf, count, buf);
    size_t index = 0;
    for (size_t i = 0; i < count; ++i) {
        long r = BPF_SNPRINTF(&tmp[index], sizeof(tmp) - index, "%x ", _buf[i]);
        if (r < 0) break;
        if (r == 3) {
            index += 2;
        } else {
            index += 3;
        }
    }
    bpf_printk("sys_enter_write: fd=%d count=%lu buf=%s %s", fd, _count, tmp,
               _count != count ? "..." : "");
}

static inline void sys_enter_clock_nanosleep(clockid_t clockid, int flags,
                                             const struct timespec *request,
                                             struct timespec *remain)
{
    const struct __kernel_timespec *r = (struct __kernel_timespec *)request;
    long tv_sec = BPF_CORE_READ_USER(r, tv_sec);
    long tv_nsec = BPF_CORE_READ_USER(r, tv_nsec);
    bpf_printk(
        "sys_enter_clock_nanosleep: clockid=%d flag=%d tv_sec=%lu tv_nsec=%lu",
        clockid, flags, tv_sec, tv_nsec);
}

static void sys_enter_bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
    bpf_printk("sys_enter_bpf: cmd=%d size=%u", cmd, size);
    if (cmd >= BPF_MAP_LOOKUP_ELEM && cmd <= BPF_MAP_GET_NEXT_KEY) {
        __u32 map_fd = BPF_CORE_READ_USER(attr, map_fd);
        __u64 key = BPF_CORE_READ_USER(attr, key);
        bpf_printk("sys_enter_bpf: map_fd=%d key=%lx", map_fd, key);
    }
}

static inline void __syscall_enter_func(__u64 id, __u64 di, __u64 si, __u64 dx,
                                        __u64 r10, __u64 r8, __u64 r9)
{
    switch (id) {
    case __NR_write: {
        sys_enter_write(di, (void *)si, dx);
    } break;
    case __NR_clock_nanosleep: {
        sys_enter_clock_nanosleep(di, si, (const struct timespec *)dx,
                                  (struct timespec *)r10);
    } break;
    case __NR_bpf: {
        sys_enter_bpf(di, (union bpf_attr *)si, dx);
    } break;
    default:
        break;
    }
}

SEC("raw_tracepoint/sys_enter")
int sys_enter(struct bpf_raw_tracepoint_args *ctx)
{
    __u64 id = ctx->args[1];
    if (filter_syscall != -1 && id != filter_syscall) return 0;

    __u64 pid = bpf_get_current_pid_tgid();
    if (filter_pid > 0 && (pid_t)(pid >> 32) != filter_pid) return 0;

    /**
     * https://github.com/DavadDi/bpf_study/blob/master/the-art-of-writing-ebpf-programs-a-primer/index.md
     * The System V ABI mandates the protocol for exchanging arguments
     * during a system call invocation between user and kernel, and the
     * exchange happens via CPU registers. In particular, the convention is:
     * User-level applications use as integer registers for passing the
     * sequence %rdi, %rsi, %rdx, %rcx, %r8 and %r9. The kernel interface
     * uses %rdi, %rsi, %rdx, %r10, %r8 and %r9.
     */
    struct pt_regs *args = (struct pt_regs *)ctx->args[0];
    if (__flags & FLAG_ENABLE_BPF_PRINTK) {
        __u64 di = BPF_CORE_READ(args, di);
        __u64 si = BPF_CORE_READ(args, si);
        __u64 dx = BPF_CORE_READ(args, dx);
        __u64 r10 = BPF_CORE_READ(args, r10);
        __u64 r8 = BPF_CORE_READ(args, r8);
        __u64 r9 = BPF_CORE_READ(args, r9);
        bpf_printk("sys_enter[%lu] di=%lu si=%lx dx=%lx r10=%lx r8=%lx r9=%lx",
                   id, di, si, dx, r10, r8, r9);
        __syscall_enter_func(id, di, si, dx, r10, r8, r9);
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

SEC("raw_tracepoint/sys_exit")
int sys_exit(struct bpf_raw_tracepoint_args *ctx)
{
    struct pt_regs *args = (struct pt_regs *)ctx->args[0];
    __u64 id = BPF_CORE_READ(args, orig_ax);
    if (filter_syscall != -1 && id != filter_syscall) return 0;
    if (id >= MAX_SYSCALLS) return 0;

    __u64 pid = bpf_get_current_pid_tgid();
    if (filter_pid > 0 && (pid_t)(pid >> 32) != filter_pid) return 0;

    __u64 *tsp = map_lookup_and_delete(&clocks, &pid);
    if (!tsp) return 0;

    __u32 index = 0;
    struct hist *hp = map_lookup_or_try_init(&hists, &index, &initial_hist);
    if (!hp) return 0;

    __u64 delta = bpf_ktime_get_ns() - *tsp;
    delta /= 1000; /* micro-second */
    __u64 slot = log2l(delta);
    if (slot >= MAX_SLOTS) slot = MAX_SLOTS - 1;
    uint64_t counter = __sync_fetch_and_add(&hp->slots[id][slot], 1);
    if (__flags & FLAG_ENABLE_BPF_PRINTK) {
        bpf_printk("sys_exit[%lu]: delta=%lu slots[%lu]=%lu\n", id, delta, slot,
                   counter);
    }

    return 0;
}
