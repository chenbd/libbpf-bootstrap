// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Baodong Chen */
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/usdt.bpf.h>

pid_t my_pid;

/**
 * https://www.gnu.org/software/libc/manual/html_node/Internal-Probes.html
 */
/**
 * This probe is triggered after the main arena is extended by calling sbrk.
 * Argument $arg1 is the additional size requested to sbrk, and $arg2 is the
 * pointer that marks the end of the sbrk area, returned in response to the
 * request.
 */
SEC("usdt/libc.so.6:libc:memory_sbrk_more")
int BPF_USDT(usdt_memory_sbrk_more, void *arg1, size_t arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_sbrk_more: arg1=%lx, arg2=%zu", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered after the size of the main arena is decreased by
 * calling sbrk. Argument $arg1 is the size released by sbrk (the positive
 * value, rather than the negative value passed to sbrk), and $arg2 is the
 * pointer that marks the end of the sbrk area, returned in response to the
 * request.
 */
SEC("usdt/libc.so.6:libc:memory_sbrk_less")
int BPF_USDT(usdt_memory_sbrk_less, void *arg1, size_t arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_sbrk_less: arg1=%lx, arg2=%zu", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered after a new heap is mmaped. Argument $arg1 is a
 * pointer to the base of the memory area, where the heap_info data structure is
 * held, and $arg2 is the size of the heap.
 */
SEC("usdt/libc.so.6:libc:memory_heap_new")
int BPF_USDT(usdt_memory_heap_new, void *arg1, size_t arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_heap_new: arg1=%lx, arg2=%zu", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered before (unlike the other sbrk and heap probes) a heap
 * is completely removed via munmap. Argument $arg1 is a pointer to the heap,
 * and $arg2 is the size of the heap.
 */
SEC("usdt/libc.so.6:libc:memory_heap_free")
int BPF_USDT(usdt_memory_heap_free, void *arg1, size_t arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_heap_free: arg1=%lx, arg2=%zu", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered after a trailing portion of an mmaped heap is
 * extended. Argument $arg1 is a pointer to the heap, and $arg2 is the new size
 * of the heap.
 */
SEC("usdt/libc.so.6:libc:memory_heap_more")
int BPF_USDT(usdt_memory_heap_more, void *arg1, size_t arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_heap_more: arg1=%lx, arg2=%zu", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered after a trailing portion of an mmaped heap is
 * released. Argument $arg1 is a pointer to the heap, and $arg2 is the new size
 * of the heap.
 */
SEC("usdt/libc.so.6:libc:memory_heap_less")
int BPF_USDT(usdt_memory_heap_less, void *arg1, size_t arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_heap_less: arg1=%lx, arg2=%zu", arg1, arg2);
    return 0;
}

/**
 * These probes are triggered when the corresponding functions fail to obtain
 * the requested amount of memory from the arena in use, before they call
 * arena_get_retry to select an alternate arena in which to retry the
 * allocation. Argument $arg1 is the amount of memory requested by the user; in
 * the calloc case, that is the total size computed from both function
 * arguments. In the realloc case, $arg2 is the pointer to the memory area being
 * resized. In the memalign case, $arg2 is the alignment to be used for the
 * request, which may be stricter than the value passed to the memalign
 * function. A memalign probe is also used by functions posix_memalign, valloc
 * and pvalloc.
 */
SEC("usdt/libc.so.6:libc:memory_malloc_retry")
int BPF_USDT(usdt_memory_malloc_retry, size_t arg1)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_malloc_retry: arg1=%zu", arg1);
    return 0;
}

SEC("usdt/libc.so.6:libc:memory_realloc_retry")
int BPF_USDT(usdt_memory_realloc_retry, size_t arg1, void *arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_realloc_retry: arg1=%zu arg2=%lx", arg1, arg2);
    return 0;
}

SEC("usdt/libc.so.6:libc:memory_memalign_retry")
int BPF_USDT(usdt_memory_memalign_retry, size_t arg1)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_memalign_retry: arg1=%zu", arg1);
    return 0;
}

SEC("usdt/libc.so.6:libc:memory_calloc_retry")
int BPF_USDT(usdt_memory_calloc_retry, size_t arg1)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_calloc_retry: arg1=%zu", arg1);
    return 0;
}

/**
 * This probe is triggered within arena_get_retry (the function called to select
 * the alternate arena in which to retry an allocation that failed on the first
 * attempt), before the selection of an alternate arena. This probe is
 * redundant, but much easier to use when it’s not important to determine which
 * of the various memory allocation functions is failing to allocate on the
 * first try. Argument $arg1 is the same as in the function-specific probes,
 * except for extra room for padding introduced by functions that have to ensure
 * stricter alignment. Argument $arg2 is the arena in which allocation failed.
 */
SEC("usdt/libc.so.6:libc:memory_arena_retry")
int BPF_USDT(usdt_memory_arena_retry, size_t arg1, void *arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_arena_retry: arg1=%zu arg2=%lx", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered when malloc allocates and initializes an additional
 * arena (not the main arena), but before the arena is assigned to the running
 * thread or inserted into the internal linked list of arenas. The arena’s
 * malloc_state internal data structure is located at $arg1, within a
 * newly-allocated heap big enough to hold at least $arg2 bytes.
 */
SEC("usdt/libc.so.6:libc:memory_arena_new")
int BPF_USDT(usdt_memory_arena_new, void *arg1, size_t arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_arena_new: arg1=%lx arg2=%zu", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered when malloc has just selected an existing arena to
 * reuse, and (temporarily) reserved it for exclusive use. Argument $arg1 is a
 * pointer to the newly-selected arena, and $arg2 is a pointer to the arena
 * previously used by that thread.
 *
 * This occurs within reused_arena, right after the mutex mentioned in probe
 * memory_arena_reuse_wait is acquired; argument $arg1 will point to the same
 * arena. In this configuration, this will usually only occur once per thread.
 * The exception is when a thread first selected the main arena, but a
 * subsequent allocation from it fails: then, and only then, may we switch to
 * another arena to retry that allocation, and for further allocations within
 * that thread.
 */
SEC("usdt/libc.so.6:libc:memory_arena_reuse")
int BPF_USDT(usdt_memory_arena_reuse, void *arg1, void *arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_arena_reuse: arg1=%lx arg2=%lx", arg1, arg2);
    return 0;
}

/**
 * This probe is triggered when malloc is about to wait for an arena to become
 * available for reuse. Argument $arg1 holds a pointer to the mutex the thread
 * is going to wait on, $arg2 is a pointer to a newly-chosen arena to be reused,
 * and $arg3 is a pointer to the arena previously used by that thread.
 *
 * This occurs within reused_arena, when a thread first tries to allocate memory
 * or needs a retry after a failure to allocate from the main arena, there isn’t
 * any free arena, the maximum number of arenas has been reached, and an
 * existing arena was chosen for reuse, but its mutex could not be immediately
 * acquired. The mutex in $arg1 is the mutex of the selected arena.
 */
SEC("usdt/libc.so.6:libc:memory_arena_reuse_wait")
int BPF_USDT(usdt_memory_arena_reuse_wait, void *arg1, void *arg2, void *arg3)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_arena_reuse_wait: arg1=%lx arg2=%lx arg3=%lx",
               arg1, arg2, arg3);
    return 0;
}

/**
 * This probe is triggered when malloc has chosen an arena that is in the free
 * list for use by a thread, within the get_free_list function. The argument
 * $arg1 holds a pointer to the selected arena.
 */
SEC("usdt/libc.so.6:libc:memory_arena_reuse_free_list")
int BPF_USDT(usdt_memory_arena_reuse_free_list, void *arg1)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_arena_reuse_free_list: arg1=%lx", arg1);
    return 0;
}

/**
 * This probe is triggered when function mallopt is called to change malloc
 * internal configuration parameters, before any change to the parameters is
 * made. The arguments $arg1 and $arg2 are the ones passed to the mallopt
 * function.
 */
SEC("usdt/libc.so.6:libc:memory_mallopt")
int BPF_USDT(usdt_memory_mallopt, int arg1, int arg2)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;

    if (pid != my_pid) return 0;

    bpf_printk("USDT libc:memory_mallopt: arg1=%d arg2=%d", arg1, arg2);
    return 0;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
