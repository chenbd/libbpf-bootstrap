// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2022 Baodong Chen */
#ifndef __UPROBE_PROFILER_H__
#define __UPROBE_PROFILER_H__

#define MAX_SLOTS 32
struct hist {
    __u64 slots[MAX_SLOTS];
    struct {
        __u64 delta;
        uint32_t stackid;
    } peek[3];
};

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 64
#endif

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define FLAG_COLLECT_USER_STACK (0x01)

#endif /* __UPROBE_PROFILER_H__ */
