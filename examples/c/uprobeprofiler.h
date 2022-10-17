// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2022 Baodong Chen */
#ifndef __UPROBE_PROFILER_H__
#define __UPROBE_PROFILER_H__

#define MAX_SLOTS 32
struct hist {
    __u64 slots[MAX_SLOTS];
};

#ifndef MAX_STACK_DEPTH
#define MAX_STACK_DEPTH 64
#endif

#define FLAG_COLLECT_USER_STACK (0x01)

#endif /* __UPROBE_PROFILER_H__ */
