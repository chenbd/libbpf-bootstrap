// SPDX-License-Identifier: GPL-2.0 OR BSD-2-Clause
/* Copyright (c) 2022 Baodong Chen */
#ifndef __UPROBE_PROFILER_H__
#define __UPROBE_PROFILER_H__

#define MAX_SLOTS 32
struct hist {
    __u64 slots[MAX_SLOTS];
};

#endif /* __UPROBE_PROFILER_H__ */
