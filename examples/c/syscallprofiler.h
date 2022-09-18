// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Baodong Chen */
#ifndef __SYSCALLPROFILER_H__
#define __SYSCALLPROFILER_H__

#define MAX_SLOTS 32
struct hist {
    __u64 slots[MAX_SLOTS];
};

#endif /* __SYSCALLPROFILER_H__ */
