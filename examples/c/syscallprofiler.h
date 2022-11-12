// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 Baodong Chen */
#ifndef __SYSCALLPROFILER_H__
#define __SYSCALLPROFILER_H__

#define MAX_SLOTS 32
#define MAX_SYSCALLS 512

struct hist {
    __u64 slots[MAX_SYSCALLS][MAX_SLOTS];
};

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(a) (sizeof(a) / sizeof(a[0]))
#endif

#define FLAG_ENABLE_BPF_PRINTK (0x01)

#endif /* __SYSCALLPROFILER_H__ */
