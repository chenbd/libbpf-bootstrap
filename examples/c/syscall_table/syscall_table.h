// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Baodong Chen */
#ifndef __SYSCALLTABLE_H__
#define __SYSCALLTABLE_H__

#ifdef __x86_64__
#include "x86_64/syscall_table-x86_64.h"
#endif

static inline const char *syscall_name(uint32_t index)
{
    return index < sizeof(syscall_table) / sizeof(syscall_table[0])
               ? syscall_table[index]
               : "";
}

static inline uint32_t syscall_no(const char *name)
{
    uint32_t i;
    for (i = 0; i < sizeof(syscall_table) / sizeof(syscall_table[0]); ++i) {
        if (0 == strcmp(name, syscall_table[i])) {
            return i;
        }
    }
    return UINT32_MAX;
}

#endif /* __SYSCALLTABLE_H__ */
