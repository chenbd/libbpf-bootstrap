// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Baodong Chen */
#ifndef __SYSCALLID_H__
#define __SYSCALLID_H__

#if defined(__TARGET_ARCH_x86) || defined(__x86_64__)
#include "x86_64/syscall_id-x86_64.h"
#endif

#endif /* __SYSCALLID_H__ */
