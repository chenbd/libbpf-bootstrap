// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 Baodong Chen */
#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "uprobeprofiler.skel.h"
#include "uprobeprofiler.h"

static int __verbose = 0;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}

#if 0
#define DEBUG_LOG(fmt, args...) fprintf(stderr, fmt, ##args)
#else
#define DEBUG_LOG(fmt, args...)
#endif

/**
 * Strip the input str
 * @param addr      [I/O] the value-result param of str
 * @return The stripped str
 */
static char *str_strip(char *str)
{
    const char *src = str;
    char *dst = str;
    while (*src) {
        if (*src != ' ' && *src != '\t') {
            *dst++ = *src;
        }
        src++;
    }
    *dst = '\0';
    return str;
}

/**
 * Get whether str has symbol name
 * @param offset    [I] the str to judge
 * @param pathname  [I] the symbol name to judge
 * @return true when yes or else false
 */
static inline bool str_has_name(const char *str, const char *name)
{
    size_t str_len = strlen(str);
    size_t name_len = strlen(name);

    if (name_len >= str_len) return false;
    if (strcmp(str + str_len - name_len, name) == 0) {
        if (*(str + str_len - name_len - 1) == ' ') {
            return true;
        }
    }
    return false;
}

/**
 * Get symbol name by offset in pathname
 * @param offset    [I] the offset to judge
 * @param pathname  [I] the library or executable to find in
 * @param symbol    [O] the output symbol name
 * @return 0 when success or else error
 */
static int get_symbol_name(size_t offset, const char *pathname,
                           char symbol[128])
{
    if (__verbose)
        fprintf(stderr, "finding offset='%zx' in '%s'\n", offset, pathname);
    size_t off;
    bool found = false;
    char command[256];
    /* FIXME: parse using libelf? */
    snprintf(command, sizeof(command), "objdump -T %s | grep %zx", pathname,
             offset);
    FILE *f = popen(command, "re");
    if (!f) {
        fprintf(stderr, "popen '%s' error=%d\n", command, errno);
        return -errno;
    }
    while (1) {
        char line[1024];
        char *p = fgets(line, sizeof(line), f);
        if (!p) break;
        size_t len = strlen(line);
        if (len <= 1) continue;
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        DEBUG_LOG("line='%s'\n", line);
        int r = sscanf(line, "%zx", &off);
        if (r == 1 && off > 0 && offset == off) {
            char *p = strrchr(line, ' ');
            if (p) {
                strncpy(symbol, p + 1, 128);
            }
            found = true;
            break;
        }
    }
    pclose(f);

    if (found) {
        fprintf(stderr, "offet='%zx' found in '%s' symbol='%s'\n", offset,
                pathname, symbol);
        return 0;
    }
    return -ESRCH;
}

/**
 * Get offset by address for uprobe
 * @param addr      [I] the input address
 * @param pid       [I] the input pid
 * @param pathname  [O] the output path for library or executable
 * @return Offset for uprobe attach or < 0 when error
 */
static ssize_t get_uprobe_offset_by_addr(const void *addr, pid_t pid,
                                         char pathname[256])
{
    size_t start, end, base;
    char name[256];
    bool found = false;
    FILE *f;
    char path[64];
    if (pid > 0) {
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    } else {
        snprintf(path, sizeof(path), "/proc/self/maps");
    }
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "open '%s' error=%d\n", path, errno);
        return -errno;
    }

    while (1) {
        char buf[256];
        uint32_t major, minor;
        uint32_t inode;
        char line[1024];
        char *p = fgets(line, sizeof(line), f);
        if (!p) break;
        DEBUG_LOG("line='%s'\n", line);
        int r = sscanf(line, "%zx-%zx %s %zx %x:%x %u %s[^\n]", &start, &end,
                       buf, &base, &major, &minor, &inode, name);
        DEBUG_LOG("r='%d'\n", r);
        if (r == 7) continue;
        if (r == 8) {
            DEBUG_LOG("name='%s'\n", name);
            if (buf[2] == 'x' && (uintptr_t)addr >= start &&
                (uintptr_t)addr < end) {
                found = true;
                break;
            }
        }
    }

    fclose(f);

    if (!found) {
        fprintf(stderr, "addr='%p' not found\n", addr);
        return -ESRCH;
    }
    str_strip(name);
    strncpy(pathname, name, 256);
    return (uintptr_t)addr - start + base;
}

/**
 * Get offset for symbol in pathname
 * @param symbol    [I] the input symbol
 * @param pathname  [O] the output path for library or executable
 * @return Offset for symbol or < 0 when error
 */
static ssize_t get_symbol_offset(const char *symbol, const char *pathname)
{
    if (__verbose)
        fprintf(stderr, "finding symbol '%s' in '%s'\n", symbol, pathname);
    /**
     * skip mappings eg:
     * [heap]
     * [stack]
     * [vvar]
     * [vdso]
     * [vsyscall]
     */
    if (pathname[0] == '[') {
        return -EINVAL;
    }

#if 0
    extern long elf_find_func_offset(const char *binary_path, const char *name);
    ssize_t off = elf_find_func_offset(pathname, symbol);
    if (off < 0) {
        fprintf(stderr, "elf_find_func_offset() error\n");
        return -ESRCH;
    }
    fprintf(stderr, "symbol='%s' found in '%s' off=%zx\n", symbol, pathname,
            off);
    return off;
#else
    size_t off;
    bool found = false;
    char command[256];
    /* FIXME: parse using libelf? */
    snprintf(command, sizeof(command), "objdump -T %s | grep %s", pathname,
             symbol);
    FILE *f = popen(command, "re");
    if (!f) {
        fprintf(stderr, "popen '%s' error=%d\n", command, errno);
        return -errno;
    }
    while (1) {
        char line[1024];
        char *p = fgets(line, sizeof(line), f);
        if (!p) break;
        size_t len = strlen(line);
        if (len <= 1) continue;
        if (line[len - 1] == '\n') {
            line[len - 1] = '\0';
        }
        DEBUG_LOG("line='%s'\n", line);
        if (str_has_name(line, symbol)) {
            int r = sscanf(line, "%zx", &off);
            if (r == 1 && off > 0) {
                found = true;
                break;
            }
        }
    }
    pclose(f);

    if (found) {
        fprintf(stderr, "symbol='%s' found in '%s' off=%zx\n", symbol, pathname,
                off);
        return off;
    }
    return -ESRCH;
#endif
}

/**
 * Get offset by symbol for uprobe
 * @param symbol    [I] the input symbol
 * @param pid       [I] the input pid
 * @param pathname  [O] the output path for library or executable
 * @param address   [O] the output address for symbol
 * @return Offset for uprobe attach or < 0 when error
 */
static ssize_t get_uprobe_offset_by_symbol(const char *symbol, pid_t pid,
                                           char pathname[256], void **address)
{
    ssize_t off;
    size_t start, end, base;
    char name[256];
    bool found = false;
    FILE *f;
    char path[64];
    if (pid > 0) {
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
    } else {
        snprintf(path, sizeof(path), "/proc/self/maps");
    }
    f = fopen(path, "r");
    if (!f) {
        fprintf(stderr, "open '%s' error=%d\n", path, errno);
        return -errno;
    }

    while (1) {
        char buf[256];
        uint32_t major, minor;
        uint32_t inode;
        char line[1024];
        char *p = fgets(line, sizeof(line), f);
        if (!p) break;
        DEBUG_LOG("line ='%s'", line);
        int r = sscanf(line, "%zx-%zx %s %zx %x:%x %u %s[^\n]", &start, &end,
                       buf, &base, &major, &minor, &inode, name);
        DEBUG_LOG("r='%d'\n", r);
        if (r == 7) continue;
        if (r == 8) {
            DEBUG_LOG("name ='%s'\n", name);
            if (buf[2] == 'x') {
                off = get_symbol_offset(symbol, str_strip(name));
                if (off > 0) {
                    found = true;
                    *address = (void *)(start + off - base);
                    break;
                }
            }
        }
    }

    fclose(f);

    if (!found) {
        fprintf(stderr, "symbol='%s' not found\n", symbol);
        return -ESRCH;
    }
    strncpy(pathname, name, 256);
    return off;
}

static void show_help(const char *progname)
{
    /* clang-format off */
    printf("Usage: %s [-p <pid> -a <address> -n <symbol> -f <library:symbol>] [-v] [-h]\n",
           progname);
    /* clang-format on */
}

int main(int argc, char **argv)
{
    struct uprobeprofiler_bpf *skel;
    long uprobe_offset;
    int err;
    int argp = 0;
    int filter_pid = 0;
    void *address = 0;      /* symbol address */
    char symbol[128] = {0}; /* symbol name */
    char pathname[256] = {0};

    while ((argp = getopt(argc, argv, "hvp:a:n:f:")) != -1) {
        switch (argp) {
        case 'p':
            filter_pid = atoi(optarg);
            break;
        case 'a':
            address = (void *)strtol(optarg, NULL, 16);
            break;
        case 'n':
            strncpy(symbol, optarg, sizeof(symbol) - 1);
            break;
        case 'f': {
            const char *s = strchr(optarg, ':');
            if (s && s != optarg) {
                strncpy(pathname, optarg, s - optarg);
                s++;
                strncpy(symbol, s, sizeof(symbol));
            }
        } break;
        case 'v':
            __verbose = 1;
            break;
        case 'h':
        default:
            show_help(argv[0]);
            return 1;
        }
    }
    if (filter_pid == -1) {
        if (pathname[0] == '\0' || symbol[0] == '\0') {
            show_help(argv[0]);
            return 1;
        } else {
            if (address != 0) {
                show_help(argv[0]);
                return 1;
            }
        }
    } else if (address == 0 && strlen(symbol) == 0) {
        show_help(argv[0]);
        return 1;
    }

    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
    /* Set up libbpf errors and debug info callback */
    if (__verbose) libbpf_set_print(libbpf_print_fn);

    /* Open BPF application */
    skel = uprobeprofiler_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Load and verify BPF application */
    err = uprobeprofiler_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load BPF skeleton\n");
        goto cleanup;
    }

    /* uprobe/uretprobe expects relative offset of the function to attach
     * to. This offset is relateve to the process's base load address. So
     * easy way to do this is to take an absolute address of the desired
     * function and substract base load address from it.  If we were to
     * parse ELF to calculate this function, we'd need to add .text
     * section offset and function's offset within .text ELF section.
     */
    if (filter_pid == -1) {
#if 0
        if (!strchr(pathname, '/')) {
            extern int resolve_full_path(const char *file, char *result,
                                         size_t result_sz);
            char result[sizeof(pathname)];
            err = resolve_full_path(pathname, result, sizeof(result));
            if (err) {
                fprintf(stderr, "Resolve full path for '%s' error\n", pathname);
                goto cleanup;
            }
            strncpy(pathname, result, sizeof(pathname));
        }
#endif
        uprobe_offset = get_symbol_offset(symbol, pathname);
    } else if (address != 0) {
        uprobe_offset =
            get_uprobe_offset_by_addr(address, filter_pid, pathname);
        if (uprobe_offset > 0) {
            get_symbol_name(uprobe_offset, pathname, symbol);
        }
    } else {
        uprobe_offset =
            get_uprobe_offset_by_symbol(symbol, filter_pid, pathname, &address);
    }
    if (uprobe_offset < 0) {
        fprintf(stderr, "Failed to get uprobe_offset\n");
        goto cleanup;
    }
    if (__verbose)
        fprintf(stderr, "uprobe_offset=%zx pathname='%s'\n", uprobe_offset,
                pathname);

    /* Attach tracepoint handler */
    skel->links.uprobeprofiler = bpf_program__attach_uprobe(
        skel->progs.uprobeprofiler, false /* not uretprobe */,
        filter_pid /* -1 means any pid */, pathname, uprobe_offset);
    if (!skel->links.uprobeprofiler) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }

    /* Attach tracepoint handler */
    skel->links.uretprobeprofiler = bpf_program__attach_uprobe(
        skel->progs.uretprobeprofiler, true /* uretprobe */,
        filter_pid /* -1 means any pid */, pathname, uprobe_offset);
    if (!skel->links.uretprobeprofiler) {
        err = -errno;
        fprintf(stderr, "Failed to attach uprobe: %d\n", err);
        goto cleanup;
    }

    printf("Successfully started! Please run `sudo cat "
           "/sys/kernel/debug/tracing/trace_pipe` "
           "to see output of the BPF programs.\n");

    uint32_t counter = 0;
    for (;;) {
        if (counter % 4 == 0) {
            uint32_t key = 0;
            struct hist hists;
            int r = bpf_map__lookup_elem(skel->maps.hists, &key, sizeof(key),
                                         &hists, sizeof(hists), 0);
            if (r == 0) {
                printf("\nprofiling address='%p' symbol='%s' for pid "
                       "%d:\n\t\tMicro"
                       "seconds\t : Count\n",
                       address, symbol, filter_pid);
                __u64 total = 0;
                for (int i = 0; i < MAX_SLOTS; ++i) {
                    total += hists.slots[i];
                }
                for (int i = 0; i < MAX_SLOTS; ++i) {
                    if (hists.slots[i] != 0) {
                        printf("\t[%8llu\t%8llu]: %8llu (%.02f%%)\n",
                               (i == 0) ? 0 : (1ull << i),
                               (1ull << (i + 1)) - 1, hists.slots[i],
                               hists.slots[i] * 100.0 / total);
                    }
                }
                printf("---------------------------------| Total=%llu\n",
                       total);
            }
        }
        counter++;
        fprintf(stderr, ".");
        sleep(1);
    }

cleanup:
    uprobeprofiler_bpf__destroy(skel);
    return -err;
}