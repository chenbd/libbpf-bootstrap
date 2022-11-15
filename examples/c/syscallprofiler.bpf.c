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
struct timeval;
typedef __kernel_mode_t mode_t;
typedef __kernel_fd_set fd_set;
typedef unsigned long int nfds_t;
typedef uint32_t socklen_t; /* LP64 sitll has a 32-bit socklen_t. */

static inline void sys_enter_read(int fd, const void *buf, size_t count)
{
    bpf_printk("sys_enter_read: fd=%d count=%lx buf=%lx ", fd, count, buf);
}
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
    bpf_printk("sys_enter_write: fd=%d count=%lx buf=%s %s", fd, _count, tmp,
               _count != count ? "..." : "");
}
static void sys_enter_openat(int dirfd, const char *pathname, int flags,
                             mode_t mode)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_openat: dirfd=%d pathname='%s' flag=%x mode=%x",
               dirfd, tmp, flags, mode);
}
static void sys_enter_open(const char *pathname, int flags, mode_t mode)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_open: pathname='%s' flag=%x mode=%x", tmp, flags,
               mode);
}
static void sys_enter_stat(const char *pathname, struct stat *statbuf)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_stat: pathname='%s' statbuf=%x", tmp, statbuf);
}
static void sys_enter_fstat(int fd, struct stat *statbuf)
{
    bpf_printk("sys_enter_fstat: fd=%d statbuf=%x", fd, statbuf);
}
static void sys_enter_lstat(const char *pathname, struct stat *statbuf)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_lstat: pathname='%s' statbuf=%x", tmp, statbuf);
}
static void sys_enter_fstatat(int dirfd, const char *pathname,
                              struct stat *statbuf, int flags)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_fstatat: dirfd=%d pathname='%s' statbuf=%lx flags=%x",
               dirfd, tmp, statbuf, flags);
}
static void sys_enter_lseek(int fd, off_t offset, int whence)
{
    bpf_printk("sys_enter_lseek: fd=%d offset=%lx whence=%d", fd, offset,
               whence);
}
static void sys_enter_mprotect(void *addr, size_t len, int prot)
{
    bpf_printk("sys_enter_mprotect: addr=%lx size=%lx prot=%d", addr, len,
               prot);
}
static void sys_enter_readv(int fd, const struct iovec *iov, int iovcnt)
{
    bpf_printk("sys_enter_readv: fd=%d iovcnt=%x iov=%lx", fd, iovcnt, iov);
}
static void sys_enter_writev(int fd, const struct iovec *iov, int iovcnt)
{
    bpf_printk("sys_enter_writev: fd=%d iovcnt=%x iov=%lx", fd, iovcnt, iov);
}
static void sys_enter_access(const char *pathname, int mode)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_access: pathname='%s' mode=%d", tmp, mode);
}
static void sys_enter_faccessat(int dirfd, const char *pathname, int mode,
                                int flags)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_faccessat: dirfd=%d pathname='%s' mode=%d flags=%x",
               dirfd, tmp, mode, flags);
}
static void sys_enter_faccessat2(int dirfd, const char *pathname, int mode,
                                 int flags)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_faccessat2: dirfd=%d pathname='%s' mode=%d flags=%x",
               dirfd, tmp, mode, flags);
}
static void sys_enter_pipe(int pipefd[2])
{
    bpf_printk("sys_enter_pipe: pipefd=%lx", pipefd);
}
static void sys_enter_pipe2(int pipefd[2], int flags)
{
    bpf_printk("sys_enter_pipe2: pipefd=%lx flags=%x", pipefd, flags);
}
static void sys_enter_sched_yield(void) { bpf_printk("sys_enter_sched_yield"); }
static void sys_enter_unlink(const char *pathname)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_unlink: pathname='%s'", tmp);
}
static void sys_enter_unlinkat(int dirfd, const char *pathname, int flags)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_unlinkat: dirfd=%d pathname='%s' flag=%x", dirfd, tmp,
               flags);
}
static void sys_enter_close(int fd)
{
    bpf_printk("sys_enter_close: fd=%d", fd);
}
static void sys_enter_brk(void *addr)
{
    bpf_printk("sys_enter_brk: addr=%lx", addr);
}
static void sys_enter_mmap(void *addr, size_t length, int prot, int flags,
                           int fd, off_t offset)
{
    bpf_printk(
        "sys_enter_mmap: addr=%lx length=%lx prot=%x flags=%x fd=%d offset=%lx",
        addr, length, prot, flags, fd, offset);
}
static void sys_enter_mremap(void *old_address, size_t old_size,
                             size_t new_size, int flags)
{
    bpf_printk(
        "sys_enter_mremap: old_address=%lx old_size=%lx new_size=%lx flags=%x",
        old_address, old_size, new_size, flags);
}
static void sys_enter_msync(void *addr, size_t length, int flags)
{
    bpf_printk("sys_enter_msync: addr=%lx length=%lx flags=%x", addr, length,
               flags);
}
static void sys_enter_madvise(void *addr, size_t length, int advice)
{
    bpf_printk("sys_enter_madvise: addr=%lx length=%lx advice=%d", addr, length,
               advice);
}
static void sys_enter_munmap(void *addr, size_t length)
{
    bpf_printk("sys_enter_munmap: addr=%lx length=%lx", addr, length);
}
static void sys_enter_dup(int oldfd)
{
    bpf_printk("sys_enter_dup: oldfd=%d", oldfd);
}
static void sys_enter_dup2(int oldfd, int newfd)
{
    bpf_printk("sys_enter_dup2: oldfd=%d nnewfd=%d", oldfd, newfd);
}
static void sys_enter_dup3(int oldfd, int newfd, int flags)
{
    bpf_printk("sys_enter_dup3: oldfd=%d nnewfd=%d flags=%x", oldfd, newfd,
               flags);
}
static void sys_enter_pause(void) { bpf_printk("sys_enter_pause"); }
static void sys_enter_sendfile(int out_fd, int in_fd, off_t *offset,
                               size_t count)
{
    bpf_printk("sys_enter_sendfile: out_fd=%d in_fd=%d offset=%lx count=%lx",
               out_fd, in_fd, offset, count);
}
static void sys_enter_socket(int domain, int type, int protocol)
{
    bpf_printk("sys_enter_socket: domain=%d type=%d protocol=%d", domain, type,
               protocol);
}
static void sys_enter_connect(int sockfd, const struct sockaddr *addr,
                              socklen_t addrlen)
{
    bpf_printk("sys_enter_connect: sockfd=%d addrlen=%lu addr=%lx", sockfd,
               addrlen, addr);
}
static void sys_enter_accept(int sockfd, struct sockaddr *addr,
                             socklen_t *addrlen)
{
    bpf_printk("sys_enter_accept: sockfd=%d addrlen=%lx addr=%lx", sockfd,
               addrlen, addr);
}
static void sys_enter_accept4(int sockfd, struct sockaddr *addr,
                              socklen_t *addrlen, int flags)
{
    bpf_printk("sys_enter_accept4: sockfd=%d addrlen=%lx addr=%lx flags=%x",
               sockfd, addrlen, addr, flags);
}
static void sys_enter_sendto(int sockfd, const void *buf, size_t len, int flags,
                             const struct sockaddr *dest_addr,
                             socklen_t addrlen)
{
    bpf_printk("sys_enter_sendto: sockfd=%d buf=%lx len=%lx flags=%x "
               "dest_addr=%lx addrlen=%x",
               sockfd, buf, len, flags, dest_addr, addrlen);
}

static void sys_enter_sendmsg(int sockfd, const struct msghdr *msg, int flags)
{
    bpf_printk("sys_enter_sendmsg: sockfd=%d msg=%lx flags=%x", sockfd, msg,
               flags);
}
static void sys_enter_sendmmsg(int sockfd, struct mmsghdr *msgvec,
                               unsigned int vlen, int flags)
{
    bpf_printk("sys_enter_sendmmsg: sockfd=%d msgvec=%lx vlen=%u flags=%x",
               sockfd, msgvec, vlen, flags);
}
static void sys_enter_recvfrom(int sockfd, void *buf, size_t len, int flags,
                               struct sockaddr *src_addr, socklen_t *addrlen)
{
    bpf_printk("sys_enter_recvfrom: sockfd=%d buf=%lx len=%lx flags=%x "
               "src_addr=%lx addrlen=%x",
               sockfd, buf, len, flags, src_addr, addrlen);
}
static void sys_enter_recvmsg(int sockfd, struct msghdr *msg, int flags)
{
    bpf_printk("sys_enter_recvmsg: sockfd=%d msg=%lx flags=%x", sockfd, msg,
               flags);
}
static void sys_enter_recvmmsg(int sockfd, struct mmsghdr *msgvec,
                               unsigned int vlen, int flags,
                               struct timespec *timeout)
{
    bpf_printk(
        "sys_enter_recvmmsg: sockfd=%d msgvec=%lx vlen=%u flags=%x timeout=%lx",
        sockfd, msgvec, vlen, flags, timeout);
}
static void sys_enter_shutdown(int sockfd, int how)
{
    bpf_printk("sys_enter_shutdown: sockfd=%d how=%d", sockfd, how);
}
static void sys_enter_bind(int sockfd, const struct sockaddr *addr,
                           socklen_t addrlen)
{
    bpf_printk("sys_enter_bind: sockfd=%d addr=%lx addrlen=%x", sockfd, addr,
               addrlen);
}
static void sys_enter_listen(int sockfd, int backlog)
{
    bpf_printk("sys_enter_listen: sockfd=%d backlog=%d", sockfd, backlog);
}
static void sys_enter_getsockname(int sockfd, struct sockaddr *addr,
                                  socklen_t *addrlen)
{
    bpf_printk("sys_enter_getsockname: sockfd=%d addr=%lx addrlen=%lx", sockfd,
               addr, addrlen);
}
static void sys_enter_getpeername(int sockfd, struct sockaddr *addr,
                                  socklen_t *addrlen)
{
    bpf_printk("sys_enter_getpeername: sockfd=%d addr=%lx addrlen=%lx", sockfd,
               addr, addrlen);
}
static void sys_enter_socketpair(int domain, int type, int protocol, int sv[2])
{
    bpf_printk("sys_enter_socketpair: domain=%d type=%d protocol=%d sv=%lx",
               domain, type, protocol, sv);
}
static void sys_enter_getsockopt(int sockfd, int level, int optname,
                                 void *optval, socklen_t *optlen)
{
    bpf_printk("sys_enter_getsockopt: sockfd=%d level=%d optname=%d optval=%lx "
               "optlen=%lx",
               sockfd, level, optname, optval, optlen);
}
static void sys_enter_setsockopt(int sockfd, int level, int optname,
                                 const void *optval, socklen_t optlen)
{
    bpf_printk("sys_enter_setsockopt: sockfd=%d level=%d optname=%d optval=%lx "
               "optlen=%u",
               sockfd, level, optname, optval, optlen);
    int v = -1;
    if (optlen == 4) {
        bpf_core_read_user(&v, sizeof(v), optval);
    }
    if (v != -1) {
        bpf_printk("optval=%d", v);
    }
}
static void
sys_enter_clone(int (*fn)(void *), void *stack, int flags, void *arg
                /* pid_t *parent_tid, void *tls, pid_t *child_tid */)
{
    bpf_printk("sys_enter_clone: fn=%lx stack=%lx flags=%x arg=%lx", fn, stack,
               flags, arg);
}

static void sys_enter_clone3(struct clone_args *cl_args, size_t size)
{
    bpf_printk("sys_enter_clone3: cl_args=%lx size=%lu", cl_args, size);
}
static void sys_enter_fork() { bpf_printk("sys_enter_fork"); }
static void sys_enter_vfork() { bpf_printk("sys_enter_vfork"); }
static void sys_enter_execve(const char *pathname, char *const argv[],
                             char *const envp[])
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_execve: pathname='%s' argv=%x envp=%x", tmp, argv,
               envp);
}
static void sys_enter_exit(int status)
{
    bpf_printk("sys_enter_exit: status=%d", status);
}
static void sys_enter_exit_group(int status)
{
    bpf_printk("sys_enter_exit_group: status=%d", status);
}
static void sys_enter_wait4(pid_t pid, int *wstatus, int options,
                            struct rusage *rusage)
{
    bpf_printk("sys_enter_wait4: pid=%d wstatus=%lx options=%x rusage=%lx", pid,
               wstatus, options, rusage);
}
static void sys_enter_kill(pid_t pid, int sig)
{
    bpf_printk("sys_enter_kill: pid=%d sig=%d options=%x rusage=%lx", pid, sig);
}
static void sys_enter_fcntl(int fd, int cmd /* arg */)
{
    bpf_printk("sys_enter_fcntl: fd=%d cmd=%d", fd, cmd);
}
static void sys_enter_flock(int fd, int operation)
{
    bpf_printk("sys_enter_flock: fd=%d operation=%d", fd, operation);
}
static void sys_enter_fsync(int fd)
{
    bpf_printk("sys_enter_fsync: fd=%d", fd);
}
static void sys_enter_fdatasync(int fd)
{
    bpf_printk("sys_enter_fdatasync: fd=%d", fd);
}
static void sys_enter_truncate(const char *path, off_t length)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), path);
    bpf_printk("sys_enter_truncate: pathname='%s' length=%lu", tmp, length);
}
static void sys_enter_ftruncate(int fd, off_t length)
{
    bpf_printk("sys_enter_ftruncate: fd=%d length=%lu", fd, length);
}
static void sys_enter_getcwd(char *buf, size_t size)
{
    bpf_printk("sys_enter_getcwd: buf=%lx size=%lu", buf, size);
}
static void sys_enter_chdir(const char *path)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), path);
    bpf_printk("sys_enter_chdir: path='%s'", tmp);
}
static void sys_enter_fchdir(int fd)
{
    bpf_printk("sys_enter_fchdir: fd=%d", fd);
}
static void sys_enter_rename(const char *oldpath, const char *newpath)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), oldpath);
    bpf_printk("sys_enter_rename: oldpath='%s'", tmp);
    bpf_core_read_user_str(tmp, sizeof(tmp), newpath);
    bpf_printk("sys_enter_rename: newpath='%s'", tmp);
}
static void sys_enter_mkdir(const char *pathname, mode_t mode)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_mkdir: pathname='%s' mode=%d", tmp, mode);
}
static void sys_enter_rmdir(const char *pathname)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_rmdir: pathname='%s'", tmp);
}
static void sys_enter_creat(const char *pathname, mode_t mode)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_creat: pathname='%s' mode=%d", tmp, mode);
}
static void sys_enter_link(const char *oldpath, const char *newpath)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), oldpath);
    bpf_printk("sys_enter_link: oldpath='%s'", tmp);
    bpf_core_read_user_str(tmp, sizeof(tmp), newpath);
    bpf_printk("sys_enter_link: newpath='%s'", tmp);
}
static void sys_enter_linkat(int olddirfd, const char *oldpath, int newdirfd,
                             const char *newpath, int flags)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), oldpath);
    bpf_printk("sys_enter_linkat: olddirfd=%d oldpath='%s'", olddirfd, tmp);
    bpf_core_read_user_str(tmp, sizeof(tmp), newpath);
    bpf_printk("sys_enter_linkat: newdirfd=%d newpath='%s' flags=%x", newdirfd,
               tmp, flags);
}
static void sys_enter_symlink(const char *target, const char *linkpath)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), target);
    bpf_printk("sys_enter_symlink: target='%s'", tmp);
    bpf_core_read_user_str(tmp, sizeof(tmp), linkpath);
    bpf_printk("sys_enter_symlink: linkpath='%s'", tmp);
}
static void sys_enter_symlinkat(const char *target, int newdirfd,
                                const char *linkpath)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), target);
    bpf_printk("sys_enter_symlink: target='%s'", tmp);
    bpf_core_read_user_str(tmp, sizeof(tmp), linkpath);
    bpf_printk("sys_enter_symlink: newdirfd=%d linkpath='%s'", newdirfd, tmp);
}
static void sys_enter_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_readlink: pathname='%s' buf=%lx bufsiz=%lu", tmp, buf,
               bufsiz);
}
static void sys_enter_chmod(const char *pathname, mode_t mode)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_chmod: pathname='%s' mode=%d", tmp, mode);
}
static void sys_enter_fchmod(int fd, mode_t mode)
{
    bpf_printk("sys_enter_fchmod: fd=%d mode=%d", fd, mode);
}
static void sys_enter_fchmodat(int dirfd, const char *pathname, mode_t mode,
                               int flags)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_fchmodat: dirfd=%d pathname='%s' mode=%d flags=%x",
               dirfd, tmp, mode, flags);
}
static void sys_enter_nanosleep(const struct timespec *req,
                                struct timespec *rem)
{
    const struct __kernel_timespec *r = (struct __kernel_timespec *)req;
    long tv_sec = BPF_CORE_READ_USER(r, tv_sec);
    long tv_nsec = BPF_CORE_READ_USER(r, tv_nsec);
    bpf_printk("sys_enter_nanosleep: req=%lx tv_sec=%lu tv_nsec=%lu", req,
               tv_sec, tv_nsec);
}
static void
sys_enter_futex(uint32_t *uaddr, int futex_op, uint32_t val,
                const struct timespec *timeout, /* or: uint32_t val2 */
                uint32_t *uaddr2, uint32_t val3)
{
    const struct __kernel_timespec *r = (struct __kernel_timespec *)timeout;
    long tv_sec = BPF_CORE_READ_USER(r, tv_sec);
    long tv_nsec = BPF_CORE_READ_USER(r, tv_nsec);
    bpf_printk("sys_enter_futex: uaddr=%lx futex_op=%x val=%x tv_sec=%lu "
               "tv_nsec=%lu uaddr2=%lx val3=%x",
               uaddr, futex_op, val, tv_sec, tv_nsec, uaddr2, val3);
}
static void sys_enter_select(int nfds, fd_set *readfds, fd_set *writefds,
                             fd_set *exceptfds, struct timeval *timeout)
{
    const struct __kernel_old_timeval *r =
        (struct __kernel_old_timeval *)timeout;
    long tv_sec = BPF_CORE_READ_USER(r, tv_sec);
    long tv_usec = BPF_CORE_READ_USER(r, tv_usec);
    bpf_printk("sys_enter_select: nfds=%d readfds=%lx writefds=%lx "
               "exceptfds=%lx tv_sec=%lu tv_usec=%lu",
               nfds, readfds, writefds, exceptfds, tv_sec, tv_usec);
}
static void sys_enter_poll(struct pollfd *fds, nfds_t nfds, int timeout)
{
    bpf_printk("sys_enter_poll: nfds=%lu fds=%lx timeout=%d", nfds, fds,
               timeout);
}
static void sys_enter_epoll_create(int size)
{
    bpf_printk("sys_enter_epoll_create: size=%d", size);
}
static void sys_enter_epoll_create1(int flags)
{
    bpf_printk("sys_enter_epoll_create1: flags=%x", flags);
}
static void sys_enter_epoll_ctl(int epfd, int op, int fd,
                                struct epoll_event *event)
{
    uint32_t events = BPF_CORE_READ_USER(event, events);
    uint64_t data = BPF_CORE_READ_USER(event, data);
    bpf_printk(
        "sys_enter_epoll_ctl: epfd=%d op=%x fd=%d event=%lx events=%x data=%lx",
        epfd, op, fd, event, events, data);
}
static void sys_enter_epoll_wait(int epfd, struct epoll_event *events,
                                 int maxevents, int timeout)
{
    bpf_printk(
        "sys_enter_epoll_wait: epfd=%d maxevents=%d events=%lx timeout=%d",
        epfd, maxevents, events, timeout);
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

static inline void __syscall_enter(__u64 id, __u64 di, __u64 si, __u64 dx,
                                   __u64 r10, __u64 r8, __u64 r9)
{
    switch (id) {
    case __NR_read: {
        sys_enter_read(di, (void *)si, dx);
    } break;
    case __NR_write: {
        sys_enter_write(di, (void *)si, dx);
    } break;
    case __NR_openat: {
        sys_enter_openat(di, (void *)si, dx, r10);
    } break;
    case __NR_open: {
        sys_enter_open((void *)di, si, dx);
    } break;
    case __NR_stat: {
        sys_enter_stat((void *)di, (void *)si);
    } break;
    case __NR_fstat: {
        sys_enter_fstat(di, (void *)si);
    } break;
    case __NR_lstat: {
        sys_enter_lstat((void *)di, (void *)si);
    } break;
    case __NR_newfstatat: {
        sys_enter_fstatat(di, (void *)si, (void *)dx, r10);
    } break;
    case __NR_lseek: {
        sys_enter_lseek(di, si, dx);
    } break;
    case __NR_mprotect: {
        sys_enter_mprotect((void *)di, si, dx);
    } break;
    case __NR_readv: {
        sys_enter_readv(di, (void *)si, dx);
    } break;
    case __NR_writev: {
        sys_enter_writev(di, (void *)si, dx);
    } break;
    case __NR_access: {
        sys_enter_access((void *)di, si);
    } break;
    case __NR_faccessat: {
        sys_enter_faccessat(di, (void *)si, dx, r10);
    } break;
    case __NR_faccessat2: {
        sys_enter_faccessat2(di, (void *)si, dx, r10);
    } break;
    case __NR_pipe: {
        sys_enter_pipe((void *)di);
    } break;
    case __NR_pipe2: {
        sys_enter_pipe2((void *)di, si);
    } break;
    case __NR_sched_yield: {
        sys_enter_sched_yield();
    } break;
    case __NR_unlink: {
        sys_enter_unlink((void *)di);
    } break;
    case __NR_unlinkat: {
        sys_enter_unlinkat(di, (void *)si, dx);
    } break;
    case __NR_close: {
        sys_enter_close(di);
    } break;
    case __NR_brk: {
        sys_enter_brk((void *)di);
    } break;
    case __NR_mmap: {
        sys_enter_mmap((void *)di, si, dx, r10, r8, r9);
    } break;
    case __NR_mremap: {
        sys_enter_mremap((void *)di, si, dx, r10);
    } break;
    case __NR_msync: {
        sys_enter_msync((void *)di, si, dx);
    } break;
    case __NR_madvise: {
        sys_enter_madvise((void *)di, si, dx);
    } break;
    case __NR_munmap: {
        sys_enter_munmap((void *)di, si);
    } break;
    case __NR_dup: {
        sys_enter_dup(di);
    } break;
    case __NR_dup2: {
        sys_enter_dup2(di, si);
    } break;
    case __NR_dup3: {
        sys_enter_dup3(di, si, dx);
    } break;
    case __NR_pause: {
        sys_enter_pause();
    } break;
    case __NR_sendfile: {
        sys_enter_sendfile(di, si, (void *)dx, r10);
    } break;
    case __NR_socket: {
        sys_enter_socket(di, si, dx);
    } break;
    case __NR_connect: {
        sys_enter_connect(di, (void *)si, dx);
    } break;
    case __NR_accept: {
        sys_enter_accept(di, (void *)si, (void *)dx);
    } break;
    case __NR_accept4: {
        sys_enter_accept4(di, (void *)si, (void *)dx, r10);
    } break;
    case __NR_sendto: {
        sys_enter_sendto(di, (void *)si, dx, r10, (void *)r8, r9);
    } break;
    case __NR_sendmsg: {
        sys_enter_sendmsg(di, (void *)si, dx);
    } break;
    case __NR_sendmmsg: {
        sys_enter_sendmmsg(di, (void *)si, dx, r10);
    } break;
    case __NR_recvfrom: {
        sys_enter_recvfrom(di, (void *)si, dx, r10, (void *)r8, (void *)r9);
    } break;
    case __NR_recvmsg: {
        sys_enter_recvmsg(di, (void *)si, dx);
    } break;
    case __NR_recvmmsg: {
        sys_enter_recvmmsg(di, (void *)si, dx, r10, (void *)r8);
    } break;
    case __NR_shutdown: {
        sys_enter_shutdown(di, si);
    } break;
    case __NR_bind: {
        sys_enter_bind(di, (void *)si, dx);
    } break;
    case __NR_listen: {
        sys_enter_listen(di, si);
    } break;
    case __NR_getsockname: {
        sys_enter_getsockname(di, (void *)si, (void *)dx);
    } break;
    case __NR_getpeername: {
        sys_enter_getpeername(di, (void *)si, (void *)dx);
    } break;
    case __NR_socketpair: {
        sys_enter_socketpair(di, si, dx, (void *)r10);
    } break;
    case __NR_setsockopt: {
        sys_enter_setsockopt(di, si, dx, (void *)r10, r8);
    } break;
    case __NR_getsockopt: {
        sys_enter_getsockopt(di, si, dx, (void *)r10, (void *)r8);
    } break;
    case __NR_clone: {
        sys_enter_clone((void *)di, (void *)si, dx, (void *)r10);
    } break;
    case __NR_clone3: {
        sys_enter_clone3((void *)di, si);
    } break;
    case __NR_fork: {
        sys_enter_fork();
    } break;
    case __NR_vfork: {
        sys_enter_vfork();
    } break;
    case __NR_execve: {
        sys_enter_execve((void *)di, (void *)si, (void *)dx);
    } break;
    case __NR_exit: {
        sys_enter_exit(di);
    } break;
    case __NR_exit_group: {
        sys_enter_exit_group(di);
    } break;
    case __NR_wait4: {
        sys_enter_wait4(di, (void *)si, dx, (void *)r10);
    } break;
    case __NR_kill: {
        sys_enter_kill(di, si);
    } break;
    case __NR_fcntl: {
        sys_enter_fcntl(di, si);
    } break;
    case __NR_flock: {
        sys_enter_flock(di, si);
    } break;
    case __NR_fsync: {
        sys_enter_fsync(di);
    } break;
    case __NR_fdatasync: {
        sys_enter_fdatasync(di);
    } break;
    case __NR_truncate: {
        sys_enter_truncate((void *)di, si);
    } break;
    case __NR_ftruncate: {
        sys_enter_ftruncate(di, si);
    } break;
    case __NR_getcwd: {
        sys_enter_getcwd((void *)di, si);
    } break;
    case __NR_chdir: {
        sys_enter_chdir((void *)di);
    } break;
    case __NR_fchdir: {
        sys_enter_fchdir(di);
    } break;
    case __NR_rename: {
        sys_enter_rename((void *)di, (void *)si);
    } break;
    case __NR_mkdir: {
        sys_enter_mkdir((void *)di, si);
    } break;
    case __NR_rmdir: {
        sys_enter_rmdir((void *)di);
    } break;
    case __NR_creat: {
        sys_enter_creat((void *)di, si);
    } break;
    case __NR_link: {
        sys_enter_link((void *)di, (void *)si);
    } break;
    case __NR_linkat: {
        sys_enter_linkat(di, (void *)si, dx, (void *)r10, r8);
    } break;
    case __NR_symlink: {
        sys_enter_symlink((void *)di, (void *)si);
    } break;
    case __NR_readlink: {
        sys_enter_readlink((void *)di, (void *)si, dx);
    } break;
    case __NR_chmod: {
        sys_enter_chmod((void *)di, si);
    } break;
    case __NR_fchmod: {
        sys_enter_fchmod(di, si);
    } break;
    case __NR_fchmodat: {
        sys_enter_fchmodat(di, (void *)si, dx, r10);
    } break;
    case __NR_symlinkat: {
        sys_enter_symlinkat((void *)di, si, (void *)dx);
    } break;
    case __NR_nanosleep: {
        sys_enter_nanosleep((void *)di, (void *)si);
    } break;
    case __NR_futex: {
        sys_enter_futex((void *)di, si, dx, (void *)r10, (void *)r8, r9);
    } break;
    case __NR_select: {
        sys_enter_select(di, (void *)si, (void *)dx, (void *)r10, (void *)r8);
    } break;
    case __NR_poll: {
        sys_enter_poll((void *)di, si, dx);
    } break;
    case __NR_epoll_create: {
        sys_enter_epoll_create(di);
    } break;
    case __NR_epoll_create1: {
        sys_enter_epoll_create1(di);
    } break;
    case __NR_epoll_ctl: {
        sys_enter_epoll_ctl(di, si, dx, (void *)r10);
    } break;
    case __NR_epoll_wait: {
        sys_enter_epoll_wait(di, (void *)si, dx, r10);
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
        bpf_printk("sys_enter[%lu] di=%lx si=%lx dx=%lx r10=%lx r8=%lx r9=%lx",
                   id, di, si, dx, r10, r8, r9);
        __syscall_enter(id, di, si, dx, r10, r8, r9);
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
        __u64 ax = BPF_CORE_READ(args, ax);
        __u64 di = BPF_CORE_READ(args, di);
        __u64 si = BPF_CORE_READ(args, si);
        __u64 dx = BPF_CORE_READ(args, dx);
        __u64 r10 = BPF_CORE_READ(args, r10);
        __u64 r8 = BPF_CORE_READ(args, r8);
        __u64 r9 = BPF_CORE_READ(args, r9);
        bpf_printk("sys_exit[%lu]: ax=%lx di=%lx si=%lx dx=%lx r10=%lx r8=%lx "
                   "r9=%lx delta=%lu slots[%lu]=%lu\n",
                   id, ax, di, si, dx, r10, r8, r9, delta, slot, counter);
    }

    return 0;
}
