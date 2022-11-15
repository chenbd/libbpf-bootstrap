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
typedef uint32_t id_t;      /* LP64 sitll has a 32-bit socklen_t. */

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
static void sys_enter_ioctl(int fd, unsigned long request)
{
    bpf_printk("sys_enter_ioctl: fd=%d request=%lx", fd, request);
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
    bpf_printk("sys_enter_socket: domain=%d type=%x protocol=%d", domain, type,
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
    bpf_printk("sys_enter_socketpair: domain=%d type=%x protocol=%d sv=%lx",
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
static void sys_enter_chown(const char *pathname, uid_t owner, gid_t group)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_chown: pathname='%s' owner=%d group=%d", tmp, owner,
               group);
}
static void sys_enter_fchown(int fd, uid_t owner, gid_t group)
{
    bpf_printk("sys_enter_fchown: fd=%d owner=%d group=%d", fd, owner, group);
}
static void sys_enter_lchown(const char *pathname, uid_t owner, gid_t group)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_lchown: pathname='%s' owner=%d group=%d", tmp, owner,
               group);
}
static void sys_enter_umask(mode_t mask)
{
    bpf_printk("sys_enter_umask: mask=%d", mask);
}
static void sys_enter_gettimeofday(struct timeval *tv, struct timezone *tz)
{
    bpf_printk("sys_enter_gettimeofday: tv=%lx tz=%lx", tv, tz);
}
static void sys_enter_settimeofday(const struct timeval *tv,
                                   const struct timezone *tz)
{
    bpf_printk("sys_enter_settimeofday: tv=%lx tz=%lx", tv, tz);
}
static void sys_enter_utime(const char *filename, const struct utimbuf *times)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), filename);
    bpf_printk("sys_enter_utime: filename='%s' times=%lx", tmp, times);
}
static void sys_enter_utimes(const char *filename,
                             const struct timeval *times /* [2] */)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), filename);
    bpf_printk("sys_enter_utimes: filename='%s' times=%lx", tmp, times);
}
static void sys_enter_ustat(dev_t dev, struct ustat *ubuf)
{
    bpf_printk("sys_enter_ustat: dev=%u ubuf=%lx", dev, ubuf);
}
static void sys_enter_statfs(const char *path, struct statfs *buf)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), path);
    bpf_printk("sys_enter_statfs: path='%s' buf=%lx", tmp, buf);
}
static void sys_enter_fstatfs(int fd, struct statfs *buf)
{
    bpf_printk("sys_enter_fstatfs: fd=%d buf=%lx", fd, buf);
}
static void sys_enter_getpriority(int which, id_t who)
{
    bpf_printk("sys_enter_getpriority: which=%d who=%d", which, who);
}
static void sys_enter_setpriority(int which, id_t who, int prio)
{
    bpf_printk("sys_enter_setpriority: which=%d who=%d prio=%d", which, who,
               prio);
}
static void sys_enter_sched_setparam(pid_t pid, const struct sched_param *param)
{
    bpf_printk("sys_enter_sched_setparamm: pid=%d param=%lx", pid, param);
}
static void sys_enter_sched_getparam(pid_t pid, struct sched_param *param)
{
    bpf_printk("sys_enter_sched_getparamm: pid=%d param=%lx", pid, param);
}
static void sys_enter_sched_setscheduler(pid_t pid, int policy,
                                         const struct sched_param *param)
{
    bpf_printk("sys_enter_sched_setscheduler: pid=%d policy=%d param=%lx", pid,
               policy, param);
}
static void sys_enter_sched_getscheduler(pid_t pid)
{
    bpf_printk("sys_enter_sched_getscheduler: pid=%d ", pid);
}
static void sys_enter_mlock(const void *addr, size_t len)
{
    bpf_printk("sys_enter_mlock: addr=%lx len=%lu", addr, len);
}
static void sys_enter_mlock2(const void *addr, size_t len, int flags)
{
    bpf_printk("sys_enter_mlock2: addr=%lx len=%lu flags=%x", addr, len, flags);
}
static void sys_enter_munlock(const void *addr, size_t len)
{
    bpf_printk("sys_enter_munlock: addr=%lx len=%lu", addr, len);
}
static void sys_enter_mlockall(int flags)
{
    bpf_printk("sys_enter_mlockall: flags=%x", flags);
}
static void sys_enter_munlockall(void) { bpf_printk("sys_enter_munlockall: "); }
static void sys_enter_prctl(int option, unsigned long arg2, unsigned long arg3,
                            unsigned long arg4, unsigned long arg5)
{
    bpf_printk("sys_enter_prctl: option=%d arg2=%lx arg3=%lx arg4=%lx arg5=%lx",
               option, arg2, arg3, arg4, arg5);
}
static void sys_enter_getrlimit(int resource, struct rlimit *rlim)
{
    bpf_printk("sys_enter_getrlimit: resource=%d rlim=%lx", resource, rlim);
}
static void sys_enter_setrlimit(int resource, const struct rlimit *rlim)
{
    bpf_printk("sys_enter_setrlimit: resource=%d rlim=%lx", resource, rlim);
}
static void sys_enter_inotify_init(void)
{
    bpf_printk("sys_enter_inotify_init:");
}
static void sys_enter_inotify_init1(int flags)
{
    bpf_printk("sys_enter_inotify_init1: flags=%x", flags);
}
static void sys_enter_inotify_add_watch(int fd, const char *pathname,
                                        uint32_t mask)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_add_watch: fd=%d pathname='%s' mask=%lx", fd, tmp,
               mask);
}
static void sys_enter_inotify_rm_watch(int fd, int wd)
{
    bpf_printk("sys_enter_add_watch: fd=%d wd=%d", fd, wd);
}
static void sys_enter_fallocate(int fd, int mode, off_t offset, off_t len)
{
    bpf_printk("sys_enter_fallocate: fd=%d mode=%d offset=%lu len=%lu", fd,
               mode, offset, len);
}
static void sys_enter_copy_file_range(int fd_in, loff_t *off_in, int fd_out,
                                      loff_t *off_out, size_t len,
                                      unsigned int flags)
{
    bpf_printk("sys_enter_copy_file_range: fd_in=%d off_in=%lx fd_out=%d "
               "off_out=%lx len=%lu flags=%x",
               fd_in, off_in, fd_out, off_out, len, flags);
}
static void sys_enter_getpid() { bpf_printk("sys_enter_getpid:"); }
static void sys_enter_gettid() { bpf_printk("sys_enter_gettid:"); }
static void sys_enter_readlink(const char *pathname, char *buf, size_t bufsiz)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk("sys_enter_readlink: pathname='%s' buf=%lx bufsiz=%lu", tmp, buf,
               bufsiz);
}
static void sys_enter_readlinkat(int dirfd, const char *pathname, char *buf,
                                 size_t bufsiz)
{
    char tmp[256] = {0};
    bpf_core_read_user_str(tmp, sizeof(tmp), pathname);
    bpf_printk(
        "sys_enter_readlinkat: dirfd=%d pathname='%s' buf=%lx bufsiz=%lu",
        dirfd, tmp, buf, bufsiz);
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
    case __NR_open: {
        sys_enter_open((void *)di, si, dx);
    } break;
    case __NR_openat: {
        sys_enter_openat(di, (void *)si, dx, r10);
    } break;
    case __NR_close: {
        sys_enter_close(di);
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
    case __NR_poll: {
        sys_enter_poll((void *)di, si, dx);
    } break;
    case __NR_lseek: {
        sys_enter_lseek(di, si, dx);
    } break;
    case __NR_mmap: {
        sys_enter_mmap((void *)di, si, dx, r10, r8, r9);
    } break;
    case __NR_mprotect: {
        sys_enter_mprotect((void *)di, si, dx);
    } break;
    case __NR_munmap: {
        sys_enter_munmap((void *)di, si);
    } break;
    case __NR_brk: {
        sys_enter_brk((void *)di);
    } break;
    case __NR_rt_sigaction:
    case __NR_rt_sigprocmask:
    case __NR_rt_sigreturn:
    case __NR_pread64:
    case __NR_pwrite64:
        break;
    case __NR_ioctl: {
        sys_enter_ioctl(di, si);
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
    case __NR_select: {
        sys_enter_select(di, (void *)si, (void *)dx, (void *)r10, (void *)r8);
    } break;
    case __NR_sched_yield: {
        sys_enter_sched_yield();
    } break;
    case __NR_mremap: {
        sys_enter_mremap((void *)di, si, dx, r10);
    } break;
    case __NR_msync: {
        sys_enter_msync((void *)di, si, dx);
    } break;
    case __NR_mincore:
    case __NR_shmget:
    case __NR_shmat:
    case __NR_shmctl:
    case __NR_getitimer:
    case __NR_alarm:
    case __NR_setitimer:
        break;
    case __NR_madvise: {
        sys_enter_madvise((void *)di, si, dx);
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
    case __NR_nanosleep: {
        sys_enter_nanosleep((void *)di, (void *)si);
    } break;
    case __NR_getpid: {
        sys_enter_getpid();
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
    case __NR_uname:
    case __NR_semget:
    case __NR_semop:
    case __NR_semctl:
    case __NR_shmdt:
    case __NR_msgget:
    case __NR_msgsnd:
    case __NR_msgrcv:
    case __NR_msgctl:
    case __NR_getdents:
        break;
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
    case __NR_unlink: {
        sys_enter_unlink((void *)di);
    } break;
    case __NR_unlinkat: {
        sys_enter_unlinkat(di, (void *)si, dx);
    } break;
    case __NR_symlink: {
        sys_enter_symlink((void *)di, (void *)si);
    } break;
    case __NR_symlinkat: {
        sys_enter_symlinkat((void *)di, si, (void *)dx);
    } break;
    case __NR_readlink: {
        sys_enter_readlink((void *)di, (void *)si, dx);
    } break;
    case __NR_readlinkat: {
        sys_enter_readlinkat(di, (void *)si, (void *)dx, r10);
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
    case __NR_chown: {
        sys_enter_chown((void *)di, si, dx);
    } break;
    case __NR_fchown: {
        sys_enter_fchown(di, si, dx);
    } break;
    case __NR_lchown: {
        sys_enter_lchown((void *)di, si, dx);
    } break;
    case __NR_umask: {
        sys_enter_umask(di);
    } break;
    case __NR_gettimeofday: {
        sys_enter_gettimeofday((void *)di, (void *)si);
    } break;
    case __NR_settimeofday: {
        sys_enter_settimeofday((void *)di, (void *)si);
    } break;
    case __NR_setrlimit: {
        sys_enter_setrlimit(di, (void *)si);
    } break;
    case __NR_getrlimit: {
        sys_enter_getrlimit(di, (void *)si);
    } break;
    case __NR_getrusage:
    case __NR_sysinfo:
    case __NR_times:
    case __NR_ptrace:
    case __NR_getuid:
    case __NR_syslog:
    case __NR_getgid:
    case __NR_setuid:
    case __NR_setgid:
    case __NR_geteuid:
    case __NR_getegid:
    case __NR_setpgid:
    case __NR_getppid:
    case __NR_getpgrp:
    case __NR_setsid:
    case __NR_setreuid:
    case __NR_setregid:
    case __NR_getgroups:
    case __NR_setgroups:
    case __NR_setresuid:
    case __NR_getresuid:
    case __NR_setresgid:
    case __NR_getresgid:
    case __NR_getpgid:
    case __NR_setfsuid:
    case __NR_setfsgid:
    case __NR_getsid:
    case __NR_capget:
    case __NR_capset:
    case __NR_rt_sigpending:
    case __NR_rt_sigtimedwait:
    case __NR_rt_sigqueueinfo:
    case __NR_rt_sigsuspend:
    case __NR_sigaltstack:
    case __NR_mknod:
    case __NR_uselib:
    case __NR_personality:
    case __NR_sysfs:
        break;
    case __NR_utime: {
        sys_enter_utime((void *)di, (void *)si);
    } break;
    case __NR_utimes: {
        sys_enter_utimes((void *)di, (void *)si);
    } break;
    case __NR_ustat: {
        sys_enter_ustat(di, (void *)si);
    } break;
    case __NR_statfs: {
        sys_enter_statfs((void *)di, (void *)si);
    } break;
    case __NR_fstatfs: {
        sys_enter_fstatfs(di, (void *)si);
    } break;
    case __NR_getpriority: {
        sys_enter_getpriority(di, si);
    } break;
    case __NR_setpriority: {
        sys_enter_setpriority(di, si, dx);
    } break;
    case __NR_sched_getparam: {
        sys_enter_sched_getparam(di, (void *)si);
    } break;
    case __NR_sched_setparam: {
        sys_enter_sched_setparam(di, (void *)si);
    } break;
    case __NR_sched_getscheduler: {
        sys_enter_sched_getscheduler(di);
    } break;
    case __NR_sched_setscheduler: {
        sys_enter_sched_setscheduler(di, si, (void *)dx);
    } break;
    case __NR_sched_get_priority_max:
    case __NR_sched_get_priority_min:
    case __NR_sched_rr_get_interval:
    case __NR_vhangup:
    case __NR_modify_ldt:
    case __NR_pivot_root:
    case __NR__sysctl:
    case __NR_arch_prctl:
    case __NR_adjtimex:
    case __NR_chroot:
    case __NR_sync:
    case __NR_acct:
    case __NR_mount:
    case __NR_umount2:
    case __NR_swapon:
    case __NR_swapoff:
    case __NR_reboot:
    case __NR_sethostname:
    case __NR_setdomainname:
    case __NR_iopl:
    case __NR_ioperm:
    case __NR_create_module:
    case __NR_init_module:
    case __NR_delete_module:
    case __NR_get_kernel_syms:
    case __NR_query_module:
    case __NR_quotactl:
    case __NR_nfsservctl:
    case __NR_getpmsg:
    case __NR_putpmsg:
    case __NR_afs_syscall:
    case __NR_tuxcall:
    case __NR_security:
        break;
    case __NR_mlock: {
        sys_enter_mlock((void *)di, si);
    } break;
    case __NR_mlock2: {
        sys_enter_mlock2((void *)di, si, dx);
    } break;
    case __NR_munlock: {
        sys_enter_munlock((void *)di, si);
    } break;
    case __NR_mlockall: {
        sys_enter_mlockall(di);
    } break;
    case __NR_munlockall: {
        sys_enter_munlockall();
    } break;
    case __NR_prctl: {
        sys_enter_prctl(di, si, dx, r10, r8);
    } break;
    case __NR_gettid: {
        sys_enter_gettid();
    } break;
    case __NR_readahead:
    case __NR_setxattr:
    case __NR_lsetxattr:
    case __NR_fsetxattr:
    case __NR_getxattr:
    case __NR_lgetxattr:
    case __NR_fgetxattr:
    case __NR_listxattr:
    case __NR_llistxattr:
    case __NR_flistxattr:
    case __NR_removexattr:
    case __NR_lremovexattr:
    case __NR_fremovexattr:
    case __NR_tkill:
    case __NR_time:
        break;
    case __NR_futex: {
        sys_enter_futex((void *)di, si, dx, (void *)r10, (void *)r8, r9);
    } break;
    case __NR_sched_setaffinity:
    case __NR_sched_getaffinity:
    case __NR_set_thread_area:
    case __NR_io_setup:
    case __NR_io_destroy:
    case __NR_io_getevents:
    case __NR_io_submit:
    case __NR_io_cancel:
    case __NR_get_thread_area:
    case __NR_lookup_dcookie:
        break;
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
    case __NR_epoll_ctl_old:
    case __NR_epoll_wait_old:
    case __NR_remap_file_pages:
    case __NR_getdents64:
    case __NR_set_tid_address:
    case __NR_restart_syscall:
    case __NR_semtimedop:
    case __NR_fadvise64:
    case __NR_timer_create:
    case __NR_timer_settime:
    case __NR_timer_gettime:
    case __NR_timer_getoverrun:
    case __NR_timer_delete:
    case __NR_clock_settime:
    case __NR_clock_gettime:
    case __NR_clock_getres:
    case __NR_tgkill:
        break;
    case __NR_clock_nanosleep: {
        sys_enter_clock_nanosleep(di, si, (const struct timespec *)dx,
                                  (struct timespec *)r10);
    } break;
    case __NR_vserver:
    case __NR_mbind:
    case __NR_set_mempolicy:
    case __NR_get_mempolicy:
    case __NR_mq_open:
    case __NR_mq_unlink:
    case __NR_mq_timedsend:
    case __NR_mq_timedreceive:
    case __NR_mq_notify:
    case __NR_mq_getsetattr:
    case __NR_kexec_load:
    case __NR_waitid:
    case __NR_add_key:
    case __NR_request_key:
    case __NR_keyctl:
    case __NR_ioprio_set:
    case __NR_ioprio_get:
    case __NR_migrate_pages:
    case __NR_mknodat:
    case __NR_futimesat:
        break;
    case __NR_inotify_init: {
        sys_enter_inotify_init();
    } break;
    case __NR_inotify_init1: {
        sys_enter_inotify_init1(di);
    } break;
    case __NR_inotify_add_watch: {
        sys_enter_inotify_add_watch(di, (void *)si, dx);
    } break;
    case __NR_inotify_rm_watch: {
        sys_enter_inotify_rm_watch(di, si);
    } break;
    case __NR_pselect6:
    case __NR_ppoll:
    case __NR_unshare:
    case __NR_set_robust_list:
    case __NR_get_robust_list:
    case __NR_splice:
    case __NR_tee:
    case __NR_sync_file_range:
    case __NR_vmsplice:
    case __NR_move_pages:
    case __NR_utimensat:
    case __NR_epoll_pwait:
    case __NR_signalfd:
    case __NR_timerfd_create:
    case __NR_eventfd:
    case __NR_timerfd_settime:
    case __NR_timerfd_gettime:
    case __NR_signalfd4:
    case __NR_eventfd2:
    case __NR_preadv:
    case __NR_pwritev:
    case __NR_rt_tgsigqueueinfo:
    case __NR_perf_event_open:
        break;
    case __NR_fallocate: {
        sys_enter_fallocate(di, si, dx, r10);
    } break;
    case __NR_copy_file_range: {
        sys_enter_copy_file_range(di, (void *)si, dx, (void *)r10, r8, r9);
    } break;
    case __NR_bpf: {
        sys_enter_bpf(di, (union bpf_attr *)si, dx);
    } break;
    case __NR_fanotify_init:
    case __NR_fanotify_mark:
    case __NR_prlimit64:
    case __NR_name_to_handle_at:
    case __NR_open_by_handle_at:
    case __NR_clock_adjtime:
    case __NR_syncfs:
    case __NR_setns:
    case __NR_getcpu:
    case __NR_process_vm_readv:
    case __NR_process_vm_writev:
    case __NR_kcmp:
    case __NR_finit_module:
    case __NR_sched_setattr:
    case __NR_sched_getattr:
    case __NR_renameat2:
    case __NR_seccomp:
    case __NR_getrandom:
    case __NR_memfd_create:
    case __NR_kexec_file_load:
    case __NR_execveat:
    case __NR_userfaultfd:
    case __NR_membarrier:
    case __NR_preadv2:
    case __NR_pwritev2:
    case __NR_pkey_mprotect:
    case __NR_pkey_alloc:
    case __NR_pkey_free:
    case __NR_statx:
    case __NR_io_pgetevents:
    case __NR_rseq:
    case __NR_pidfd_send_signal:
    case __NR_io_uring_setup:
    case __NR_io_uring_enter:
    case __NR_io_uring_register:
    case __NR_open_tree:
    case __NR_move_mount:
    case __NR_fsopen:
    case __NR_fsconfig:
    case __NR_fsmount:
    case __NR_fspick:
    case __NR_pidfd_open:
    case __NR_close_range:
    case __NR_openat2:
    case __NR_pidfd_getfd:
    case __NR_process_madvise:
    case __NR_epoll_pwait2:
    case __NR_mount_setattr:
    case __NR_quotactl_fd:
    case __NR_landlock_create_ruleset:
    case __NR_landlock_add_rule:
    case __NR_landlock_restrict_self:
    case __NR_memfd_secret:
    case __NR_process_mrelease:
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
