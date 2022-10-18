# libbpf-bootstrap: demo BPF applications

[![Github Actions](https://github.com/libbpf/libbpf-bootstrap/actions/workflows/build.yml/badge.svg)](https://github.com/libbpf/libbpf-bootstrap/actions/workflows/build.yml)

## Minimal

`minimal` is just that – a minimal practical BPF application example. It
doesn't use or require BPF CO-RE, so should run on quite old kernels. It
installs a tracepoint handler which is triggered once every second. It uses
`bpf_printk()` BPF helper to communicate with the world. To see it's output,
read `/sys/kernel/debug/tracing/trace_pipe` file as a root:

```shell
$ cd examples/c
$ make minimal
$ sudo ./minimal
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-3840345 [010] d... 3220701.101143: bpf_trace_printk: BPF triggered from PID 3840345.
           <...>-3840345 [010] d... 3220702.101265: bpf_trace_printk: BPF triggered from PID 3840345.
```

`minimal` is great as a bare-bones experimental playground to quickly try out
new ideas or BPF features.

## Minimal_Legacy

This version of `minimal` is modified to allow running on even older kernels
that do not allow global variables. bpf_printk uses global variables unless
BPF_NO_GLOBAL_DATA is defined before including bpf_helpers.h. Additionally,
the global variable my_pid has been replaced with an array of one element to
hold the process pid.

```
$ cd examples/c
$ make minimal_legacy
$ sudo ./minimal_legacy
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
  minimal_legacy-52030 [001] .... 491227.784078: 0x00000001: BPF triggered from PID 52030.
  minimal_legacy-52030 [001] .... 491228.840571: 0x00000001: BPF triggered from PID 52030.
  minimal_legacy-52030 [001] .... 491229.841643: 0x00000001: BPF triggered from PID 52030.
  minimal_legacy-52030 [001] .... 491230.842432: 0x00000001: BPF triggered from PID 52030.
```

## Bootstrap

`bootstrap` is an example of a simple (but realistic) BPF application. It
tracks process starts (`exec()` family of syscalls, to be precise) and exits
and emits data about filename, PID and parent PID, as well as exit status and
duration of the process life. With `-d <min-duration-ms>` you can specify
minimum duration of the process to log. In such mode process start
(technically, `exec()`) events are not output (see example output below).

`bootstrap` was created in the similar spirit as
[libbpf-tools](https://github.com/iovisor/bcc/tree/master/libbpf-tools) from
BCC package, but is designed to be more stand-alone and with simpler Makefile
to simplify adoption to user's particular needs. It demonstrates the use of
typical BPF features:
  - cooperating BPF programs (tracepoint handlers for process `exec` and `exit`
    events, in this particular case);
  - BPF map for maintaining the state;
  - BPF ring buffer for sending data to user-space;
  - global variables for application behavior parameterization.
  - it utilizes BPF CO-RE and vmlinux.h to read extra process information from
    kernel's `struct task_struct`.

`bootstrap` is intended to be the starting point for your own BPF application,
with things like BPF CO-RE and vmlinux.h, consuming BPF ring buffer data,
command line arguments parsing, graceful Ctrl-C handling, etc. all taken care
of for you, which are crucial but mundane tasks that are no fun, but necessary
to be able to do anything useful. Just copy/paste and do simple renaming to get
yourself started.

Here's an example output in minimum process duration mode:

```shell
$ sudo ./bootstrap -d 50
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
19:18:32 EXIT  timeout          3817109 402466  [0] (126ms)
19:18:32 EXIT  sudo             3817117 3817111 [0] (259ms)
19:18:32 EXIT  timeout          3817110 402466  [0] (264ms)
19:18:33 EXIT  python3.7        3817083 1       [0] (1026ms)
19:18:38 EXIT  python3          3817429 3817424 [1] (60ms)
19:18:38 EXIT  sh               3817424 3817420 [0] (79ms)
19:18:38 EXIT  timeout          3817420 402466  [0] (80ms)
19:18:43 EXIT  timeout          3817610 402466  [0] (70ms)
19:18:43 EXIT  grep             3817619 3817617 [1] (271ms)
19:18:43 EXIT  timeout          3817609 402466  [0] (321ms)
19:18:44 EXIT  iostat           3817585 3817531 [0] (3006ms)
19:18:44 EXIT  tee              3817587 3817531 [0] (3005ms)
...
```

## Uprobe

`uprobe` is an example of dealing with user-space entry and exit (return) probes,
`uprobe` and `uretprobe` in libbpf lingo. It attached `uprobe` and `uretprobe`
BPF programs to its own functions (`uprobed_add()` and `uprobed_sub()`) and logs input arguments
and return result, respectively, using `bpf_printk()` macro. The user-space
function is triggered once every second:

```shell
$ sudo ./uprobe
libbpf: loading object 'uprobe_bpf' from buffer
...
Successfully started!
...........
```

You can see `uprobe` demo output in `/sys/kernel/debug/tracing/trace_pipe`:
```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
          uprobe-1809291 [007] .... 4017233.106596: 0: uprobed_add ENTRY: a = 0, b = 1
          uprobe-1809291 [007] .... 4017233.106605: 0: uprobed_add EXIT: return = 1
          uprobe-1809291 [007] .... 4017233.106606: 0: uprobed_sub ENTRY: a = 0, b = 0
          uprobe-1809291 [007] .... 4017233.106607: 0: uprobed_sub EXIT: return = 0
          uprobe-1809291 [007] .... 4017234.106694: 0: uprobed_add ENTRY: a = 1, b = 2
          uprobe-1809291 [007] .... 4017234.106697: 0: uprobed_add EXIT: return = 3
          uprobe-1809291 [007] .... 4017234.106700: 0: uprobed_sub ENTRY: a = 1, b = 1
          uprobe-1809291 [007] .... 4017234.106701: 0: uprobed_sub EXIT: return = 0
```

## Uprobe

`uprobeprofiler` is an example of profiling with user-space entry and exit (return) probes,
`uprobe` and `uretprobe` in libbpf lingo. It attached `uprobe` and `uretprobe`
BPF programs to user specified function by address(with `-a <address>` option)  or function name(with `-n <symbol>` option)
or library name and function name(with `-f <library:symbol>` option) to specified process(with `-p <pid>` option, -1 for any process).
`-s` maybe also be specified to collect stack trace. The `uprobeprofiler` uses map for collecting function call latency in micro seconds and counter, display in stand output as the following:


```shell
$ sudo ./uprobeprofiler -p 1262767 -n malloc
symbol='malloc' found in '/usr/lib/x86_64-linux-gnu/libc.so.6' off=a5120
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.

profiling address='0x7f0af01cd120' symbol='malloc' for pid 1262767:
		Microseconds	 : Count
---------------------------------| Total=0
....
profiling address='0x7f0af01cd120' symbol='malloc' for pid 1262767:
		Microseconds	 : Count
	[       0	       1]:      146 (44.92%)
	[       2	       3]:      167 (51.38%)
	[       4	       7]:        9 (2.77%)
	[       8	      15]:        1 (0.31%)
	[      16	      31]:        2 (0.62%)
---------------------------------| Total=325
```

```shell
$ sudo ./uprobeprofiler -p -1 -f /usr/lib/x86_64-linux-gnu/libc.so.6:malloc
symbol='malloc' found in '/usr/lib/x86_64-linux-gnu/libc.so.6' off=a5120
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.

profiling address='(nil)' symbol='malloc' for pid -1:
		Microseconds	 : Count
	[       4	       7]:        1 (100.00%)
---------------------------------| Total=1
....
profiling address='(nil)' symbol='malloc' for pid -1:
		Microseconds	 : Count
	[       0	       1]:     4100 (10.61%)
	[       2	       3]:    26885 (69.59%)
	[       4	       7]:     7090 (18.35%)
	[       8	      15]:      398 (1.03%)
	[      16	      31]:      146 (0.38%)
	[      32	      63]:       14 (0.04%)
---------------------------------| Total=38633
```

```shell
$ sudo ./uprobeprofiler -p 462573 -n free -s
symbol='free' found in '/usr/lib/x86_64-linux-gnu/libc.so.6' off=a5460
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.

profiling address='0x7f759a657460' symbol='free' for pid 462573:
		Microseconds	 : Count
---------------------------------| Total=0
....
profiling address='0x7f759a657460' symbol='free' for pid 462573:
		Microseconds	 : Count
	[       8	      15]:        3 (37.50%)
	[      16	      31]:        4 (50.00%)
	[      32	      63]:        1 (12.50%)
---------------------------------| Total=8
[0]: 57 us	stackid: 8216
[1]: 23 us	stackid: 8216
[2]: 19 us	stackid: 8216
stackid=8216 counter=4
  0 [<00007f759a1d99e7>] user_timeout_cb+0x97
  1 [<00007f759a1d3a06>] h2o_evloop_run+0x86
  2 [<00007f759a1d9c4e>] client_loop+0x25e
  3 [<00007f759a646b43>] pthread_condattr_setpshared+0x513
stackid=8497 counter=4
  0 [<00007f759a18d0fd>] _ZN4cmap14CMapLocalCache16GetTokenWorkUnitD0Ev+0xd
  1 [<00007f759a5923e3>] _ZN10foundation9WorkQueue10threadLoopEv+0xe3
  2 [<00007f759a592464>] _ZN10foundation9WorkQueue10WorkThread10threadLoopEv+0x14
  3 [<00007f759a593419>] _ZN10foundation6Thread11_threadLoopEPv+0x129
  4 [<00007f759a646b43>] pthread_condattr_setpshared+0x513
```


## Rawtracepoint

`syscallprofiler` is an example of profiling with system call entry and exit,
`raw_tracepoint` in libbpf lingo. It attached `sys_enter` and `sys_exit`
BPF programs to user specified system call no(with `-c <syscall no>` option)  or system call name(with `-n <syscall name>` option)
to specified process(with `-p <pid>` option, -1 for any process).
The `syscallprofiler` uses map for collecting function call latency in micro seconds and counter, display in stand output as the following:

```shell
$ sudo ./syscallprofiler  -p -1 -n ioctl
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF programs.

profiling syscall=16(ioctl) for pid -1:
		Microseconds	 : Count
---------------------------------| Total=0
..........
profiling syscall=16(ioctl) for pid -1:
		Microseconds	 : Count
	[       0	       1]:      646 (27.64%)
	[       2	       3]:        8 (0.34%)
	[       4	       7]:      265 (11.34%)
	[       8	      15]:       47 (2.01%)
	[      16	      31]:      251 (10.74%)
	[      32	      63]:      420 (17.97%)
	[      64	     127]:      682 (29.18%)
	[     128	     255]:       18 (0.77%)
---------------------------------| Total=2337
```

## USDT

`usdt` is an example of dealing with USDT probe. It attaches USDT BPF programs to
the [libc:setjmp](https://www.gnu.org/software/libc/manual/html_node/Non_002dlocal-Goto-Probes.html) probe, which is triggered by calling `setjmp` in user-space program once per second and logs USDT arguments using `bpf_printk()` macro:

```shell
$ sudo ./usdt
libbpf: loading object 'usdt_bpf' from buffer
...
Successfully started!
...........
```

You can see `usdt` demo output in `/sys/kernel/debug/tracing/trace_pipe`:
```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            usdt-1919077 [005] d..21 537310.886092: bpf_trace_printk: USDT auto attach to libc:setjmp: arg1 = 55d03d6a42a0, arg2 = 0, arg3 = 55d03d65e54e
            usdt-1919077 [005] d..21 537310.886105: bpf_trace_printk: USDT manual attach to libc:setjmp: arg1 = 55d03d6a42a0, arg2 = 0, arg3 = 55d03d65e54e
            usdt-1919077 [005] d..21 537311.886214: bpf_trace_printk: USDT auto attach to libc:setjmp: arg1 = 55d03d6a42a0, arg2 = 0, arg3 = 55d03d65e54e
            usdt-1919077 [005] d..21 537311.886227: bpf_trace_printk: USDT manual attach to libc:setjmp: arg1 = 55d03d6a42a0, arg2 = 0, arg3 = 55d03d65e54e
```

## Fentry

`fentry` is an example that uses fentry and fexit BPF programs for tracing. It
attaches `fentry` and `fexit` traces to `do_unlinkat()` which is called when a
file is deleted and logs the return value, PID, and filename to the
trace pipe.

Important differences, compared to kprobes, are improved performance and
usability. In this example, better usability is shown with the ability to
directly dereference pointer arguments, like in normal C, instead of using
various read helpers. The big distinction between **fexit** and **kretprobe**
programs is that fexit one has access to both input arguments and returned
result, while kretprobe can only access the result.

fentry and fexit programs are available starting from 5.5 kernels.

```shell
$ sudo ./fentry
libbpf: loading object 'fentry_bpf' from buffer
...
Successfully started!
..........
```

The `fentry` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file, ret = 0
              rm-9290    [004] d..2  4637.798698: bpf_trace_printk: fentry: pid = 9290, filename = test_file2
              rm-9290    [004] d..2  4637.798843: bpf_trace_printk: fexit: pid = 9290, filename = test_file2, ret = 0
```

## Kprobe

`kprobe` is an example of dealing with kernel-space entry and exit (return)
probes, `kprobe` and `kretprobe` in libbpf lingo. It attaches `kprobe` and
`kretprobe` BPF programs to the `do_unlinkat()` function and logs the PID,
filename, and return result, respectively, using `bpf_printk()` macro.

```shell
$ sudo ./kprobe
libbpf: loading object 'kprobe_bpf' from buffer
...
Successfully started!
...........
```

The `kprobe` demo output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
              rm-9346    [005] d..3  4710.951696: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test1
              rm-9346    [005] d..4  4710.951819: bpf_trace_printk: KPROBE EXIT: ret = 0
              rm-9346    [005] d..3  4710.951852: bpf_trace_printk: KPROBE ENTRY pid = 9346, filename = test2
              rm-9346    [005] d..4  4710.951895: bpf_trace_printk: KPROBE EXIT: ret = 0
```

## XDP

`xdp` is an example written in Rust (using libbpf-rs). It attaches to
the ingress path of networking device and logs the size of each packet,
returning `XDP_PASS` to allow the packet to be passed up to the kernel’s
networking stack.

```shell
$ sudo ./target/release/xdp 1
..........
```

The `xdp` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```shell
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
           <...>-823887  [000] d.s1 602386.079100: bpf_trace_printk: packet size: 75
           <...>-823887  [000] d.s1 602386.079141: bpf_trace_printk: packet size: 66
           <...>-2813507 [000] d.s1 602386.696702: bpf_trace_printk: packet size: 77
           <...>-2813507 [000] d.s1 602386.696735: bpf_trace_printk: packet size: 66
```

## TC

`tc` (short for Traffic Control) is an example of handling ingress network traffics.
It creates a qdisc on the `lo` interface and attaches the `tc_ingress` BPF program to it.
It reports the metadata of the IP packets that coming into the `lo` interface.

```shell
$ sudo ./tc
...
Successfully started! Please run `sudo cat /sys/kernel/debug/tracing/trace_pipe` to see output of the BPF program.
......
```

The `tc` output in `/sys/kernel/debug/tracing/trace_pipe` should look
something like this:

```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
            node-1254811 [007] ..s1 8737831.671074: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674334: 0: Got IP packet: tot_len: 79, ttl: 64
            sshd-1254728 [006] ..s1 8737831.674349: 0: Got IP packet: tot_len: 72, ttl: 64
            node-1254811 [007] ..s1 8737831.674550: 0: Got IP packet: tot_len: 71, ttl: 64
```

## Profile

`profile` is an example written in Rust and C with BlazeSym. It
attaches to perf events, sampling on every processor periodically. It
shows addresses, symbols, file names, and line numbers of stacktraces.

```shell
$ sudo ./target/release/profile
COMM: swapper/6 (pid=0) @ CPU 6
Kernel:
  0 [<ffffffff81bdf010>] intel_idle+0x96
  1 [<ffffffff819959b0>] cpuidle_enter_state+0x80 /ro/source/drivers/cpuidle/cpuidle.c:238
  2 [<ffffffff81995cc9>] cpuidle_enter+0x29 /ro/source/drivers/cpuidle/cpuidle.c:353
  3 [<ffffffff810f8c0b>] do_idle+0x1bb /ro/source/kernel/sched/idle.c:243
  4 [<ffffffff810f8de9>] cpu_startup_entry+0x19 /ro/source/kernel/sched/idle.c:396
  5 [<ffffffff81044f46>] start_secondary+0x116 /ro/source/arch/x86/kernel/smpboot.c:272
  6 [<ffffffff810000f5>] secondary_startup_64_no_verify+0xb0 /ro/source/arch/x86/kernel/head_64.S:283
No Userspace Stack
```

C version and Rust version show the same content.  Both of them use BlazeSym to symbolize stacktraces.

## Socket filter

`sockfilter` is an example of monitoring packet and dealing with `__sk_buff`
structure. It attaches `socket` BPF program to `sock_queue_rcv_skb()` function
and retrieve information from `BPF_MAP_TYPE_RINGBUF`, then print
protocol, src IP, src port, dst IP, dst port in standard output.
Currently, most of the IPv4 protocols defined in `uapi/linux/in.h` are included,
please check `ipproto_mapping` of `examples/c/sockfilter.c` for the supported protocols.

```shell
$ sudo ./sockfilter
interface:lo    protocol: UDP   127.0.0.1:51845(src) -> 127.0.0.1:53(dst)
interface:lo    protocol: UDP   127.0.0.1:41552(src) -> 127.0.0.1:53(dst)
```

# Building

libbpf-bootstrap supports multiple build systems that do the same thing.
This serves as a cross reference for folks coming from different backgrounds.

## Install Dependencies

You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros.

On Ubuntu/Debian, you need:
```shell
$ apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:
```shell
$ dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```
## Getting the source code

Download the git repository and check out submodules:
```shell
$ git clone --recurse-submodules https://github.com/libbpf/libbpf-bootstrap
```

## C Examples

Makefile build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd examples/c
$ make
$ sudo ./bootstrap
TIME     EVENT COMM             PID     PPID    FILENAME/EXIT CODE
00:21:22 EXIT  python3.8        4032353 4032352 [0] (123ms)
00:21:22 EXEC  mkdir            4032379 4032337 /usr/bin/mkdir
00:21:22 EXIT  mkdir            4032379 4032337 [0] (1ms)
00:21:22 EXEC  basename         4032382 4032381 /usr/bin/basename
00:21:22 EXIT  basename         4032382 4032381 [0] (0ms)
00:21:22 EXEC  sh               4032381 4032380 /bin/sh
00:21:22 EXEC  dirname          4032384 4032381 /usr/bin/dirname
00:21:22 EXIT  dirname          4032384 4032381 [0] (1ms)
00:21:22 EXEC  readlink         4032387 4032386 /usr/bin/readlink
^C
```

CMake build:

```shell
$ git submodule update --init --recursive       # check out libbpf
$ mkdir build && cd build
$ cmake ../examples/c
$ make
$ sudo ./bootstrap
<...>
```

XMake build (Linux):

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd examples/c
$ xmake
$ xmake run bootstrap
```

XMake build (Android):

```shell
$ git submodule update --init --recursive       # check out libbpf
$ cd examples/c
$ xmake f -p android
$ xmake
```

Install [Xmake](https://github.com/xmake-io/xmake)

```shell
$ bash <(wget https://xmake.io/shget.text -O -)
$ source ~/.xmake/profile
```

## Rust Examples

Install `libbpf-cargo`:
```shell
$ cargo install libbpf-cargo
```

Build using `cargo`:
```shell
$ cd examples/rust
$ cargo build --release
$ sudo ./target/release/xdp 1
<...>
```

# Troubleshooting

Libbpf debug logs are quire helpful to pinpoint the exact source of problems,
so it's usually a good idea to look at them before starting to debug or
posting question online.

`./minimal` is always running with libbpf debug logs turned on.

For `./bootstrap`, run it in verbose mode (`-v`) to see libbpf debug logs:

```shell
$ sudo ./bootstrap -v
libbpf: loading object 'bootstrap_bpf' from buffer
libbpf: elf: section(2) tp/sched/sched_process_exec, size 384, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exec': found program 'handle_exec' at insn offset 0 (0 bytes), code size 48 insns (384 bytes)
libbpf: elf: section(3) tp/sched/sched_process_exit, size 432, link 0, flags 6, type=1
libbpf: sec 'tp/sched/sched_process_exit': found program 'handle_exit' at insn offset 0 (0 bytes), code size 54 insns (432 bytes)
libbpf: elf: section(4) license, size 13, link 0, flags 3, type=1
libbpf: license of bootstrap_bpf is Dual BSD/GPL
...
```
