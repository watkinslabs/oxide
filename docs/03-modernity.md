# 03 Modernity Charter

FROZEN 2026-05-02. Dep:`02`,`08`.

Linux-compatible at modern userspace ABI. Pre-2015 / 4.x-era stuff dropped unless named reason. musl/glibc≥2.34 runs; libc5 doesn't.

## 1 Filter (per feature)

1. Modern Linux still preferred path? Else use the replacement.
2. Fresh musl-linked Go/Rust/Zig today exercise it? Else justify or drop.
3. Costs a verification harness? Drop unless 1+2 say keep.

When in doubt, drop. Add later if needed.

## 2 Syscall keep/drop

| Area | Keep | Drop |
|---|---|---|
| open | `openat2`(`RESOLVE_*`),`openat` | `open`,`creat` |
| stat | `statx` | `stat`,`lstat` (keep `fstat` for fd compat) |
| getdents | `getdents64` | `getdents` (32-bit d_off) |
| process create | `clone3` | `fork`,`vfork`,plain `clone` |
| wait | `waitid`,`pidfd_open/_send_signal/_getfd` | `wait`,`wait3`,`waitpid` (libc wraps waitid) |
| signals | `rt_sig*` | `signal`,`sigaction` (32b sigset),`sgetmask` |
| time | `clock_gettime`,`clock_nanosleep`,`clock_getres`,`timerfd_create` | `time`,`gettimeofday`,`stime`,legacy `adjtimex` |
| mux | `epoll_create1`,`epoll_pwait2`,`ppoll` | `select`,`pselect6`,`poll`,`epoll_create` |
| async I/O | **`io_uring` primary** | POSIX AIO (`io_submit`/`io_getevents`) |
| memory | `mmap`,`mremap`,`mprotect`,`madvise`,`memfd_create`,`userfaultfd` | SysV shm (`shm*`); `brk` only thin libc shim |
| sync | **`futex2` primary**, classic `futex` for compat | — |
| FS notify | `inotify`,`fanotify` | `dnotify` |
| FS misc | `copy_file_range`,`splice`,`sendfile`,`fallocate`,`renameat2`,`*at` family | non-`*at` (libc wraps with AT_FDCWD) |
| sockets | `socket`,`bind`,`listen`,`accept4`,`connect`,`sendmsg`,`recvmsg`,`sendmmsg`,`recvmmsg`,`socketpair`,`shutdown` | `accept`,`send`,`recv` (libc wraps) |
| sandbox | `seccomp(FILTER)`,`prctl(PR_SET_NO_NEW_PRIVS)`,`landlock_*`,`capset`/`capget` v3 | caps v1/v2 |
| namespaces | `unshare`,`setns`,`clone3` w/ `CLONE_NEW*` | — |
| cgroups | **cgroup v2 only**, `/sys/fs/cgroup` unified | cgroup v1 (any) |
| random | `getrandom`(`GRND_RANDOM`/`GRND_INSECURE`) | `/dev/random` blocking pool semantics |
| BPF | `bpf()` (subset: socket filters, kprobes later) | — |
| modules | `finit_module`,`delete_module` (signed) | `init_module` blob, `create_module`,`query_module`,`get_kernel_syms` |
| mount | `fsopen`/`fsconfig`/`fsmount`/`open_tree`/`move_mount`/`mount_setattr` | old `mount(2)` (thin compat shim only) |
| misc | `prctl`,`getrandom`,`membarrier`,`close_range`,`pivot_root` | — |

Hard `ENOSYS`: SysV IPC (msg/sem/shm), a.out/COFF/ECOFF (ELF64 only), `personality()` beyond `PER_LINUX`+`ADDR_NO_RANDOMIZE`, `uselib`,`init_module` (blob),`create_module`,`query_module`,`get_kernel_syms`,`nfsservctl`,`afs_syscall`,`tuxcall`,`vserver`,`iopl`,`ioperm`,`modify_ldt`,`olduname`/`oldolduname`,`fstatfs64`(use `fstatfs`),32-bit time syscalls (`*_time32`).

Linux numbers reserved for dropped → `ENOSYS` (not `EINVAL`, not silent success). Fuzz: every nr 0..1024 asserted.

## 3 Process / thread

- Real threads via `clone3` flags `VM|THREAD|SIGHAND|FS|FILES|SETTLS|PARENT_SETTID|CHILD_CLEARTID`. No `pthread`-over-`fork` ever.
- TLS: `fs_base` x86, `tpidr_el0` arm. Set via `arch_prctl(ARCH_SET_FS)` / `clone3.tls`.
- PID: 32-bit, sparse IDR alloc, no reuse while pidfd open.
- Reap: `pidfd`+`waitid`. SIGCHLD secondary.
- ptrace: gdb/strace subset; no legacy `PTRACE_PEEKUSR` for non-current arch reg sets.

## 4 Memory

- 48-bit canonical VA both arches; 5-level (57-bit) tracked as a later phase.
- `MAP_FIXED_NOREPLACE` default placement; `MAP_FIXED` opt-in overwrite.
- THP: madvise-only, never "always".
- userfaultfd: yes (Go, CRIU need).
- memfd_secret: yes (no kernel direct map).
- No swap to disk; zram-style tracked as later phase.

## 5 Filesystems

| Kept | Notes |
|---|---|
| tmpfs | scratch |
| devtmpfs | `/dev` populated by kernel |
| proc | modern subset; legacy `/proc/sys` knobs absent |
| sysfs | driver model |
| cgroup2 | unified `/sys/fs/cgroup` |
| ext4 | RW; journal mandatory; `metadata_csum`,`64bit`,`extents`,`flex_bg` always on |
| FAT32 | RW; ESP only; no FAT12/16 |
| OverlayFS | containers |
| 9p / virtiofs | virtiofs preferred; 9p only for QEMU host shares dev-time |

Dropped: ext2/ext3 (use ext4), ISO9660/UDF (no optical), NFSv2/v3 (NFSv4.2 tracked as phase 37), ReiserFS/JFS/HFS+/NTFS/exFAT, autofs (use new mount API). FUSE tracked as phase 37.

### 5.1 `/dev` (devtmpfs, kernel-populated)

| Path | Backing | M:m |
|---|---|---|
| `/dev/null` | char misc | 1:3 |
| `/dev/zero` | " | 1:5 |
| `/dev/full` | " | 1:7 |
| `/dev/random`,`/dev/urandom` | both `getrandom` (no blocking pool) | 1:8,1:9 |
| `/dev/tty` | controlling tty of caller | 5:0 |
| `/dev/console` | early console (UART/fb) | 5:1 |
| `/dev/ptmx` | UNIX98 pty mux | 5:2 |
| `/dev/pts/*` | devpts | — |
| `/dev/kmsg` | klog binary records | 1:11 |
| `/dev/fd` → `/proc/self/fd` | symlink | — |
| `/dev/std{in,out,err}` → `/proc/self/fd/{0,1,2}` | symlink | — |
| `/dev/disk/by-{uuid,label,partuuid,id}/*` | symlinks to `sd?`/`nvme?` | — |
| `/dev/mapper/*` | dm (later phase) | — |
| `/dev/loop-control`,`/dev/loop*` | loop | — |
| `/dev/input/event*` | evdev | — |
| `/dev/fb0` | EFI framebuffer | — |
| `/dev/serial/by-id/*` | symlinks | — |

Denied (`EPERM`): `/dev/mem`,`/dev/kmem`,`/dev/port`. Ever.

Tracked as later phases: `/dev/snd/*`,`/dev/dri/*` (phase 32),`/dev/video*`,`/dev/tpm*`.

### 5.2 `/proc`

Per-pid (`/proc/<pid>/`,`/proc/self`,`/proc/thread-self`): `cmdline`,`comm`,`environ`,`exe`,`cwd`,`root`,`fd/`,`fdinfo/`,`maps`,`smaps`,`mem` (ptrace-gated),`stat`,`status`,`statm`,`mountinfo`,`mounts`,`mountstats`,`cgroup`,`ns/{pid,mnt,net,uts,ipc,user,cgroup,time}`,`oom_score`,`oom_score_adj`,`task/<tid>/...`.

Global: `cpuinfo`,`meminfo`,`stat`,`loadavg`,`uptime`,`version`,`cmdline`,`mounts`,`filesystems`,`partitions`,`devices`,`kallsyms` (kptr_restrict-gated),`modules`,`interrupts`,`softirqs`,`self`,`thread-self`,`sys/` (sparse subset; legacy → `ENOENT`).

Linux fmt compat verified by busybox `ps`,`top`,`free`,`uptime`.

### 5.3 `/sys`

`/sys/devices/`,`/sys/class/{block,net,tty,input,...}`,`/sys/block/<dev>/{size,queue/...,partition*}`,`/sys/fs/cgroup/`,`/sys/firmware/{efi,acpi,devicetree}/`,`/sys/kernel/`,`/sys/module/<n>/{parameters,sections,refcnt}`. Bus subtrees (`/sys/bus/{pci,usb,virtio}/`) populated per-driver.

## 6 Networking

- IPv6 first-class; IPv4 compat.
- TCP: SACK, timestamps, window scaling, ECN, TFO. Cubic default; BBR available. MPTCP later.
- UDP: GSO/GRO d1.
- AF_UNIX: stream+dgram+seqpacket; SCM_RIGHTS+SCM_CREDENTIALS.
- AF_PACKET: SOCK_DGRAM/RAW + PACKET_MMAP.
- AF_NETLINK: ROUTE+GENERIC.
- AF_VSOCK: yes.
- AF_XDP: yes (modern).
- eBPF/XDP: socket filters first, XDP per phase 23.

Dropped AF: IPX, X25, DECnet, APPLETALK, NETROM, BRIDGE, AX25, ROSE, ECONET, RDS, LLC, TIPC, PHONET, IEEE802154, CAIF, ALG (use direct API), NFC, KCM, QIPCRTR, SMC.

Dropped protos: DCCP, SCTP, L2TP, RDS, TIPC.

## 7 Boot / firmware / hardware

- UEFI only. No BIOS/CSM/multiboot1. Limine x86 / EDK2/U-Boot arm.
- No real mode/v8086/A20/segmentation. Long mode at first instr.
- No 32-bit kernel/syscall ABI. 32-bit binary → `ENOEXEC` at loader.
- IRQ ctrl: x2APIC x86 (xAPIC fallback only on pre-Nehalem, effectively unsupported); GICv3+ arm (GICv2 dropped).
- Timers: TSC-deadline + invariant TSC x86 (mandatory; pre-Nehalem unsupported); Generic Timer arm. HPET sanity-check only; no PIT; RTC only for wall-seed at boot.
- PCI: PCIe ECAM. No `0xCF8/CFC`. MSI-X mandatory in shipped drivers; INTx fallback.
- Storage: NVMe + virtio-blk first-class; AHCI supported; IDE/PATA never.
- Net: virtio-net, igc/ice, mlx5; r8169 if contrib. No 10/100Mb-only chips.
- Input: USB HID primary; PS/2 keyboard x86 only (firmware fallback); PS/2 mouse dropped.
- Graphics: serial + EFI framebuffer now; real GPU per phase 32.
- Audio: tracked as later phase.
- Power: ACPI 6.4+ static tables (MADT,FADT,MCFG,SRAT,SLIT,HMAT,PPTT). AML interpreter per phase 35; power currently = halt+reboot via UEFI Runtime Services / platform reset reg.

## 8 Security baseline (mandatory)

- W^X kernel+user. No RWX. JITs use `memfd_create` dual-map.
- KASLR text + direct map.
- SMEP/SMAP (x86), PAN/PXN (arm) always on.
- KPTI on by default both arches.
- Stack canaries `+stack-protector=strong`.
- CET shadow stack / ARM GCS when present.
- IBT/BTI on.
- `init_on_alloc=1`,`init_on_free=1` (debug always; release tunable).
- `/dev/{mem,kmem,port}` denied always.
- `unprivileged_userns_clone=1` default.
- Mandatory seccomp for non-root drops.

Crypto allow:
| Use | Algos |
|---|---|
| AEAD | ChaCha20-Poly1305, AES-256-GCM, AES-256-GCM-SIV |
| Hash | SHA-256/512/3, BLAKE3 |
| MAC | HMAC-SHA-256, KMAC |
| KDF | HKDF-SHA-256, Argon2id |
| Asym | X25519, Ed25519, P-256, Kyber/ML-KEM (PQ hybrid) |
| TLS | 1.3 only |

Crypto deny: MD2/4/5, SHA-1, RIPEMD, RC2/4/5, DES, 3DES, Blowfish, CAST, Skipjack, IDEA. PKCS#1 v1.5 sigs. SSLv3, TLS 1.0/1.1/1.2.

## 9 Containers

- OCI runtime spec target — `runc`/`crun` unmodified.
- Namespaces d1: pid, mount, net, uts, ipc, user, cgroup, time.
- cgroup v2 controllers: cpu, memory, io, pids, cpuset, hugetlb.
- Sandbox primitives: seccomp + Landlock + capabilities.
- SELinux/AppArmor per phase 38 (Landlock covers the sandbox primitive; LSM stacking lands then).

## 10 Observability

- eBPF = introspection mechanism (no kprobes-as-text-files).
- tracefs: tracepoints, function tracer, uprobe/kprobe via BPF.
- `perf_event_open` + hardware PMU.
- No oprofile, kdb, kgdb (QEMU gdb-stub suffices).

## 11 Acceptance binaries (split per `43`)

Now: busybox, bash 5, coreutils 9, redis 7, sqlite 3.45, openssh 9, statically-linked Go≥1.22 + Rust≥1.75 binaries, nginx 1.25 (without io_uring).
Per phase 22+: nginx + io_uring; runc + privileged OCI bundle; bpftrace; perf record/report.
Per phase 29+: systemd≥254 PID1; rootless runc; Wayland GUI app.

Failure to run a listed binary = charter break = bug.

## 12 The single rule

> If Linus deleted it 5y ago, we don't have it.
> If today's binary doesn't use it, we don't have it.
> If keeping it costs a verification harness, doubly don't.

PR review: cite "modernity §12"; author either deletes or names the binary requiring it.

## 13 Changes

Sub-section frozen-unit. Change → revision block (`02§1`). Silent edits = bugs.

## 14 Changelog

(none)

