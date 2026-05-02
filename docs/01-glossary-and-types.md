# 01 Glossary + Shared Types

FROZEN 2026-05-02. Dep:`02`,`08`,`09`.

Every type referenced by ≥2 subsystems lives here. Single-subsystem types stay in their spec.

Common derives `D` = `Copy,Clone,Eq,PartialEq,Ord,PartialOrd,Hash,Debug` (Hash skipped where Wallclock-like). All newtypes `#[repr(transparent)]` unless noted.

## 1 Address types (frozen)

| Type | Repr | Notes |
|---|---|---|
| `PhysAddr(u64)` | D | high bits zero in v1; sized for 5-level future |
| `VirtAddr(u64)` | D | 48-bit canonical v1 |
| `UserVirtAddr(u64)` | D, priv ctor | `new(u64)→KR<Self>` rejects ≥`USER_VA_END` and non-canonical |

Constants:
```
PAGE_SIZE_BITS=12  PAGE_SIZE=1<<12
HUGE_2M_BITS=21    HUGE_2M=1<<21
HUGE_1G_BITS=30    HUGE_1G=1<<30
USER_VA_END=0x0000_8000_0000_0000   // 47-bit user range
```

Rules: `PhysAddr(0)` valid; absent encoded `Option<PhysAddr>`. No `+usize` op on VA types — only `checked_add(usize)→Option<Self>`. `UserVirtAddr` constructible only via `::new`.

## 2 Pages + order

| Type | Notes |
|---|---|
| `Pfn(u64)` | covers phys `[N<<12, (N+1)<<12)` |
| `Order(u8)` | 0..=`MAX_ORDER`=20 |

## 3 CPU + NUMA

| Type | Notes |
|---|---|
| `CpuId(u16)` | dense 0..NCPU; `MAX_CPUS=256` v1 |
| `NodeId(u8)` | `MAX_NODES=16`; single-node uses `NodeId(0)` |

## 4 Process / thread

| Type | Notes |
|---|---|
| `Pid(u32)` | sparse alloc; never reused while pidfd open. `PID_INIT=1`,`PID_INVALID=0` |
| `Tid(u32)` | leader's `Tid==Pid` |
| `Uid(u32)`,`Gid(u32)` | 32-bit; no 16-bit legacy. `UID_ROOT=Gid_ROOT=0` |
| `RawFd = i32` | `RAW_FD_INVALID=-1` at boundary; internal uses `KR<RawFd>` |

## 5 Time (frozen)

```rust
#[repr(transparent)] pub struct Nanos(pub u64);   // mono since boot, non-decreasing
#[repr(transparent)] pub struct Duration(pub u64); // ns; positive only
pub struct Wallclock { pub secs:i64, pub nanos:u32 }  // unix epoch; non-monotonic
```

`Nanos` impl: `ZERO`, `checked_add(Duration)→Option<Self>`, `checked_sub(Self)→Option<Duration>`.
`Duration` ctors: `from_{secs,millis,micros,nanos}`; getters mirror.

Rules: never 32-bit time at any internal boundary (Linux ABI 32-bit `time_t` syscalls → `ENOSYS`, `15`). `Nanos` arithmetic never wraps. `clock_gettime(MONOTONIC)` source = `Nanos::now()`.

## 6 Errno (frozen, ABI numbers = Linux x86_64)

```rust
#[repr(u16)] pub enum Errno {
  EPERM=1, ENOENT=2, ESRCH=3, EINTR=4, EIO=5, ENXIO=6, E2BIG=7, ENOEXEC=8,
  EBADF=9, ECHILD=10, EAGAIN=11, ENOMEM=12, EACCES=13, EFAULT=14, ENOTBLK=15,
  EBUSY=16, EEXIST=17, EXDEV=18, ENODEV=19, ENOTDIR=20, EISDIR=21, EINVAL=22,
  ENFILE=23, EMFILE=24, ENOTTY=25, ETXTBSY=26, EFBIG=27, ENOSPC=28, ESPIPE=29,
  EROFS=30, EMLINK=31, EPIPE=32, EDOM=33, ERANGE=34, EDEADLK=35, ENAMETOOLONG=36,
  ENOLCK=37, ENOSYS=38, ENOTEMPTY=39, ELOOP=40,
  // 41 alias EWOULDBLOCK=EAGAIN
  ENOMSG=42, EIDRM=43, ECHRNG=44, EL2NSYNC=45, EL3HLT=46, EL3RST=47, ELNRNG=48,
  EUNATCH=49, ENOCSI=50, EL2HLT=51, EBADE=52, EBADR=53, EXFULL=54, ENOANO=55,
  EBADRQC=56, EBADSLT=57, /*58 unused*/ EBFONT=59,
  ENOSTR=60, ENODATA=61, ETIME=62, ENOSR=63, ENONET=64, ENOPKG=65, EREMOTE=66,
  ENOLINK=67, EADV=68, ESRMNT=69, ECOMM=70, EPROTO=71, EMULTIHOP=72, EDOTDOT=73,
  EBADMSG=74, EOVERFLOW=75, ENOTUNIQ=76, EBADFD=77, EREMCHG=78,
  ELIBACC=79, ELIBBAD=80, ELIBSCN=81, ELIBMAX=82, ELIBEXEC=83, EILSEQ=84,
  ERESTART=85, ESTRPIPE=86, EUSERS=87,
  ENOTSOCK=88, EDESTADDRREQ=89, EMSGSIZE=90, EPROTOTYPE=91, ENOPROTOOPT=92,
  EPROTONOSUPPORT=93, ESOCKTNOSUPPORT=94, EOPNOTSUPP=95, EPFNOSUPPORT=96,
  EAFNOSUPPORT=97, EADDRINUSE=98, EADDRNOTAVAIL=99,
  ENETDOWN=100, ENETUNREACH=101, ENETRESET=102, ECONNABORTED=103, ECONNRESET=104,
  ENOBUFS=105, EISCONN=106, ENOTCONN=107, ESHUTDOWN=108, ETOOMANYREFS=109,
  ETIMEDOUT=110, ECONNREFUSED=111, EHOSTDOWN=112, EHOSTUNREACH=113, EALREADY=114,
  EINPROGRESS=115, ESTALE=116, EUCLEAN=117, ENOTNAM=118, ENAVAIL=119, EISNAM=120,
  EREMOTEIO=121, EDQUOT=122, ENOMEDIUM=123, EMEDIUMTYPE=124, ECANCELED=125,
  ENOKEY=126, EKEYEXPIRED=127, EKEYREVOKED=128, EKEYREJECTED=129,
  EOWNERDEAD=130, ENOTRECOVERABLE=131, ERFKILL=132, EHWPOISON=133,
}
```

Aliases as `pub const Errno`: `EWOULDBLOCK=EAGAIN(11)`, `ENOTSUP=EOPNOTSUPP(95)`, `EDEADLOCK=EDEADLK(35)`.

`pub type KResult<T> = Result<T, Errno>;` — every fallible kernel fn returns `KR<T>`. Never raw `i32`/`Option<T>`-as-failure.

## 7 Signals (frozen, Linux numbering)

```
1 HUP, 2 INT, 3 QUIT, 4 ILL, 5 TRAP, 6 ABRT(=IOT), 7 BUS, 8 FPE,
9 KILL¬, 10 USR1, 11 SEGV, 12 USR2, 13 PIPE, 14 ALRM, 15 TERM, 16 STKFLT,
17 CHLD, 18 CONT, 19 STOP¬, 20 TSTP, 21 TTIN, 22 TTOU, 23 URG, 24 XCPU,
25 XFSZ, 26 VTALRM, 27 PROF, 28 WINCH, 29 IO(=POLL), 30 PWR, 31 SYS
// 32,33 reserved (NPTL)
// 34..=64 RT signals (queue with siginfo_t payload)
SIGRT_MIN=34  SIGRT_MAX=64
```

¬ = uncatchable/unblockable/unignorable; enforced at `rt_sigaction`. Standard signals collapse to pending-bit-set; RT signals queue.

## 8 File / FD (kernel-internal)

| Type | Notes |
|---|---|
| `Ino(u64)` | filesystem-local, not unique cross-FS |
| `DevId{major:u32,minor:u32}` | unpacked; ABI `dev_t` packing in `15` |

`FileMode`/`O_*`/`MAP_*`/`PROT_*`/`mode` bits = ABI surface, in `15§6`. Not here.

## 9 Capabilities (Linux v3, 64-bit)

`#[repr(transparent)] pub struct Caps(pub u64)`. Methods `has(u8)`,`raise(u8)`,`drop(u8)`.

| # | Name | # | Name |
|---|---|---|---|
| 0 | CHOWN | 21 | SYS_ADMIN |
| 1 | DAC_OVERRIDE | 22 | SYS_BOOT |
| 2 | DAC_READ_SEARCH | 23 | SYS_NICE |
| 3 | FOWNER | 24 | SYS_RESOURCE |
| 4 | FSETID | 25 | SYS_TIME |
| 5 | KILL | 26 | SYS_TTY_CONFIG |
| 6 | SETGID | 27 | MKNOD |
| 7 | SETUID | 28 | LEASE |
| 8 | SETPCAP | 29 | AUDIT_WRITE |
| 9 | LINUX_IMMUTABLE | 30 | AUDIT_CONTROL |
| 10 | NET_BIND_SERVICE | 31 | SETFCAP |
| 11 | NET_BROADCAST | 32 | MAC_OVERRIDE |
| 12 | NET_ADMIN | 33 | MAC_ADMIN |
| 13 | NET_RAW | 34 | SYSLOG |
| 14 | IPC_LOCK | 35 | WAKE_ALARM |
| 15 | IPC_OWNER | 36 | BLOCK_SUSPEND |
| 16 | SYS_MODULE | 37 | AUDIT_READ |
| 17 | SYS_RAWIO | 38 | PERFMON |
| 18 | SYS_CHROOT | 39 | BPF |
| 19 | SYS_PTRACE | 40 | CHECKPOINT_RESTORE |
| 20 | SYS_PACCT | — | LAST_CAP=40 |

Const names: `Caps::CAP_<NAME>`.

## 10 Glossary

| Term | Def |
|---|---|
| Hot path | >100/s on representative load OR per-pkt/syscall/ctxsw; has cycle budget |
| Cold path | else; allowed alloc/log/coarse locks |
| Slow path | correct-not-fast fallback inside hot fn (e.g., per-CPU miss → global) |
| Critical section | between lock acq/rel; IRQ-disable counts |
| IRQ ctx | on IRQ stack, entered via vector, not yet returned (≠ "IRQs disabled") |
| Process ctx | task stack + AS; the normal context |
| Soft IRQ ctx | bottom-half deferred; IRQs on, can't block |
| Preempt-disabled | per-CPU `preempt_count>0`; sched won't switch |
| IRQs-disabled | arch IRQ-mask set on this CPU |
| Sleeping | calls fn that may yield; forbidden in atomic ctx |
| Atomic ctx | union {IRQ, softIRQ, preempt-off, IRQ-off}; sleeping forbidden |
| Oracle | reference impl, deliberately stupid, in `tools/oracle-*/`, used in differential tests |
| Soak | hours-long randomized stress, measured in CPU-hours |
| Property test | proptest-driven, checks invariant under random ops |
| Loom test | exhaustive interleaving exploration, depth-bounded |
| Hosted test | `cargo test` on dev host (not kernel target) |
| In-kernel test | runs inside booted kernel; result via serial |
| FROZEN | spec marked `Status: FROZEN <date>`; revision blocks required (`02`) |
| Charter | non-subsystem spec (`00`–`09`) constraining everything below |
| HAL | trait set in `crates/hal/`, impls per arch |
| vDSO | RX ELF blob mapped in every user AS; `clock_gettime`,`getcpu` fast paths |
| W^X | no page simultaneously W and X |
| KPTI | kernel/user split PT roots; entry/exit swaps CR3/TTBR; mitigates Meltdown |
| PCID/ASID | TLB tagging x86/arm; multiple AS coexist in TLB |
| NMI ctx | non-maskable; reentrancy-safe; logging via NMI ringlet only |

## 11 Naming (frozen)

Types `UpperCamel`. Constants `SCREAMING_SNAKE`. Fns `lower_snake`. Crates `lower_snake`. Traits noun or `-Ops`. Doc-comment markers per `09§6` (`# C:` `# Lk:` `# Ctx:` `# Sleeps:` `# SAFETY:` `# Pre:` `# Post:` `# Lin:`); CI-enforced on every `pub fn`.

## 12 Not here

If a type isn't here it's: (a) single-subsystem (lives in that spec), (b) ABI struct (`15`), (c) HW-specific (`20`/`21`). Add here only when ≥2 subsystems reference.

## 13 Changelog

(none)

