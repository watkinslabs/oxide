// Per-task rlimit clamping + validity per POSIX setrlimit(2). Pure
// logic; the kernel-side syscall glue calls into this module to
// enforce the rules.
//
// Child modules own one ENFORCEMENT contract each — the decision the limit
// actually makes, kept ungated so it is hosted-testable, with the live-state
// glue in the subsystem that owns the state:
//   `vm`      — RLIMIT_AS admission + the RLIMIT_STACK growth bound.
//   `cputime` — RLIMIT_CPU / RLIMIT_RTTIME SIGXCPU-then-SIGKILL ladder.
//   `dump`    — RLIMIT_CORE dump-size truncation.
//   `pending` — RLIMIT_SIGPENDING per-user queued-record admission.

pub mod cputime;
pub mod dump;
pub mod pending;
pub mod vm;

/// Linux RLIMIT_* indices.
pub mod rlim {
    pub const CPU:        usize = 0;
    pub const FSIZE:      usize = 1;
    pub const DATA:       usize = 2;
    pub const STACK:      usize = 3;
    pub const CORE:       usize = 4;
    pub const RSS:        usize = 5;
    pub const NPROC:      usize = 6;
    pub const NOFILE:     usize = 7;
    pub const MEMLOCK:    usize = 8;
    pub const AS:         usize = 9;
    pub const LOCKS:      usize = 10;
    pub const SIGPENDING: usize = 11;
    pub const MSGQUEUE:   usize = 12;
    pub const NICE:       usize = 13;
    pub const RTPRIO:     usize = 14;
    pub const RTTIME:     usize = 15;
    pub const COUNT:      usize = 16;
}

/// `RLIM_INFINITY` per POSIX — the "no limit" sentinel.
pub const INFINITY: u64 = u64::MAX;

/// Linux's init-task rlimit table (`INIT_RLIMITS`) AFTER `fork_init`'s two
/// overwrites, which is the state every task actually inherits. Fork copies it
/// per POSIX. Anything not listed here is `RLIM_INFINITY` in both columns.
///
/// RLIMIT_STACK = (8 MiB, RLIM_INFINITY) — Linux's _STK_LIM. Used
/// by execve to compute mmap_base = stack_top - rlim_stack - GAP
/// and by try_grow_stack as the upper bound on auto-extension.
///
/// The four DEFAULT-ZERO entries are the load-bearing ones and were all
/// `RLIM_INFINITY` here until F777. `RLIMIT_NICE` and `RLIMIT_RTPRIO` are
/// `{0, 0}` upstream: with them unlimited, the `setpriority(2)` and
/// `sched_setscheduler(2)` ladders — which are written correctly and consult
/// exactly these two slots — could never refuse anything, so any unprivileged
/// process could take nice -20 or SCHED_FIFO priority 99 without `CAP_SYS_NICE`.
pub const DEFAULT_RLIMITS: [(u64, u64); rlim::COUNT] = {
    let mut a = [(INFINITY, INFINITY); rlim::COUNT];
    a[rlim::STACK] = (8 * 1024 * 1024, INFINITY);
    a[rlim::NOFILE] = (1024, 4096);  // Linux INR_OPEN_CUR / INR_OPEN_MAX
    a[rlim::CORE]   = (0, INFINITY);  // disabled by default
    a[rlim::MEMLOCK] = (MLOCK_LIMIT, MLOCK_LIMIT);
    a[rlim::MSGQUEUE] = (MQ_BYTES_MAX, MQ_BYTES_MAX);
    a[rlim::NPROC] = (DEFAULT_NPROC, DEFAULT_NPROC);
    a[rlim::SIGPENDING] = (DEFAULT_SIGPENDING, DEFAULT_SIGPENDING);
    a[rlim::NICE] = (0, 0);
    a[rlim::RTPRIO] = (0, 0);
    a
};

/// Linux `max_threads` — `kernel.threads-max`, the value `procfs`'s sysctl leaf
/// renders. Owned here because `fork_init` derives an rlimit default from it and
/// a second copy could disagree with what the sysctl reports.
pub const THREADS_MAX: u64 = 32768;

/// `INIT_RLIMITS` leaves `RLIMIT_NPROC` and `RLIMIT_SIGPENDING` at `{0, 0}` and
/// `fork_init` immediately overwrites BOTH with `max_threads / 2`, so the zeros
/// in the table are never observable. Leaving either at `RLIM_INFINITY` instead
/// would make its admission gate unreachable — an unbounded real-time signal
/// queue and an unbounded task count are both memory-exhaustion paths any
/// unprivileged process can drive.
pub const DEFAULT_SIGPENDING: u64 = THREADS_MAX / 2;

/// `fork_init`'s `RLIMIT_NPROC` default, the same `max_threads / 2`.
pub const DEFAULT_NPROC: u64 = THREADS_MAX / 2;

/// Linux `MQ_BYTES_MAX` — the `RLIMIT_MSGQUEUE` default for both columns, and
/// the ceiling the POSIX message-queue admission gate charges against.
pub const MQ_BYTES_MAX: u64 = 819_200;

/// Linux `MLOCK_LIMIT`, the RLIMIT_MEMLOCK
/// default for both the soft and hard limit. Leaving MEMLOCK unlimited would
/// make the whole mlock(2)/mlock2(2)/mlockall(2) admission ladder unreachable —
/// EPERM and ENOMEM would never fire — and would let any unprivileged process
/// pin arbitrary memory. CAP_IPC_LOCK still bypasses it, so a privileged init
/// is unaffected.
pub const MLOCK_LIMIT: u64 = 8 * 1024 * 1024;

/// Why `do_prlimit` rejected a `setrlimit(2)` / `prlimit64(2)` request.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PrlimitError {
    /// Bad resource index, or `rlim_cur > rlim_max`.
    Einval,
    /// `RLIMIT_NOFILE` above `fs.nr_open`, or a hard-limit raise without
    /// `CAP_SYS_RESOURCE`.
    Eperm,
}

/// The half of Linux `do_prlimit` that inspects only the INCOMING pair, run
/// before the rlimit table is even read:
///
/// ```text
/// if (new_rlim->rlim_cur > new_rlim->rlim_max)          return -EINVAL;
/// if (resource == RLIMIT_NOFILE && new_rlim->rlim_max > sysctl_nr_open)
///                                                       return -EPERM;
/// ```
///
/// `nr_open` is the live `fs.nr_open` (`vfs::fdtable::nr_open`); it is a
/// parameter so the ladder stays pure and hosted-testable.
/// # C: O(1)
pub fn check_new_rlimit(resource: usize, new: (u64, u64), nr_open: u64)
    -> Result<(), PrlimitError>
{
    if new.0 > new.1 { return Err(PrlimitError::Einval); }
    if resource == rlim::NOFILE && new.1 > nr_open { return Err(PrlimitError::Eperm); }
    Ok(())
}

/// `MIN_NICE` / `MAX_NICE`.
pub const MIN_NICE: i32 = -20;
pub const MAX_NICE: i32 = 19;

/// `which` selector shared by getpriority(2)/setpriority(2).
pub mod prio_which {
    pub const PROCESS: u64 = 0;
    pub const PGRP:    u64 = 1;
    pub const USER:    u64 = 2;
}

/// Clamp a setpriority(2) `nice` argument to `[MIN_NICE, MAX_NICE]`. Linux
/// SATURATES rather than rejecting: `SYSCALL_DEFINE3(setpriority)` does
/// `if (niceval < MIN_NICE) niceval = MIN_NICE; if (niceval > MAX_NICE)
/// niceval = MAX_NICE;` before touching any target.
/// # C: O(1)
pub fn clamp_nice(nice: i32) -> i8 {
    if nice < MIN_NICE { MIN_NICE as i8 }
    else if nice > MAX_NICE { MAX_NICE as i8 }
    else { nice as i8 }
}

/// Linux `nice_to_rlimit`: convert a nice value
/// in `[19, -20]` to the rlimit-style value in `[1, 40]`, `MAX_NICE - nice + 1`.
///
/// This is BOTH the `getpriority(2)` return bias and the units `RLIMIT_NICE`
/// is expressed in. The bias exists so the syscall never returns a small
/// negative that the libc wrapper would read as `-errno`: the lowest possible
/// result is 1 (nice 19), never 0 or below.
/// # C: O(1)
pub const fn nice_to_rlimit(nice: i32) -> i32 { MAX_NICE - nice + 1 }

/// Linux `rlimit_to_nice` — the inverse of [`nice_to_rlimit`]. # C: O(1)
pub const fn rlimit_to_nice(prio: i32) -> i32 { MAX_NICE - prio + 1 }

/// Render an rlimit `cur` field as either a decimal number or
/// `"unlimited"` for the /proc/<pid>/limits text. Returns the byte
/// count written into `buf` or `None` if the buffer is too small.
/// # C: O(log10(v))
pub fn format_rlim(buf: &mut [u8], v: u64) -> Option<usize> {
    if v == INFINITY {
        let s = b"unlimited";
        if buf.len() < s.len() { return None; }
        buf[..s.len()].copy_from_slice(s);
        return Some(s.len());
    }
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    let mut x = v;
    if x == 0 { tmp[0] = b'0'; n = 1; }
    else { while x > 0 { tmp[n] = b'0' + (x % 10) as u8; x /= 10; n += 1; } }
    if buf.len() < n { return None; }
    for i in 0..n { buf[i] = tmp[n - 1 - i]; }
    Some(n)
}
