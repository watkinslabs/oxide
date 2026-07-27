// Per-task rlimit clamping + validity per POSIX setrlimit(2). Pure
// logic; the kernel-side syscall glue calls into this module to
// enforce the rules.

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

/// Linux's init-task rlimit defaults (kernel/include/asm-generic/
/// resource.h `INIT_RLIMITS`). Inherited by every task at creation
/// (and by fork per POSIX). Only the rusable ones diverge from
/// RLIM_INFINITY; the rest stay unlimited so they don't bite.
///
/// RLIMIT_STACK = (8 MiB, RLIM_INFINITY) — Linux's _STK_LIM. Used
/// by execve to compute mmap_base = stack_top - rlim_stack - GAP
/// and by try_grow_stack as the upper bound on auto-extension.
pub const DEFAULT_RLIMITS: [(u64, u64); rlim::COUNT] = {
    let mut a = [(INFINITY, INFINITY); rlim::COUNT];
    a[rlim::STACK] = (8 * 1024 * 1024, INFINITY);
    a[rlim::NOFILE] = (1024, 4096);  // Linux _RLIM_NOFILE / NR_OPEN_DEFAULT
    a[rlim::CORE]   = (0, INFINITY);  // disabled by default
    a
};

/// Validate a setrlimit(2) request against the current `(old_cur, old_max)`.
/// Returns the new `(cur, max)` or `Err(())` if the request would
/// raise the hard limit (privileged-only, v1 always-root semantics
/// allow it; the validation is structural — `cur <= max`).
///
/// Linux setrlimit rules (paraphrased):
///   - new_cur must be <= new_max (else EINVAL).
///   - new_max <= old_max for unprivileged callers (we treat all v1
///     tasks as root, so always allow raising — caller bypasses if
///     needed).
/// # C: O(1)
pub fn validate_setrlimit(old: (u64, u64), new: (u64, u64)) -> Result<(u64, u64), ()> {
    let (new_cur, new_max) = new;
    if new_cur > new_max { return Err(()); }
    let _ = old;
    Ok((new_cur, new_max))
}

/// Clamp a "set this resource limit" request: caller passes a raw
/// `(cur, max)` from userspace; this enforces `cur <= max`. Returns
/// the validated tuple or `None` if invalid.
/// # C: O(1)
pub fn clamp_pair(cur: u64, max: u64) -> Option<(u64, u64)> {
    if cur > max { None } else { Some((cur, max)) }
}

/// `MIN_NICE` / `MAX_NICE` (Linux `include/linux/sched/prio.h`).
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

/// Linux `nice_to_rlimit` (`include/linux/sched/prio.h`): convert a nice value
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
