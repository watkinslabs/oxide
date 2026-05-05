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

/// Clamp a setpriority(2) `nice` argument to the POSIX `[-20, 19]`
/// range. Out-of-range values silently saturate (Linux returns
/// EINVAL on out-of-range; v1 saturates for shell-friendliness).
/// # C: O(1)
pub fn clamp_nice(nice: i32) -> i8 {
    if nice < -20 { -20 }
    else if nice > 19 { 19 }
    else { nice as i8 }
}

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
