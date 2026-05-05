// Clock conversion helpers per `28§4` / `clock_gettime(2)`.
// Pure; hosted-tested. Kernel-side `syscall_glue_time` calls these.

/// Compute the wall-clock offset to store given a target time
/// `target_ns` (UNIX-epoch ns) and the current monotonic clock
/// `mono_ns`. Result satisfies `mono + offset == target` (wrapping).
/// settimeofday / clock_settime CLOCK_REALTIME use this so future
/// CLOCK_REALTIME reads return the caller-configured wall-clock.
/// # C: O(1)
pub fn settimeofday_offset(mono_ns: u64, target_ns: u64) -> u64 {
    target_ns.wrapping_sub(mono_ns)
}

/// Apply a stored offset to monotonic_ns. Inverse of
/// `settimeofday_offset` — `apply(mono, offset)` returns the
/// CLOCK_REALTIME value when mono is the live monotonic count.
/// # C: O(1)
pub fn apply_offset(mono_ns: u64, offset: u64) -> u64 {
    mono_ns.wrapping_add(offset)
}

/// Linux `CLK_TCK` is fixed at 100 Hz on glibc x86_64 / aarch64.
/// /proc/<pid>/stat utime/stime + sys_times return ticks at this
/// rate. Convert ns → ticks.
/// # C: O(1)
pub fn ns_to_clk_tck(ns: u64) -> u64 { ns / 10_000_000 }

/// Split a wall-clock ns count into `(sec, nsec)` per timespec.
/// # C: O(1)
pub fn ns_to_timespec(ns: u64) -> (u64, u64) {
    (ns / 1_000_000_000, ns % 1_000_000_000)
}

/// Split into `(sec, usec)` per timeval.
/// # C: O(1)
pub fn ns_to_timeval(ns: u64) -> (u64, u64) {
    let (s, n) = ns_to_timespec(ns);
    (s, n / 1000)
}
