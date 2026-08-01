// x86_64: `CR4.TSD`. Set = `rdtsc`/`rdtscp` at CPL>0 raise `#GP(0)`.

/// # SAFETY: privileged CR4 write, legal at CPL=0; CR4 is per-CPU so this CPU
/// is its sole writer, and callers run preempt-off.
/// # C: O(1)
pub unsafe fn set_trapped(on: bool) {
    // SAFETY: forwards this fn's own contract — privileged per-CPU CR4 RMW, preempt-off caller, no other CR4 bit touched.
    unsafe { hal_x86_64::set_tsd(on) }
}
