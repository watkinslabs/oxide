//! Permanent, feature-gated timerfd evidence for compositor timing failures.

fn is_mutter() -> bool {
    // SAFETY: current task remains scheduled while reading its immutable executable path.
    sched::live::current()
        .and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| {
            s.contains("gnome-shell") || s.contains("mutter")
        }) })
        .unwrap_or(false)
}

fn write_i64(value: i64) {
    if value < 0 { klog::write_raw(b"-"); klog::write_dec_u64(value.wrapping_neg() as u64); }
    else { klog::write_dec_u64(value as u64); }
}

fn prefix(op: &'static [u8], id: u32, clockid: u64, flags: u64) -> bool {
    if !is_mutter() { return false; }
    // Clutter's frame clock is a CLOCK_MONOTONIC timerfd.  It is the focused
    // `debug-boot` evidence; GLib also creates many CLOCK_REALTIME timers
    // during desktop startup, whose full ledger stays available under the
    // explicit verbose feature so serial tracing cannot change boot timing.
    #[cfg(not(feature = "debug-mutter-timer-verbose"))]
    if clockid != 1 { return false; }
    klog::write_raw(b"[MUTTIMER "); klog::write_raw(op);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(sched::live::current().map(|c| c.tid as u64).unwrap_or(0));
    klog::write_raw(b" id="); klog::write_dec_u64(id as u64);
    klog::write_raw(b" clk="); klog::write_dec_u64(clockid);
    klog::write_raw(b" fl="); klog::write_hex_u64(flags);
    true
}

/// Emit a named timerfd state transition. # C: O(1)
pub(super) fn event(op: &'static [u8], id: u32, clockid: u64, flags: u64, expiry: u64, now: u64) {
    if !prefix(op, id, clockid, flags) { return; }
    klog::write_raw(b" exp="); klog::write_dec_u64(expiry);
    klog::write_raw(b" now="); klog::write_dec_u64(now); klog::write_raw(b"]\n");
}

/// Emit raw timerfd input before validation or deadline conversion. # C: O(1)
pub(super) fn spec(id: u32, clockid: u64, flags: u64,
    interval_sec: i64, interval_nsec: i64, value_sec: i64, value_nsec: i64)
{
    if !prefix(b"spec", id, clockid, flags) { return; }
    klog::write_raw(b" int_s="); write_i64(interval_sec);
    klog::write_raw(b" int_ns="); write_i64(interval_nsec);
    klog::write_raw(b" val_s="); write_i64(value_sec);
    klog::write_raw(b" val_ns="); write_i64(value_nsec); klog::write_raw(b"]\n");
}

/// Emit an invalid timerfd input rejected with `EINVAL`. # C: O(1)
pub(super) fn bad_value(id: u32, clockid: u64, flags: u64,
    interval_sec: i64, interval_nsec: i64, value_sec: i64, value_nsec: i64)
{
    if !prefix(b"bad-value", id, clockid, flags) { return; }
    klog::write_raw(b" int_s="); write_i64(interval_sec);
    klog::write_raw(b" int_ns="); write_i64(interval_nsec);
    klog::write_raw(b" val_s="); write_i64(value_sec);
    klog::write_raw(b" val_ns="); write_i64(value_nsec); klog::write_raw(b"]\n");
}
