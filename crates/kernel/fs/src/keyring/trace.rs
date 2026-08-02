// `debug-keyring` trace of the construction chain.
//
// The upcall's outcome is deliberately opaque to userspace: whatever goes wrong
// between "the helper was started" and "the key was answered" reaches the
// requester as one ENOKEY, because that is what a negated key reports. That is
// correct behaviour and useless for diagnosis — a helper that could not be
// exec'd, one that ran and never answered, and one whose `KEYCTL_INSTANTIATE`
// was refused are indistinguishable from the requester's side, and the helper's
// own stderr goes nowhere.
//
// So the kernel says which of them happened, on the one channel that survives:
// the log. Off by default; `debug-keyring` turns it on.

/// One traced step: a label, the key or token it concerns, and the result.
/// # C: O(1)
#[cfg(feature = "debug-keyring")]
pub fn step(what: &'static [u8], tid: u32, id: i32, rc: i64) {
    klog::write_raw(b"[KEYRING] ");
    klog::write_raw(what);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" id=");
    signed(id as i64);
    klog::write_raw(b" rc=");
    signed(rc);
    klog::write_raw(b"\n");
}

/// Compiled away when the trace is off. # C: O(1)
#[cfg(not(feature = "debug-keyring"))]
pub fn step(_what: &'static [u8], _tid: u32, _id: i32, _rc: i64) {}

#[cfg(feature = "debug-keyring")]
fn signed(v: i64) {
    if v < 0 { klog::write_raw(b"-"); klog::write_dec_u64(v.unsigned_abs()); }
    else { klog::write_dec_u64(v as u64); }
}
