// [TCPRX] delivery-side trace for the SA_RESTART TCP-recv re-entry hunt.
// Answers ONE question a boot cannot otherwise answer: when the peer's bytes
// land, had the receiver actually published itself on `entry.rx_waiters`?
// Feature-gated — a default build compiles the empty arm and emits nothing.

/// Report one TCP delivery's receive-buffer growth and the parked-receiver
/// count observed immediately before the wake. # C: O(1)
#[cfg(feature = "debug-tcprx")]
pub(crate) fn deliver(local_port: u16, pre_len: usize, post_len: usize, waiters: bool) {
    klog::write_raw(b"[TCPRX deliver lport=");
    klog::write_dec_u64(local_port as u64);
    klog::write_raw(b" pre=");
    klog::write_dec_u64(pre_len as u64);
    klog::write_raw(b" post=");
    klog::write_dec_u64(post_len as u64);
    klog::write_raw(if waiters { b" waiters=1]\n" } else { b" waiters=0]\n" });
}

/// # C: O(1)
#[cfg(not(feature = "debug-tcprx"))]
pub(crate) fn deliver(_local_port: u16, _pre_len: usize, _post_len: usize, _waiters: bool) {}
