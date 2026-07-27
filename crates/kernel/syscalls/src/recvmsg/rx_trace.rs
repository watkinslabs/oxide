// [TCPRX] shim-side receive-loop trace for the SA_RESTART TCP-recv re-entry
// hunt. The loop is kernel-gated, so no hosted test can observe whether a
// restarted `recvfrom` re-enters, parks, and is woken; these five events
// separate the three candidate failures in ONE boot:
//
//   `enter` once only              -> the restart never re-entered the syscall
//   `enter` x2 + `prepark`, no `postpark`, and a `[TCPRX deliver ... waiters=1]`
//                                  -> the wake was published but did not rouse
//   `enter` x2 + `prepark`/`postpark` loop with no `deliver`
//                                  -> the peer's bytes never reached this entry
//   `enter` many                   -> the tail is restarting in a loop
//
// Feature-gated — a default build compiles the empty arm and emits nothing.

/// Emit one receive-loop checkpoint tagged with the running tid. # C: O(1)
#[cfg(feature = "debug-tcprx")]
pub(crate) fn event(what: &'static [u8]) {
    klog::write_raw(b"[TCPRX ");
    klog::write_raw(what);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(sched::live::current().map(|task| task.tid).unwrap_or(0) as u64);
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(feature = "debug-tcprx"))]
pub(crate) fn event(_what: &'static [u8]) {}
