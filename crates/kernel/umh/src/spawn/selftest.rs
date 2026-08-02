// Boot self-test for the kernel -> userspace exec path (`debug-umh`).
//
// The decision logic is covered hosted, but "does a helper process actually
// reach user mode and run" can only be answered on a booted system. This runs
// on the helper thread, driving the same exec and wait the queue drives — it
// cannot go through the submission entry point, which would park waiting on the
// very thread running the test.

#![cfg(feature = "debug-umh")]

use crate::env;
use crate::gate;
use crate::info::SubprocessInfo;
use crate::uapi::{UMH_WAIT_EXEC, UMH_WAIT_PROC};

/// Program every root has, used to prove a helper reaches user mode and exits.
const PRESENT: &[u8] = b"/usr/bin/true";
/// Program no root has, used to prove a missing helper reports its real error.
///
/// It must be a path nothing can ever install. This was `/sbin/request-key`
/// until the images grew keyutils, at which point both `absent-*` cases
/// silently started reporting success — a self-test that passes by testing
/// nothing.
const ABSENT: &[u8] = b"/nonexistent/oxide-umh-absent";
/// A directory, used to prove the executability gate runs.
const NOT_A_PROGRAM: &[u8] = b"/usr/bin";

/// Iterations to wait for the gate, one millisecond apart.
const GATE_WAIT_MS: u32 = 20_000;

/// Run the self-test once the gate has opened. # C: O(helpers)
pub fn run() {
    // The gate opens just before the first user process starts; wait for it
    // rather than reporting a refusal the boot order guarantees.
    for _ in 0..GATE_WAIT_MS {
        if !gate::usermodehelper_disabled() { break; }
        super::queue::yield_one_ms();
    }
    if gate::usermodehelper_disabled() { report(b"gate", -(syscall::errno::Errno::Ebusy.as_i32())); return; }
    report(b"absent-wait-exec", probe(ABSENT, UMH_WAIT_EXEC));
    report(b"notaprog-wait-exec", probe(NOT_A_PROGRAM, UMH_WAIT_EXEC));
    report(b"present-wait-exec", probe(PRESENT, UMH_WAIT_EXEC));
    report(b"present-wait-proc", probe(PRESENT, UMH_WAIT_PROC));
    report(b"absent-wait-proc", probe(ABSENT, UMH_WAIT_PROC));
}

fn probe(path: &[u8], wait: i32) -> i32 {
    let mut info = SubprocessInfo::new(Some(path), &[path], &env::UPCALL_ENV, None, None, 0);
    info.wait = wait;
    if let Some(vpid) = super::queue::run_inline(&mut info) { let _ = super::reap::wait_for(vpid); }
    info.retval
}

fn report(what: &'static [u8], rc: i32) {
    klog::write_raw(b"[UMH] ");
    klog::write_raw(what);
    klog::write_raw(b" rc=");
    if rc < 0 {
        klog::write_raw(b"-");
        klog::write_dec_u64((-(rc as i64)) as u64);
    } else {
        klog::write_dec_u64(rc as u64);
    }
    klog::write_raw(b"\n");
}
