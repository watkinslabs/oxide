//! `__ptrace_may_access`'s dumpability gate (`kernel/ptrace.c`): a target that
//! dropped privileges is non-dumpable, and only `CAP_SYS_PTRACE` may still
//! reach it — even when the credential comparison passes.
//!
//! This is the clause `pidfd_getfd` was missing while it carried its own
//! open-coded copy of the ladder: same real uid, so the cred check passed, and
//! nothing then consulted dumpability — so a process that dropped privileges
//! could still have its fds stolen by the uid that launched it.

use super::common::registry_test_lock;
use crate::ptrace_access::{may_access, Mode, may_access_mode};
use crate::task::{SchedClass, Task, SUID_DUMP_DISABLE, SUID_DUMP_USER};
use core::sync::atomic::Ordering;

/// Two tasks in DIFFERENT thread groups with identical real ids — the cred
/// comparison passes, so dumpability is the only thing left to deny on.
fn peers() -> (Task, Task) {
    let a = Task::new(9101, "attacher", SchedClass::Normal { weight: 1024 });
    let b = Task::new(9102, "target",   SchedClass::Normal { weight: 1024 });
    a.tgid.store(9101, Ordering::Release);
    b.tgid.store(9102, Ordering::Release);
    for t in [&a, &b] {
        for f in [&t.creds.ruid, &t.creds.euid, &t.creds.suid] { f.store(1000, Ordering::Release); }
        for f in [&t.creds.rgid, &t.creds.egid, &t.creds.sgid] { f.store(1000, Ordering::Release); }
        // A fresh Task carries a full capability set. Leaving it would take the
        // CAP_SYS_PTRACE bypass and make every assertion below vacuous — which
        // is exactly what the first run of this test did.
        t.creds.cap_effective.store(0, Ordering::Release);
    }
    (a, b)
}

#[test]
fn matching_creds_alone_do_not_grant_access_to_a_non_dumpable_target() {
    let _g = registry_test_lock();
    let (cur, target) = peers();
    target.dumpable.store(SUID_DUMP_USER, Ordering::Release);
    assert!(may_access(&cur, &target).is_ok(), "same real ids, dumpable: allowed");

    // The target drops privileges — Linux clears dumpable, and the SAME
    // credential match must no longer be enough.
    target.dumpable.store(SUID_DUMP_DISABLE, Ordering::Release);
    assert!(may_access(&cur, &target).is_err(),
        "non-dumpable target must be refused despite matching creds");
}

#[test]
fn cap_sys_ptrace_still_reaches_a_non_dumpable_target() {
    let _g = registry_test_lock();
    let (cur, target) = peers();
    target.dumpable.store(SUID_DUMP_DISABLE, Ordering::Release);
    cur.creds.cap_effective.store(1u64 << crate::cap::SYS_PTRACE, Ordering::Release);
    assert!(may_access(&cur, &target).is_ok(),
        "CAP_SYS_PTRACE bypasses the dumpability gate, as Linux allows");
}

#[test]
fn the_gate_applies_to_fscreds_mode_too() {
    let _g = registry_test_lock();
    let (cur, target) = peers();
    target.dumpable.store(SUID_DUMP_DISABLE, Ordering::Release);
    assert!(may_access_mode(&cur, &target, Mode::FsCreds).is_err(),
        "dumpability is checked on top of EITHER credential path");
}
