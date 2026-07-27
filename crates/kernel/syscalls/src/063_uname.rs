// `sys_uname` — ABI shim only. Field values and the personality-driven
// overrides live in `uname_release`; the names come from the caller's UTS
// namespace.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use alloc::format;

use crate::uname_release::{build_utsname, UTS_NONE, UTSNAME_TOTAL_LEN};

/// Resolve hostname through the calling task's exact UTS owner.
/// # C: O(log N)
pub fn uts_hostname_for_current() -> alloc::vec::Vec<u8> {
    sched::live::current()
        .and_then(|task| task.namespace_owner(namespace_identity::NamespaceKind::Uts))
        .and_then(|owner| crate::hostname::host_for(&owner).ok())
        .unwrap_or_default()
}

/// Resolve the calling task's NIS/YP domainname per UTS namespace
/// membership; a UTS namespace isolates both names.
/// # C: O(log N)
pub fn uts_domainname_for_current() -> alloc::vec::Vec<u8> {
    sched::live::current()
        .and_then(|task| task.namespace_owner(namespace_identity::NamespaceKind::Uts))
        .and_then(|owner| crate::hostname::dom_for(&owner).ok())
        .unwrap_or_default()
}

/// `sys_uname(buf)` — slot 63 (Linux `newuname`). Copies the caller's UTS
/// namespace `struct new_utsname` (6 × 65 B: sysname, nodename, release,
/// version, machine, domainname), then applies the two personality overrides
/// Linux applies after the copy: `UNAME26` rewrites `release` to the 2.6 series
/// and `PER_LINUX32` reports the compat `machine`.
/// # C: O(1)
pub fn kernel_uname(args: &SyscallArgs) -> i64 {
    use core::sync::atomic::Ordering;
    use syscall::errno::Errno;
    let tp = args.a0;
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(tp, UTSNAME_TOTAL_LEN as u64, 1) {
        return rv;
    }
    let cur = match sched::live::current() {
        Some(cur) => cur, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let owner = match cur.namespace_owner(namespace_identity::NamespaceKind::Uts) {
        Some(owner) => owner, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let host = match crate::hostname::host_for(&owner) {
        Ok(host) => host, Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    let dom = match crate::hostname::dom_for(&owner) {
        Ok(dom) => dom, Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    // Both names are reported verbatim: the `(none)` default Linux carries in
    // `init_uts_ns` lives in the storage seed, so a caller that sets an EMPTY
    // name reads an empty name back. The fallback here covers only a task with
    // no UTS state at all.
    let host: &[u8] = if host.is_empty() { UTS_NONE } else { &host };
    let dom:  &[u8] = &dom;
    let version = format!("#1 SMP PREEMPT oxide v0.1.0 nr_cpus={}", cpu::smp::online_count());
    let img = build_utsname(host, dom, version.as_bytes(), cur.personality.load(Ordering::Acquire));
    // SAFETY: `tp` names one validated writable `struct new_utsname`; the image
    // is exactly UTSNAME_TOTAL_LEN bytes and byte writes need no alignment.
    unsafe {
        for (i, byte) in img.iter().enumerate() {
            core::ptr::write_unaligned((tp + i as u64) as *mut u8, *byte);
        }
    }
    0
}
