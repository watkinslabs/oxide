// `sys_uname` — ABI shim only. Field values and the personality-driven
// overrides live in `uname_release`; the names come from the caller's UTS
// namespace.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use alloc::format;

use crate::uname_release::{build_utsname, UTSNAME_TOTAL_LEN};

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
    // Both names are reported VERBATIM. Linux `newuname` copies
    // `utsname()->nodename` straight out; the `(none)` default lives in
    // `init_uts_ns`'s seed (here: `Hostname::none_seed`), not in this reader.
    // Substituting `(none)` for an empty nodename made `sethostname("", 0)`
    // unobservable through `uname(2)` while `/proc/sys/kernel/hostname`
    // reported the empty string — two answers for one piece of state.
    let host: &[u8] = &host;
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
