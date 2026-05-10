// `sys_uname` real impl + UTS namespace-aware hostname resolution.
// Split out of syscall_glue.rs to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

const UTSNAME_FIELD_LEN: usize = 65;
const UTSNAME_TOTAL_LEN: usize = UTSNAME_FIELD_LEN * 6;

#[cfg(target_arch = "x86_64")]
const UNAME_MACHINE: &[u8] = b"x86_64";
#[cfg(target_arch = "aarch64")]
const UNAME_MACHINE: &[u8] = b"aarch64";

/// Write a utsname field at offset `off`: `src` then NUL pad to 65 B.
unsafe fn write_utsname_field(tp: u64, off: usize, src: &[u8]) {
    let n = src.len().min(UTSNAME_FIELD_LEN - 1);
    // SAFETY: caller validated [tp, tp+UTSNAME_TOTAL_LEN) writable; CPL=0 byte writes for src copy + NUL pad.
    unsafe {
        for i in 0..n { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, src[i]); }
        for i in n..UTSNAME_FIELD_LEN { core::ptr::write_volatile((tp + (off + i) as u64) as *mut u8, 0u8); }
    }
}

/// Resolve the calling task's hostname per UTS namespace membership
/// (F97). CLONE_NEWUTS-bearing task → private uts_hostname slot;
/// else falls back to the global hostname.
/// # C: O(1)
pub fn uts_hostname_for_current() -> alloc::vec::Vec<u8> {
    use core::sync::atomic::Ordering;
    if let Some(t) = crate::sched::current() {
        if (t.ns_membership.load(Ordering::Acquire) & (1u64 << 1)) != 0 {
            // SAFETY: per-task uts_hostname slot single-mutator per `13§5`; running task on this CPU is the sole writer.
            let s = unsafe { (*t.uts_hostname.get()).clone() };
            if !s.is_empty() { return s.into_bytes(); }
        }
    }
    crate::syscalls::hostname::snapshot()
}

/// `sys_uname(buf)` — slot 63. Writes the 6-field utsname struct
/// (sysname/nodename/release/version/machine/domainname, each 65 B).
/// # C: O(1)
pub fn kernel_uname(args: &SyscallArgs) -> i64 {
    let tp = args.a0;
    if let Err(rv) = crate::syscalls::validate_user_buf(tp, UTSNAME_TOTAL_LEN as u64, 1) {
        return rv;
    }
    let host = uts_hostname_for_current();
    let dom = crate::syscalls::hostname::domain_snapshot();
    let dom_bytes: &[u8] = if dom.is_empty() { b"(none)" } else { &dom };
    // SAFETY: range validated; user half mapped writable; byte writes need no alignment.
    unsafe {
        write_utsname_field(tp, 0 * UTSNAME_FIELD_LEN, b"Linux");
        write_utsname_field(tp, 1 * UTSNAME_FIELD_LEN, &host);
        write_utsname_field(tp, 2 * UTSNAME_FIELD_LEN, b"5.15.0-oxide");
        write_utsname_field(tp, 3 * UTSNAME_FIELD_LEN, b"#1 SMP PREEMPT oxide v0.1.0");
        write_utsname_field(tp, 4 * UTSNAME_FIELD_LEN, UNAME_MACHINE);
        write_utsname_field(tp, 5 * UTSNAME_FIELD_LEN, dom_bytes);
    }
    0
}
