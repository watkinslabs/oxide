// `sys_uname` real impl + UTS namespace-aware hostname resolution.
// Split out of syscall_glue.rs to keep that file under the 1000-line cap.

#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use alloc::format;

const UTSNAME_FIELD_LEN: usize = 65;
const UTSNAME_TOTAL_LEN: usize = UTSNAME_FIELD_LEN * 6;

#[cfg(target_arch = "x86_64")]
const UNAME_MACHINE: &[u8] = b"x86_64";
#[cfg(target_arch = "aarch64")]
const UNAME_MACHINE: &[u8] = b"aarch64";

/// Kernel release reported by `uname(2)` and `/proc/sys/kernel/osrelease`.
const UNAME_RELEASE: &[u8] = b"5.15.0-oxide";

/// Write a utsname field at offset `off`: `src` then NUL pad to 65 B.
unsafe fn write_utsname_field(tp: u64, off: usize, src: &[u8]) {
    let n = src.len().min(UTSNAME_FIELD_LEN - 1);
    // SAFETY: caller validated [tp, tp+UTSNAME_TOTAL_LEN) writable; Linux copyout accepts byte-granular storage.
    unsafe {
        for i in 0..n { core::ptr::write_unaligned((tp + (off + i) as u64) as *mut u8, src[i]); }
        for i in n..UTSNAME_FIELD_LEN { core::ptr::write_unaligned((tp + (off + i) as u64) as *mut u8, 0u8); }
    }
}

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

/// `sys_uname(buf)` — slot 63. Writes the 6-field utsname struct
/// (sysname/nodename/release/version/machine/domainname, each 65 B).
/// # C: O(1)
pub fn kernel_uname(args: &SyscallArgs) -> i64 {
    use syscall::errno::Errno;
    let tp = args.a0;
    if let Err(rv) = crate::userbuf::validate_user_buf_writable(tp, UTSNAME_TOTAL_LEN as u64, 1) {
        return rv;
    }
    let owner = match sched::live::current()
        .and_then(|task| task.namespace_owner(namespace_identity::NamespaceKind::Uts))
    {
        Some(owner) => owner, None => return -(Errno::Esrch.as_i32() as i64),
    };
    let host = match crate::hostname::host_for(&owner) {
        Ok(host) => host, Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    let dom = match crate::hostname::dom_for(&owner) {
        Ok(dom) => dom, Err(_) => return -(Errno::Eio.as_i32() as i64),
    };
    let dom_bytes: &[u8] = if dom.is_empty() { b"(none)" } else { &dom };
    let version = format!("#1 SMP PREEMPT oxide v0.1.0 nr_cpus={}", cpu::smp::online_count());
    // Linux `override_release`: a personality(UNAME26) process is shown a
    // 2.6.x release so programs that reject "Linux 3.0"-or-newer keep working.
    let mut faked = [0u8; UTSNAME_FIELD_LEN];
    let mut release: &[u8] = UNAME_RELEASE;
    if sched::live::current().map(|c| sched::personality::uname26(c)).unwrap_or(false) {
        let n = sched::personality::override_release(UNAME_RELEASE, &mut faked);
        release = &faked[..n];
    }
    // SAFETY: range validated; user half mapped writable; byte writes need no alignment.
    unsafe {
        write_utsname_field(tp, 0 * UTSNAME_FIELD_LEN, b"Linux");
        write_utsname_field(tp, 1 * UTSNAME_FIELD_LEN, &host);
        write_utsname_field(tp, 2 * UTSNAME_FIELD_LEN, release);
        write_utsname_field(tp, 3 * UTSNAME_FIELD_LEN, version.as_bytes());
        write_utsname_field(tp, 4 * UTSNAME_FIELD_LEN, UNAME_MACHINE);
        write_utsname_field(tp, 5 * UTSNAME_FIELD_LEN, dom_bytes);
    }
    0
}
