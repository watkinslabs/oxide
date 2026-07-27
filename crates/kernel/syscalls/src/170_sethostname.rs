// 170 sethostname — one syscall, one file (docs/53 §0). Linux implements
// `sethostname` and `setdomainname` as the same routine over two
// `new_utsname` fields, so both slots call one work-fn.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

/// `sys_sethostname(name, len)` — slot 170. Writes `new_utsname.nodename` in
/// the calling task's UTS namespace (shared by every member via the exact
/// `nscg` UTS owner) and is what `uname(2)` then reports.
/// # C: O(N)
pub fn sys_sethostname(args: &SyscallArgs) -> i64 {
    crate::hostname::write_uts_name(args, crate::hostname::UtsField::Nodename)
}
