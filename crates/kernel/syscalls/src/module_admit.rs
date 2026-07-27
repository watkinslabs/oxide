// Shared admission bridge for slots 175/176/313. The DECISION is
// `modules::admission` (hosted-tested); this file only binds it to the live
// task's credentials and to the syscall return convention, so it is the one
// place the three module syscalls can disagree — and therefore the one place
// to keep them from disagreeing.
#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;

/// Upper bound on a module image this kernel will buffer. Linux has no
/// explicit cap — `__vmalloc` simply fails — so an over-large image maps to
/// ENOMEM here, the same errno Linux produces by that route. (An image
/// SHORTER than an ELF header is ENOEXEC in `copy_module_from_user`, not
/// EINVAL.)
pub const MODULE_IMAGE_MAX: usize = 64 * 1024 * 1024;

/// Smallest image that can possibly be an ELF object: Linux
/// `if (info->len < sizeof(*(info->hdr))) return -ENOEXEC;` over `Elf64_Ehdr`.
pub const ELF64_EHDR_LEN: usize = 64;

/// Linux `may_init_module()` bound to the running task: `capable(CAP_SYS_MODULE)`
/// in the INITIAL user namespace, plus the `kernel.modules_disabled` latch.
///
/// `capable()` (not `ns_capable(current_user_ns(), ...)`) is what Linux uses
/// here, so `unshare(CLONE_NEWUSER)` cannot manufacture the privilege.
/// # C: O(1)
pub fn may_init_module() -> Result<(), i64> {
    let denied = Err(-(Errno::Eperm.as_i32() as i64));
    let Some(cur) = sched::live::current() else { return denied };
    match modules::admission::may_init_module(
        crate::perm_common::capable(&cur, sched::cap::SYS_MODULE))
    {
        modules::admission::Admission::Allow  => Ok(()),
        modules::admission::Admission::Denied => denied,
    }
}
