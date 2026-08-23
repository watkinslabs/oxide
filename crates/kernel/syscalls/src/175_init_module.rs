// 175 init_module — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::module_admit::{ELF64_EHDR_LEN, MODULE_IMAGE_MAX};

/// `init_module(image, len, params)` slot 175. `image` points at the `.ko`
/// bytes in the caller's address space, `len` is their size.
///
/// Linux `SYSCALL_DEFINE3(init_module)` runs `may_init_module()` FIRST — before
/// it looks at `umod`, `len` or `uargs` — so an unprivileged caller gets EPERM
/// without learning anything about the arguments it passed. That capability
/// test was absent here until F757: any unprivileged process could relocate
/// and execute arbitrary bytes in ring 0.
/// # C: O(len)
pub fn sys_init_module(args: &SyscallArgs) -> i64 {
    if let Err(rv) = crate::module_admit::may_init_module() { return rv; }
    let img = args.a0;
    let len = args.a1 as usize;
    if img == 0 { return -(Errno::Efault.as_i32() as i64); }
    // Linux `copy_module_from_user`: an image too short to hold an ELF header
    // is ENOEXEC (not EINVAL), and an image too large to buffer is the ENOMEM
    // that its `__vmalloc` failure produces.
    if len < ELF64_EHDR_LEN { return -(Errno::Enoexec.as_i32() as i64); }
    if len > MODULE_IMAGE_MAX { return -(Errno::Enomem.as_i32() as i64); }
    // `copy_from_user` faults safely: an image that runs off the end of a
    // mapping is EFAULT rather than a kernel page fault on the first unmapped
    // page.
    if let Err(rv) = crate::userbuf::validate_user_buf_readable(img, len as u64, 1) {
        return rv;
    }
    let mut bytes = alloc::vec![0u8; len];
    if uaccess::copy_from_user(&mut bytes, img).is_err() {
        return -(Errno::Efault.as_i32() as i64);
    }
    match modules::registry::load_blob(&bytes) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}
