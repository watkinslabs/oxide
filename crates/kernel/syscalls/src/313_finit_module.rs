// 313 finit_module — one syscall, one file (docs/53 §0).
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::module_admit::MODULE_IMAGE_MAX;

/// `finit_module(fd, params, flags)` slot 313. Reads the image through `fd`
/// then delegates to the loader.
///
/// Linux `SYSCALL_DEFINE3(finit_module)` order: `may_init_module()`, then the
/// `flags & ~(IGNORE_MODVERSIONS|IGNORE_VERMAGIC|COMPRESSED_FILE)` EINVAL, then
/// the fd lookup (EBADF). Both leading checks were missing until F757 — an
/// unprivileged caller could load a module, and a caller passing an unknown
/// flag got silent success instead of EINVAL, which is how a future flag ends
/// up mistaken for a supported one.
/// # C: O(file size)
pub fn sys_finit_module(args: &SyscallArgs) -> i64 {
    if let Err(rv) = crate::module_admit::may_init_module() { return rv; }
    if !modules::admission::finit_flags_valid(args.a2) {
        return -(Errno::Einval.as_i32() as i64);
    }
    // MODULE_INIT_COMPRESSED_FILE asks the kernel to decompress the image
    // before parsing it. Linux answers EOPNOTSUPP without a decompressor built
    // (its `module_decompress()` stub) — never a
    // silent attempt to parse compressed bytes as ELF, which would surface as
    // a misleading EINVAL "bad module".
    if args.a2 & modules::admission::MODULE_INIT_COMPRESSED_FILE != 0 {
        return -(Errno::Eopnotsupp.as_i32() as i64);
    }
    let fd = args.a0 as i32;
    let cur = match sched::live::current() {
        Some(c) => c, None => return -(Errno::Ebadf.as_i32() as i64),
    };
    // SAFETY: running task on this CPU; sole reader of fd_table slot.
    let fdt = match unsafe { cur.fd_table_ref() } {
        Some(t) => t.clone(), None => return -(Errno::Ebadf.as_i32() as i64),
    };
    let file = match fdt.get(fd) {
        Ok(f) => f, Err(_) => return -(Errno::Ebadf.as_i32() as i64),
    };
    let mut buf = alloc::vec::Vec::new();
    let mut chunk = [0u8; 4096];
    let mut off = 0u64;
    loop {
        match file.inode().read(off, &mut chunk) {
            Ok(0) => break,
            Ok(n) => { buf.extend_from_slice(&chunk[..n]); off += n as u64; }
            Err(_) => return -(Errno::Eio.as_i32() as i64),
        }
        // Linux's ceiling is whatever `vmalloc` can satisfy; over it, ENOMEM.
        // E2BIG was wrong: it is `execve`'s argument-list errno and no libc
        // module path maps it to "image too large".
        if buf.len() > MODULE_IMAGE_MAX { return -(Errno::Enomem.as_i32() as i64); }
    }
    match modules::registry::load_blob(&buf) {
        Some(_) => 0,
        None    => -(Errno::Einval.as_i32() as i64),
    }
}
