// 083 mkdir — one syscall, one file (docs/53 §0). Moved verbatim from namei.rs.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use syscall::SyscallArgs;
use syscall::errno::Errno;
use crate::namei_common::{
    read_path, resolve, errno_from_vfs, resolve_parent, path_exists, strip_trailing_slash,
};

/// `mkdir(path, mode)` slot 83.
/// # C: O(N parent entries)
pub fn sys_mkdir(args: &SyscallArgs) -> i64 {
    let raw = match read_path(args.a0) {
        Some(s) => s, None => return -(Errno::Einval.as_i32() as i64),
    };
    let p = resolve(&raw).unwrap_or(raw);
    let p = String::from(strip_trailing_slash(&p));
    if let Err(rv) = crate::landlock::check(&p,
        ::security::landlock::access::MAKE_DIR) { return rv; }
    let mode = args.a1 as u16;
    if path_exists(&p) { return -(Errno::Eexist.as_i32() as i64); }
    let (pino, name) = match resolve_parent(&p) { Ok(x) => x, Err(rv) => return rv };
    match pino.mkdir(&name, mode as u32) { Ok(_) => 0, Err(e) => errno_from_vfs(e) }
}
