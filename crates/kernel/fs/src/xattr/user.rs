// User-buffer edge of the xattr family: `import_xattr_name` / `setxattr_copy` /
// `copy_struct_from_user` on the way in, and `do_getxattr`/`listxattr`'s
// size-capped copy-out on the way back. Linux imports the name, the flags and
// the value BEFORE resolving the path, so a bad name beats `ENOENT`; the
// syscall shims call [`import_set`]/[`import_name`] first for that reason.

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::InodeRef;

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};
use super::ops::{vfs_getxattr, vfs_listxattr, vfs_removexattr, vfs_setxattr};
use super::policy::{check_fit, check_name, check_set_flags, check_value_size, current_xattr_cred,
                    err, XATTR_LIST_MAX, XATTR_NAME_MAX, XATTR_SIZE_MAX};

/// `struct xattr_args` (`uapi/linux/xattr.h`): `{ __u64 value; __u32 size; __u32 flags; }`.
const XATTR_ARGS_SIZE_VER0: usize = 16;

/// Linux `struct kernel_xattr_ctx` — everything `setxattr_copy` imports before
/// the path is resolved.
pub struct SetCtx { pub name: String, pub value: Vec<u8>, pub flags: u32 }

/// `import_xattr_name`: a NUL-terminated name of 1..=`XATTR_NAME_MAX` RAW
/// bytes. Unreadable pointer is `EFAULT`, empty or over-long is `ERANGE`.
/// # C: O(len)
pub fn import_name(name_ptr: u64) -> Result<String, i64> {
    validate_user_buf(name_ptr, 1, 1)?;
    // SAFETY: first byte user-buffer validated; read_user_cstr bounds the remaining C-string scan.
    let bytes = unsafe { devfs::read_user_cstr(name_ptr, XATTR_NAME_MAX + 1) };
    let name = vfs::path_from_bytes(bytes.ok_or(err(Errno::Efault))?);
    check_name(&name)?;
    Ok(name)
}

/// `setxattr_copy`: flags, then name, then the value — with the `E2BIG` size
/// limit applied BEFORE any of the value is copied into the kernel. # C: O(size)
pub fn import_set(name_ptr: u64, value_ptr: u64, size: usize, flags: u32) -> Result<SetCtx, i64> {
    check_set_flags(flags)?;
    let name = import_name(name_ptr)?;
    check_value_size(size)?;
    Ok(SetCtx { name, value: read_user_bytes(value_ptr, size)?, flags })
}

/// `setxattr` work: policy + storage for an already-imported context. # C: O(N_xattr)
pub fn set_on(inode: &InodeRef, ctx: SetCtx) -> i64 {
    let c = current_xattr_cred();
    match vfs_setxattr(inode, &ctx.name, ctx.value, ctx.flags, &c) { Ok(()) => 0, Err(rv) => rv }
}

/// `getxattr` work: `size == 0` PROBES the length without copying; a short
/// buffer is `ERANGE`. # C: O(N_xattr)
pub fn get_on(inode: &InodeRef, name: &str, buf_ptr: u64, size: usize) -> i64 {
    let c = current_xattr_cred();
    let val = match vfs_getxattr(inode, name, &c) { Ok(v) => v, Err(rv) => return rv };
    copy_out(buf_ptr, size, &val, XATTR_SIZE_MAX)
}

/// `listxattr` work: NUL-separated, NUL-terminated names; `size == 0` probes.
/// # C: O(N_xattr)
pub fn list_on(inode: &InodeRef, buf_ptr: u64, size: usize) -> i64 {
    let c = current_xattr_cred();
    let payload = match vfs_listxattr(inode, &c) { Ok(v) => v, Err(rv) => return rv };
    copy_out(buf_ptr, size, &payload, XATTR_LIST_MAX)
}

/// `removexattr` work. # C: O(N_xattr)
pub fn remove_on(inode: &InodeRef, name: &str) -> i64 {
    let c = current_xattr_cred();
    match vfs_removexattr(inode, name, &c) { Ok(()) => 0, Err(rv) => rv }
}

/// Shared `do_getxattr`/`listxattr` tail: probe, fit-check against the capped
/// buffer, then copy. # C: O(len)
pub(super) fn copy_out(buf_ptr: u64, size: usize, src: &[u8], max: usize) -> i64 {
    let want = src.len();
    if size == 0 { return want as i64; }
    if let Err(rv) = check_fit(want, size, max) { return rv; }
    if let Err(rv) = write_user_bytes(buf_ptr, src) { return rv; }
    want as i64
}

/// `copy_struct_from_user` for `struct xattr_args` → `(value, size, flags)`.
/// A short struct is `EINVAL`, an over-page one is `E2BIG`, and any non-zero
/// byte past the known fields is `E2BIG` (unknown extension). `zero_flags`
/// applies the extra `args.flags != 0 → EINVAL` rule `getxattrat` carries.
/// # C: O(args_size)
pub fn import_xattr_args(args_ptr: u64, args_size: usize, zero_flags: bool)
    -> Result<(u64, u32, u32), i64>
{
    if args_size < XATTR_ARGS_SIZE_VER0 { return Err(err(Errno::Einval)); }
    if args_size as u64 > hal::PAGE_SIZE_BYTES { return Err(err(Errno::E2big)); }
    let b = read_user_bytes(args_ptr, args_size)?;
    if b[XATTR_ARGS_SIZE_VER0..].iter().any(|x| *x != 0) { return Err(err(Errno::E2big)); }
    let value = u64::from_le_bytes(b[0..8].try_into().unwrap());
    let size  = u32::from_le_bytes(b[8..12].try_into().unwrap());
    let flags = u32::from_le_bytes(b[12..16].try_into().unwrap());
    if zero_flags && flags != 0 { return Err(err(Errno::Einval)); }
    Ok((value, size, flags))
}

/// Copy `len` bytes in from user. A zero length never touches the pointer
/// (Linux skips the copy entirely, so a NULL value with size 0 is legal).
/// # C: O(len)
fn read_user_bytes(p: u64, len: usize) -> Result<Vec<u8>, i64> {
    if len == 0 { return Ok(Vec::new()); }
    validate_user_buf(p, len as u64, 1)?;
    let mut out = alloc::vec![0u8; len];
    // SAFETY: exact user byte range validated by validate_user_buf; destination is a kernel-owned Vec.
    unsafe {
        for i in 0..len { out[i] = core::ptr::read_unaligned((p + i as u64) as *const u8); }
    }
    Ok(out)
}

/// Copy `src` out to user. # C: O(len)
fn write_user_bytes(p: u64, src: &[u8]) -> Result<(), i64> {
    if src.is_empty() { return Ok(()); }
    validate_user_buf_writable(p, src.len() as u64, 1)?;
    // SAFETY: exact writable user byte range validated; source is a kernel-owned slice.
    unsafe {
        for i in 0..src.len() { core::ptr::write_unaligned((p + i as u64) as *mut u8, src[i]); }
    }
    Ok(())
}
