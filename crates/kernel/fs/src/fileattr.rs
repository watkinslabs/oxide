// `struct file_attr` ABI edge of `file_getattr(2)` / `file_setattr(2)`
// (Linux `fs/file_attr.c`). The inode work is `vfs::fileattr_{get,set}`; this
// module owns only the extensible-struct handshake and the `fsxattr` field
// translation, so every rule below is hosted-testable (`tests/fileattr_abi.rs`).
//
//   struct file_attr {          // uapi/linux/fs.h, FILE_ATTR_SIZE_VER0 = 24
//       __u64 fa_xflags;        // @0
//       __u32 fa_extsize;       // @8
//       __u32 fa_nextents;      // @12  (get-only)
//       __u32 fa_projid;        // @16
//       __u32 fa_cowextsize;    // @20
//   };

extern crate alloc;
use alloc::vec::Vec;

use syscall::errno::Errno;
use vfs::FileAttr;
use vfs::inode::{FS_XFLAG_RDONLY_MASK, FS_XFLAGS_MASK};

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

/// `FILE_ATTR_SIZE_VER0` / `FILE_ATTR_SIZE_LATEST` (`uapi/linux/fs.h`).
pub const FILE_ATTR_SIZE_VER0: usize = 24;

/// Field offsets inside `struct file_attr`.
const OFF_XFLAGS: usize = 0;
const OFF_EXTSIZE: usize = 8;
const OFF_NEXTENTS: usize = 12;
const OFF_PROJID: usize = 16;
const OFF_COWEXTSIZE: usize = 20;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// The `usize` handshake both syscalls run before touching the pointer: Linux
/// rejects an over-page struct with `E2BIG` and a pre-VER0 one with `EINVAL`
/// (`fs/file_attr.c` `SYSCALL_DEFINE5(file_getattr)`). # C: O(1)
pub fn check_struct_size(usize_bytes: usize) -> Result<(), i64> {
    if usize_bytes as u64 > hal::PAGE_SIZE_BYTES { return Err(err(Errno::E2big)); }
    if usize_bytes < FILE_ATTR_SIZE_VER0 { return Err(err(Errno::Einval)); }
    Ok(())
}

fn le32(b: &[u8], off: usize) -> u32 { u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]]) }

fn le64(b: &[u8], off: usize) -> u64 {
    let mut v = [0u8; 8];
    v.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(v)
}

/// `copy_struct_from_user` + `file_attr_to_fileattr` (`fs/file_attr.c`): any
/// non-zero byte past the known fields is an unknown extension (`E2BIG`), an
/// xflag outside `FS_XFLAGS_MASK` is `EINVAL`, and the read-only xflags are
/// dropped before the request reaches the filesystem. `fa_nextents` is
/// get-only and is NOT carried into the request. # C: O(usize)
pub fn decode(bytes: &[u8]) -> Result<FileAttr, i64> {
    if bytes.len() < FILE_ATTR_SIZE_VER0 { return Err(err(Errno::Einval)); }
    if bytes[FILE_ATTR_SIZE_VER0..].iter().any(|b| *b != 0) { return Err(err(Errno::E2big)); }
    let xflags = le64(bytes, OFF_XFLAGS);
    if xflags & !(FS_XFLAGS_MASK as u64) != 0 { return Err(err(Errno::Einval)); }
    let mut fa = vfs::fileattr_fill_xflags((xflags as u32) & !FS_XFLAG_RDONLY_MASK);
    fa.fsx_extsize = le32(bytes, OFF_EXTSIZE);
    fa.fsx_projid = le32(bytes, OFF_PROJID);
    fa.fsx_cowextsize = le32(bytes, OFF_COWEXTSIZE);
    Ok(fa)
}

/// `fileattr_to_file_attr` (`fs/file_attr.c`): the reported xflags are masked to
/// `FS_XFLAGS_MASK`, everything else copies straight across. # C: O(1)
pub fn encode(fa: &FileAttr) -> [u8; FILE_ATTR_SIZE_VER0] {
    let mut out = [0u8; FILE_ATTR_SIZE_VER0];
    out[OFF_XFLAGS..OFF_XFLAGS + 8].copy_from_slice(&((fa.fsx_xflags & FS_XFLAGS_MASK) as u64).to_le_bytes());
    out[OFF_EXTSIZE..OFF_EXTSIZE + 4].copy_from_slice(&fa.fsx_extsize.to_le_bytes());
    out[OFF_NEXTENTS..OFF_NEXTENTS + 4].copy_from_slice(&fa.fsx_nextents.to_le_bytes());
    out[OFF_PROJID..OFF_PROJID + 4].copy_from_slice(&fa.fsx_projid.to_le_bytes());
    out[OFF_COWEXTSIZE..OFF_COWEXTSIZE + 4].copy_from_slice(&fa.fsx_cowextsize.to_le_bytes());
    out
}

/// A backend with no `i_op->fileattr_{get,set}` answers `ENOTTY`; Linux
/// translates that (and `ENOIOCTLCMD`) to `EOPNOTSUPP` at the syscall boundary.
/// # C: O(1)
pub fn map_backend_err(e: vfs::VfsError) -> i64 {
    if e == vfs::VfsError::Enotty { err(Errno::Eopnotsupp) } else { -(e as i64) }
}

/// Read `usize_bytes` of user `struct file_attr` and decode it. # C: O(usize)
pub fn read_user(ptr: u64, usize_bytes: usize) -> Result<FileAttr, i64> {
    check_struct_size(usize_bytes)?;
    validate_user_buf(ptr, usize_bytes as u64, 1)?;
    let mut buf: Vec<u8> = alloc::vec![0u8; usize_bytes];
    // SAFETY: `validate_user_buf` proved the exact byte range is a user address; the
    // destination is a kernel-owned Vec of the same length, and reads are unaligned-safe.
    unsafe {
        for i in 0..usize_bytes { buf[i] = core::ptr::read_unaligned((ptr + i as u64) as *const u8); }
    }
    decode(&buf)
}

/// `copy_struct_to_user`: the VER0 body, then zero-fill whatever extra room the
/// caller declared, so a newer userspace never reads stack garbage. # C: O(usize)
pub fn write_user(ptr: u64, usize_bytes: usize, fa: &FileAttr) -> i64 {
    if let Err(rv) = check_struct_size(usize_bytes) { return rv; }
    if let Err(rv) = validate_user_buf_writable(ptr, usize_bytes as u64, 1) { return rv; }
    let body = encode(fa);
    // SAFETY: `validate_user_buf_writable` proved [ptr, ptr+usize_bytes) is writable user
    // memory; writes are byte-wise so no alignment requirement applies.
    unsafe {
        for i in 0..FILE_ATTR_SIZE_VER0 { core::ptr::write_unaligned((ptr + i as u64) as *mut u8, body[i]); }
        for i in FILE_ATTR_SIZE_VER0..usize_bytes { core::ptr::write_unaligned((ptr + i as u64) as *mut u8, 0u8); }
    }
    0
}
