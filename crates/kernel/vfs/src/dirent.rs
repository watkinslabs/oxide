// `linux_dirent64` packing helpers per `19§4` / `15§4` — extracted
// for hosted unit tests. The on-disk layout is fixed by the Linux
// ABI and surfaces directly to userspace, so byte-level tests are
// the only way to catch silent layout drift.

use alloc::vec::Vec;

use crate::types::FileType;

/// `DT_*` directory-entry type tags (Linux `include/uapi/linux/fcntl.h` via
/// `include/linux/fs_types.h`). These land in `linux_dirent64.d_type` (offset
/// 18) / `linux_dirent`'s trailing byte and tell `ls`/`readdir(3)` the child's
/// type without a per-entry `stat`. Numerically `DT_x == (S_IFx >> 12)` — the
/// Linux `IFTODT` shift — so the type byte is derivable straight from the
/// inode's `S_IFMT` bits (`dtype_from_file_type`).
pub const DT_UNKNOWN: u8 = 0;
pub const DT_FIFO:    u8 = 1;
pub const DT_CHR:     u8 = 2;
pub const DT_DIR:     u8 = 4;
pub const DT_BLK:     u8 = 6;
pub const DT_REG:     u8 = 8;
pub const DT_LNK:     u8 = 10;
pub const DT_SOCK:    u8 = 12;

/// Map a VFS `FileType` to its `linux_dirent*` `d_type` byte. Linux derives
/// this from the inode mode with `IFTODT(mode) = (mode & S_IFMT) >> 12`; we
/// reuse `FileType::to_ifmt` as the single source of truth for the `S_IFMT`
/// bits so the dirent type byte can never drift from `stat`'s mode word. The
/// emitter (`getdents`/`getdents64`) packs this instead of a hand-rolled
/// `DT_REG == 8` match, so no magic literals leak into the syscall shim.
/// # C: O(1)
pub fn dtype_from_file_type(ft: FileType) -> u8 {
    (ft.to_ifmt() >> 12) as u8
}

/// Linux `linux_dirent64` record layout:
///
/// ```text
///   off  size  field
///     0     8  d_ino
///     8     8  d_off       (cookie of next record)
///    16     2  d_reclen    (this record length, 8B-padded)
///    18     1  d_type      (DT_*)
///    19     N  d_name      (NUL-terminated, padded with NULs to reclen)
/// ```
///
/// Returns the total record length including padding (multiple of 8).
pub const DIRENT64_HEADER: usize = 8 + 8 + 2 + 1; // 19

/// Compute reclen for a name of `name_len` bytes (excludes NUL).
/// # C: O(1)
pub const fn dirent64_reclen(name_len: usize) -> usize {
    let raw = DIRENT64_HEADER + name_len + 1;
    (raw + 7) & !7
}

/// Pack a single `linux_dirent64` record into `buf` at offset 0.
/// Caller is responsible for slicing into the user buffer.
/// Returns the record length written (multiple of 8) or `None` if
/// `buf` is too small.
/// # C: O(name.len())
pub fn dirent64_pack(
    buf: &mut [u8],
    ino: u64,
    cookie: u64,
    d_type: u8,
    name: &[u8],
) -> Option<usize> {
    let reclen = dirent64_reclen(name.len());
    if buf.len() < reclen { return None; }
    buf[0..8].copy_from_slice(&ino.to_le_bytes());
    buf[8..16].copy_from_slice(&cookie.to_le_bytes());
    buf[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    buf[18] = d_type;
    let name_off = DIRENT64_HEADER;
    buf[name_off..name_off + name.len()].copy_from_slice(name);
    for b in &mut buf[name_off + name.len()..reclen] { *b = 0; }
    Some(reclen)
}

/// Legacy `linux_dirent` (getdents(2), NR 78) record layout — distinct
/// from `linux_dirent64`:
///
/// ```text
///   off  size  field
///     0     8  d_ino       (unsigned long, 64-bit)
///     8     8  d_off       (unsigned long, cookie of next record)
///    16     2  d_reclen    (this record length, long-aligned)
///    18     N  d_name      (NUL-terminated)
///   ...        zero padding
///  rl-1     1  d_type      (DT_*, stored in the LAST byte — Linux
///                           glibc reads it at `d_reclen - 1`)
/// ```
///
/// The d_type-as-trailing-byte placement is the wart that separates this
/// from `linux_dirent64` (where d_type is a fixed field at offset 18).
pub const DIRENT_HEADER: usize = 8 + 8 + 2; // 18

/// reclen for legacy `linux_dirent`: header + name + NUL + d_type byte,
/// rounded up to `sizeof(long)` (8 on 64-bit). Matches the kernel
/// `ALIGN(offsetof(d_name) + namlen + 2, sizeof(long))`.
/// # C: O(1)
pub const fn dirent_reclen(name_len: usize) -> usize {
    let raw = DIRENT_HEADER + name_len + 2; // +NUL +d_type
    (raw + 7) & !7
}

/// Pack a single legacy `linux_dirent` record into `buf` at offset 0.
/// Returns the record length (multiple of 8) or `None` if `buf` is too
/// small. d_type is written into the last byte of the record per the
/// legacy ABI; bytes between the name's NUL and that last byte are zero.
/// # C: O(name.len())
pub fn dirent_pack(
    buf: &mut [u8],
    ino: u64,
    cookie: u64,
    d_type: u8,
    name: &[u8],
) -> Option<usize> {
    let reclen = dirent_reclen(name.len());
    if buf.len() < reclen { return None; }
    buf[0..8].copy_from_slice(&ino.to_le_bytes());
    buf[8..16].copy_from_slice(&cookie.to_le_bytes());
    buf[16..18].copy_from_slice(&(reclen as u16).to_le_bytes());
    let name_off = DIRENT_HEADER;
    buf[name_off..name_off + name.len()].copy_from_slice(name);
    for b in &mut buf[name_off + name.len()..reclen - 1] { *b = 0; }
    buf[reclen - 1] = d_type;
    Some(reclen)
}

/// Pack a sequence of dirents into `buf`, stopping when the next
/// record wouldn't fit. Returns total bytes written.
/// # C: O(N_records * name.len())
pub fn dirent64_pack_many<I, F>(buf: &mut [u8], iter: I, mut to_record: F) -> usize
where
    I: IntoIterator,
    F: FnMut(I::Item) -> (u64, u64, u8, Vec<u8>),
{
    let mut written = 0;
    for item in iter {
        let (ino, cookie, dt, name) = to_record(item);
        match dirent64_pack(&mut buf[written..], ino, cookie, dt, &name) {
            Some(n) => written += n,
            None    => break,
        }
    }
    written
}
