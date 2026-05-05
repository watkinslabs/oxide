// `linux_dirent64` packing helpers per `19§4` / `15§4` — extracted
// for hosted unit tests. The on-disk layout is fixed by the Linux
// ABI and surfaces directly to userspace, so byte-level tests are
// the only way to catch silent layout drift.

use alloc::vec::Vec;

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
