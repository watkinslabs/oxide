// `copy_file_range(2)` work-fn: admission checks, then the staged copy.
//
// The pre-fix implementation was a bare read/write loop with NO checks at all:
// it copied between directories, between filesystems, over an O_APPEND output,
// across overlapping ranges of one file, and it moved both descriptions'
// `f_pos` with `seek` even when explicit offsets were supplied.

use alloc::vec;

use syscall::errno::Errno;
use vfs::{File, FileType, OpenFlags};

/// Maximum single-call read/write byte count, page-aligned down from `i32::MAX`.
const MAX_RW_COUNT: u64 = (i32::MAX as u64) & !0xfff;
/// One batch of the fallback staged copy. Heap, not stack.
const STAGE: usize = 4096;

/// Facts the admission checks decide on, gathered from the two
/// descriptions by the caller.
#[derive(Copy, Clone, Debug)]
pub struct CopyCheckIn {
    pub in_type: FileType,
    pub out_type: FileType,
    pub in_readable: bool,
    pub out_writable: bool,
    pub out_append: bool,
    /// `file_inode(file_in)->i_sb == file_inode(file_out)->i_sb`.
    pub same_sb: bool,
    /// The two descriptions resolve to the SAME inode.
    pub same_inode: bool,
    pub out_immutable: bool,
    /// `IS_SWAPFILE` on either side.
    pub swapfile: bool,
    pub pos_in: u64,
    pub pos_out: u64,
    /// `i_size_read(inode_in)`.
    pub size_in: u64,
    /// `RLIMIT_FSIZE`, or `u64::MAX` for RLIM_INFINITY.
    pub fsize_limit: u64,
    pub len: u64,
}

/// `copy_file_range(2)` admission ladder, returning the CLAMPED byte count.
///
/// The order carries real information:
/// 1. `EISDIR` if either side is a directory.
/// 2. `EINVAL` if either side is a non-regular file that isn't a directory.
/// 3. `EBADF` if the input isn't readable, the output isn't writable, or the
/// output is `O_APPEND` (this call reports `O_APPEND` as EBADF —
/// deliberately not EINVAL, unlike `splice`).
/// 4. `EXDEV` if the two files are on different filesystems (superblock
/// test; with no backend `->copy_file_range` op anywhere, cross-fs is
/// never otherwise supported).
/// 5. `EPERM` if the output is immutable.
/// 6. `ETXTBSY` if either side is a swapfile.
/// 7. `EOVERFLOW` if `pos_in + len` or `pos_out + len` overflows — NOT EINVAL.
/// 8. EOF clamp: at or past the input's EOF the copy is simply zero bytes,
/// otherwise the count is clamped to what remains before EOF.
/// 9. `RLIMIT_FSIZE`: if set, `EFBIG` when `pos_out` is already at/over the
/// limit, else the count clamps to what remains under the limit.
/// 10. LAST: same-file range overlap is `EINVAL` — compared against the
/// ALREADY-CLAMPED count, so a copy whose tail was clipped to EOF can
/// stop overlapping and become legal. # C: O(1)
pub fn copy_file_range_checks(c: &CopyCheckIn) -> Result<u64, Errno> {
    if c.in_type == FileType::Directory || c.out_type == FileType::Directory {
        return Err(Errno::Eisdir);
    }
    if c.in_type != FileType::Regular || c.out_type != FileType::Regular {
        return Err(Errno::Einval);
    }
    if !c.in_readable || !c.out_writable || c.out_append { return Err(Errno::Ebadf); }
    // Cross-filesystem. With no backend `->copy_file_range` op anywhere, the
    // rule reduces to the superblock test.
    if !c.same_sb { return Err(Errno::Exdev); }
    if c.out_immutable { return Err(Errno::Eperm); }
    if c.swapfile { return Err(Errno::Etxtbsy); }
    // Overflow of either resulting end position is EOVERFLOW, NOT EINVAL.
    if c.pos_in.checked_add(c.len).is_none() || c.pos_out.checked_add(c.len).is_none() {
        return Err(Errno::Eoverflow);
    }
    // EOF clamp: at or past EOF the copy is simply zero bytes.
    let mut count = if c.pos_in >= c.size_in { 0 } else { c.len.min(c.size_in - c.pos_in) };
    // RLIMIT_FSIZE clamps, and a start position already at/over the limit is EFBIG.
    if c.fsize_limit != u64::MAX {
        if c.pos_out >= c.fsize_limit { return Err(Errno::Efbig); }
        count = count.min(c.fsize_limit - c.pos_out);
    }
    // Same-file overlap — last, on the clamped count.
    if c.same_inode && count > 0
        && c.pos_out + count > c.pos_in && c.pos_out < c.pos_in + count {
        return Err(Errno::Einval);
    }
    Ok(count.min(MAX_RW_COUNT))
}

/// `copy_file_range(2)` transfer over resolved descriptions. `pos_in`/`pos_out`
/// are the working offsets; the caller decides whether they came from user
/// pointers or from `f_pos`, and writes them back on success (offsets update
/// ONLY when the return value is `> 0`).
///
/// The transfer is the staged-copy fallback every filesystem without a
/// dedicated copy-offload op lands on: a bounded staged copy. Short returns
/// are legal and documented; returning the full requested count while having
/// copied less would be a data-integrity lie, so the loop reports exactly
/// what it wrote. # C: O(len)
pub fn copy_file_range(in_file: &File, pos_in: &mut u64,
                       out_file: &File, pos_out: &mut u64,
                       len: u64, flags: u64, fsize_limit: u64) -> i64 {
    // Any nonzero flags value is EINVAL — checked after the offset copy-in,
    // which the shim has already done.
    if flags != 0 { return -(Errno::Einval.as_i32() as i64); }
    let c = CopyCheckIn {
        in_type: in_file.inode().file_type(),
        out_type: out_file.inode().file_type(),
        in_readable: in_file.f_mode().contains(vfs::Fmode::READ),
        out_writable: out_file.f_mode().contains(vfs::Fmode::WRITE),
        out_append: out_file.flags().contains(OpenFlags::O_APPEND),
        same_sb: same_superblock(in_file, out_file),
        same_inode: core::ptr::eq(in_file.inode().as_ref() as *const vfs::Inode,
                                  out_file.inode().as_ref() as *const vfs::Inode),
        out_immutable: vfs::inode::is_immutable(out_file.inode()),
        swapfile: false,
        pos_in: *pos_in,
        pos_out: *pos_out,
        size_in: in_file.inode().size(),
        fsize_limit,
        len,
    };
    let count = match copy_file_range_checks(&c) { Ok(n) => n, Err(e) => return -(e.as_i32() as i64) };
    // The zero-length short-circuit runs AFTER the checks, so a bad argument
    // still reports its errno for a zero-length request.
    if count == 0 { return 0; }
    let mut total: u64 = 0;
    let mut buf = vec![0u8; STAGE];
    while total < count {
        let want = ((count - total) as usize).min(STAGE);
        let n = match in_file.pread(&mut buf[..want], (*pos_in + total) as i64) {
            Ok(0)                => break,
            Ok(n)                => n,
            Err(e) if total == 0 => return -(e as i64),
            Err(_)               => break,
        };
        let mut w = 0usize;
        while w < n {
            match out_file.pwrite(&buf[w..n], (*pos_out + total + w as u64) as i64) {
                Ok(0)                          => break,
                Ok(k)                          => w += k,
                Err(e) if total == 0 && w == 0 => return -(e as i64),
                Err(_)                         => break,
            }
        }
        total += w as u64;
        if w < n { break; }
    }
    *pos_in += total;
    *pos_out += total;
    total as i64
}

/// Same-filesystem test, expressed over oxide's canonical filesystem
/// identity, `Inode::fsid()` — the same value `stat` encodes into `st_dev`, so
/// "same filesystem" here means exactly what userspace can observe. Comparing
/// the `Arc<SuperBlock>` directly would be wrong for an inode that has no
/// superblock yet (an anon/memfd regular file), which would then report EXDEV
/// against itself. # C: O(1)
fn same_superblock(a: &File, b: &File) -> bool {
    a.inode().fsid() == b.inode().fsid()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> CopyCheckIn {
        CopyCheckIn {
            in_type: FileType::Regular, out_type: FileType::Regular,
            in_readable: true, out_writable: true, out_append: false,
            same_sb: true, same_inode: false, out_immutable: false, swapfile: false,
            pos_in: 0, pos_out: 0, size_in: 1 << 20, fsize_limit: u64::MAX, len: 4096,
        }
    }

    /// A directory on either side is EISDIR and beats the "not a regular file"
    /// EINVAL. # C: O(1)
    #[test]
    fn directory_is_eisdir_other_nonregular_is_einval() {
        assert_eq!(copy_file_range_checks(&CopyCheckIn { in_type: FileType::Directory, ..base() }),
            Err(Errno::Eisdir));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { out_type: FileType::Directory, ..base() }),
            Err(Errno::Eisdir));
        for ft in [FileType::Fifo, FileType::Socket, FileType::CharDev, FileType::BlockDev,
                   FileType::Symlink] {
            assert_eq!(copy_file_range_checks(&CopyCheckIn { in_type: ft, ..base() }),
                Err(Errno::Einval), "{ft:?}");
            assert_eq!(copy_file_range_checks(&CopyCheckIn { out_type: ft, ..base() }),
                Err(Errno::Einval), "{ft:?}");
        }
    }

    /// `O_APPEND` on the OUTPUT is EBADF here — the same condition that
    /// `splice` reports as EINVAL. Two syscalls, two errnos, both deliberate.
    /// # C: O(1)
    #[test]
    fn append_output_is_ebadf_not_einval() {
        assert_eq!(copy_file_range_checks(&CopyCheckIn { out_append: true, ..base() }),
            Err(Errno::Ebadf));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { in_readable: false, ..base() }),
            Err(Errno::Ebadf));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { out_writable: false, ..base() }),
            Err(Errno::Ebadf));
    }

    /// Cross-filesystem is EXDEV, and it is checked AFTER the type/FMODE gates.
    /// # C: O(1)
    #[test]
    fn cross_filesystem_is_exdev() {
        assert_eq!(copy_file_range_checks(&CopyCheckIn { same_sb: false, ..base() }),
            Err(Errno::Exdev));
        // The earlier gates still win.
        assert_eq!(copy_file_range_checks(&CopyCheckIn { same_sb: false, out_append: true, ..base() }),
            Err(Errno::Ebadf));
    }

    /// Immutable output → EPERM, swapfile → ETXTBSY, offset overflow →
    /// EOVERFLOW (not EINVAL). # C: O(1)
    #[test]
    fn eperm_etxtbsy_eoverflow() {
        assert_eq!(copy_file_range_checks(&CopyCheckIn { out_immutable: true, ..base() }),
            Err(Errno::Eperm));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { swapfile: true, ..base() }),
            Err(Errno::Etxtbsy));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { pos_out: u64::MAX - 1, len: 16, ..base() }),
            Err(Errno::Eoverflow));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { pos_in: u64::MAX - 1, len: 16, ..base() }),
            Err(Errno::Eoverflow));
    }

    /// The EOF clamp is the short-copy contract: a request that runs past the
    /// source's end yields exactly the bytes that exist, and a start at/after
    /// EOF yields 0. Reporting the full requested count here would be a
    /// data-integrity lie. # C: O(1)
    #[test]
    fn eof_clamp_produces_short_counts() {
        assert_eq!(copy_file_range_checks(&CopyCheckIn { size_in: 100, len: 4096, ..base() }), Ok(100));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { size_in: 100, pos_in: 60, len: 4096, ..base() }),
            Ok(40));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { size_in: 100, pos_in: 100, ..base() }), Ok(0));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { size_in: 0, ..base() }), Ok(0));
        // A huge request is clamped to MAX_RW_COUNT.
        assert_eq!(copy_file_range_checks(&CopyCheckIn { size_in: u64::MAX / 2, len: u64::MAX / 4, ..base() }),
            Ok(MAX_RW_COUNT));
    }

    /// Overlapping ranges of the SAME file are EINVAL, non-overlapping ranges
    /// of the same file are fine, and the test uses the CLAMPED count — so a
    /// request whose tail is clipped to EOF can stop overlapping. # C: O(1)
    #[test]
    fn same_file_overlap_rules() {
        // [0,4096) into [2048,6144) of one inode: overlaps.
        assert_eq!(copy_file_range_checks(&CopyCheckIn { same_inode: true, pos_in: 0, pos_out: 2048, ..base() }),
            Err(Errno::Einval));
        // Reverse direction also overlaps.
        assert_eq!(copy_file_range_checks(&CopyCheckIn { same_inode: true, pos_in: 2048, pos_out: 0, ..base() }),
            Err(Errno::Einval));
        // Disjoint ranges of the same inode are allowed.
        assert_eq!(copy_file_range_checks(&CopyCheckIn { same_inode: true, pos_in: 0, pos_out: 8192, ..base() }),
            Ok(4096));
        // Clamping to EOF removes the overlap: source has 2048 bytes, so the
        // copy is [0,2048) -> [2048,4096) and no longer overlaps.
        assert_eq!(copy_file_range_checks(&CopyCheckIn { same_inode: true, size_in: 2048,
            pos_in: 0, pos_out: 2048, len: 4096, ..base() }), Ok(2048));
        // A different inode never overlaps.
        assert_eq!(copy_file_range_checks(&CopyCheckIn { pos_in: 0, pos_out: 2048, ..base() }), Ok(4096));
    }

    /// `RLIMIT_FSIZE` clamps the count, and a start already at the limit is
    /// EFBIG. # C: O(1)
    #[test]
    fn rlimit_fsize_clamps_then_efbig() {
        assert_eq!(copy_file_range_checks(&CopyCheckIn { fsize_limit: 1000, pos_out: 900, ..base() }),
            Ok(100));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { fsize_limit: 1000, pos_out: 1000, ..base() }),
            Err(Errno::Efbig));
        assert_eq!(copy_file_range_checks(&CopyCheckIn { fsize_limit: 1000, pos_out: 2000, ..base() }),
            Err(Errno::Efbig));
    }
}
