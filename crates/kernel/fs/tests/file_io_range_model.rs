// `copy_file_range(2)`, `sync_file_range(2)` and `readahead(2)` driven over a
// REAL tmpfs filesystem (`fs::tmpfs::TmpfsFs`) through the real work-fns — the
// same inodes, address spaces and `File` gates the syscalls use in the kernel.
//
// Linux references: `fs/read_write.c` `vfs_copy_file_range` (:1553-1646),
// `fs/sync.c` `sync_file_range` (:223-292), `mm/readahead.c` `ksys_readahead`
// (:724-759).

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use std::sync::OnceLock;

use boot_info::{BootInfo, BootMemKind, BootMemRegion};

use fs::readahead::readahead;
use fs::splice::copy_file_range;
use fs::sync::{sync_file_range, SYNC_FILE_RANGE_WAIT_AFTER, SYNC_FILE_RANGE_WAIT_BEFORE,
    SYNC_FILE_RANGE_WRITE};
use fs::tmpfs::TmpfsFs;
use syscall::errno::Errno;
use vfs::inode_ops::CreateCtx;
use vfs::{Dentry, File, InodeRef, OpenFlags};

fn errno(e: Errno) -> i64 { -(e.as_i32() as i64) }

/// tmpfs data lives in real PMM frames, so the hosted harness must stand up a
/// frame allocator before any write. Same pool shape as `fs_syscall_model`.
const HOSTED_PMM_POOL: usize = 16 * 1024 * 1024;
static PMM: OnceLock<()> = OnceLock::new();

fn boot_hosted_pmm() {
    PMM.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(HOSTED_PMM_POOL, 4096).unwrap();
        // SAFETY: non-zero, page-aligned host allocation leaked for the test lifetime.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "hosted PMM pool allocation failed");
        let regions = [BootMemRegion { base_pa: 0, len: HOSTED_PMM_POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo { memmap_count: 1, memmap_ptr: regions.as_ptr(), seed: [0u8; 32],
            boot_ns: 0, rsdp_pa: 0, hhdm_offset: buf, framebuffer: boot_info::BootFramebuffer::EMPTY, bsp_lapic_id: 0, _pad: 0 };
        // SAFETY: BootInfo points at a live region slice for this call; HHDM maps to leaked host memory.
        unsafe { pmm::setup::init_from_boot_info(&info).expect("pmm init"); }
        pmm::setup::init_page_meta((HOSTED_PMM_POOL as u64) / 4096);
    });
}
/// RLIM_INFINITY, i.e. "no RLIMIT_FSIZE clamp" for the copy path.
const NO_FSIZE_LIMIT: u64 = u64::MAX;

fn open(inode: InodeRef, flags: OpenFlags) -> Arc<File> {
    boot_hosted_pmm();
    let d = Dentry::new_root(inode.clone());
    File::new(inode, d, flags)
}

/// One tmpfs with a populated source file and an empty destination file.
fn fixture(src_bytes: &[u8]) -> (Arc<TmpfsFs>, Arc<File>, Arc<File>, InodeRef, InodeRef) {
    let fs = TmpfsFs::new(String::from("fixture"));
    let root = fs.root_inode();
    let si = root.create_child("src", 0o644, &CreateCtx::root()).expect("create src");
    let di = root.create_child("dst", 0o644, &CreateCtx::root()).expect("create dst");
    let sw = open(si.clone(), OpenFlags::O_RDWR);
    assert_eq!(sw.write(src_bytes).expect("seed src"), src_bytes.len());
    let src = open(si.clone(), OpenFlags::empty());
    let dst = open(di.clone(), OpenFlags::O_WRONLY);
    (fs, src, dst, si, di)
}

fn read_all(inode: &InodeRef, n: usize) -> alloc::vec::Vec<u8> {
    let f = open(inode.clone(), OpenFlags::empty());
    let mut buf = alloc::vec![0u8; n];
    let got = f.read(&mut buf).expect("read back");
    buf.truncate(got);
    buf
}

/// A plain copy moves the bytes and advances both working offsets by exactly
/// the count copied.
#[test]
fn copy_file_range_copies_and_advances_offsets() {
    let (_fs, src, dst, _si, di) = fixture(b"abcdefghij");
    let (mut pi, mut po) = (0u64, 0u64);
    assert_eq!(copy_file_range(&src, &mut pi, &dst, &mut po, 10, 0, NO_FSIZE_LIMIT), 10);
    assert_eq!((pi, po), (10, 10));
    assert_eq!(read_all(&di, 32), b"abcdefghij");
}

/// The short-copy contract: a request that runs past the source's EOF returns
/// exactly the bytes that existed. Returning the full requested count here
/// would tell the caller data was copied that never was.
#[test]
fn copy_file_range_is_short_at_eof() {
    let (_fs, src, dst, _si, di) = fixture(b"abcd");
    let (mut pi, mut po) = (0u64, 0u64);
    assert_eq!(copy_file_range(&src, &mut pi, &dst, &mut po, 4096, 0, NO_FSIZE_LIMIT), 4);
    assert_eq!((pi, po), (4, 4));
    assert_eq!(read_all(&di, 32), b"abcd");
    // Starting at/after EOF is a legal zero-byte copy, not an error.
    let (mut pi, mut po) = (4u64, 4u64);
    assert_eq!(copy_file_range(&src, &mut pi, &dst, &mut po, 100, 0, NO_FSIZE_LIMIT), 0);
    assert_eq!((pi, po), (4, 4), "nothing copied, nothing advanced");
}

/// A non-zero `flags` word is EINVAL (`fs/read_write.c:1679`).
#[test]
fn copy_file_range_rejects_nonzero_flags() {
    let (_fs, src, dst, _si, _di) = fixture(b"abcd");
    let (mut pi, mut po) = (0u64, 0u64);
    assert_eq!(copy_file_range(&src, &mut pi, &dst, &mut po, 4, 1, NO_FSIZE_LIMIT),
        errno(Errno::Einval));
}

/// Overlapping ranges of the SAME file are EINVAL, and nothing is written —
/// the check that stops `copy_file_range` from being used as a self-shifting
/// memmove with undefined results (`fs/read_write.c:1539-1542`).
#[test]
fn copy_file_range_same_file_overlap_is_einval_and_writes_nothing() {
    let fs = TmpfsFs::new(String::from("overlap"));
    let root = fs.root_inode();
    let ino = root.create_child("f", 0o644, &CreateCtx::root()).expect("create f");
    let seed = open(ino.clone(), OpenFlags::O_RDWR);
    assert_eq!(seed.write(b"0123456789").unwrap(), 10);
    let rd = open(ino.clone(), OpenFlags::empty());
    let wr = open(ino.clone(), OpenFlags::O_WRONLY);
    let (mut pi, mut po) = (0u64, 4u64);
    assert_eq!(copy_file_range(&rd, &mut pi, &wr, &mut po, 8, 0, NO_FSIZE_LIMIT),
        errno(Errno::Einval));
    assert_eq!(read_all(&ino, 32), b"0123456789", "the file must be untouched");
    // Disjoint ranges of the same file ARE allowed.
    let (mut pi, mut po) = (0u64, 10u64);
    assert_eq!(copy_file_range(&rd, &mut pi, &wr, &mut po, 4, 0, NO_FSIZE_LIMIT), 4);
    assert_eq!(read_all(&ino, 32), b"01234567890123");
}

/// `RLIMIT_FSIZE` clamps the copy and raises EFBIG once the output offset is
/// already at the limit (`fs/read_write.c:1710-1733`).
#[test]
fn copy_file_range_honours_rlimit_fsize() {
    let (_fs, src, dst, _si, di) = fixture(b"abcdefghij");
    let (mut pi, mut po) = (0u64, 0u64);
    assert_eq!(copy_file_range(&src, &mut pi, &dst, &mut po, 10, 0, 4), 4, "clamped to the limit");
    assert_eq!(read_all(&di, 32), b"abcd");
    let (mut pi, mut po) = (0u64, 4u64);
    assert_eq!(copy_file_range(&src, &mut pi, &dst, &mut po, 10, 0, 4), errno(Errno::Efbig));
}

/// A read-only output or an unreadable input is EBADF; a directory on either
/// side is EISDIR. These are the gates the pre-fix implementation had none of.
#[test]
fn copy_file_range_fmode_and_type_gates() {
    let fs = TmpfsFs::new(String::from("gates"));
    let root = fs.root_inode();
    let si = root.create_child("s", 0o644, &CreateCtx::root()).unwrap();
    let di = root.create_child("d", 0o644, &CreateCtx::root()).unwrap();
    let dir = root.mkdir("sub", 0o755, &CreateCtx::root()).unwrap();
    let ro_out = open(di.clone(), OpenFlags::empty());
    let rd_in = open(si.clone(), OpenFlags::empty());
    let wr_out = open(di.clone(), OpenFlags::O_WRONLY);
    let wo_in = open(si.clone(), OpenFlags::O_WRONLY);
    let dir_f = open(dir.clone(), OpenFlags::empty());
    let (mut a, mut b) = (0u64, 0u64);
    assert_eq!(copy_file_range(&rd_in, &mut a, &ro_out, &mut b, 4, 0, NO_FSIZE_LIMIT),
        errno(Errno::Ebadf), "output lacks FMODE_WRITE");
    let (mut a, mut b) = (0u64, 0u64);
    assert_eq!(copy_file_range(&wo_in, &mut a, &wr_out, &mut b, 4, 0, NO_FSIZE_LIMIT),
        errno(Errno::Ebadf), "input lacks FMODE_READ");
    let (mut a, mut b) = (0u64, 0u64);
    assert_eq!(copy_file_range(&dir_f, &mut a, &wr_out, &mut b, 4, 0, NO_FSIZE_LIMIT),
        errno(Errno::Eisdir));
    // O_APPEND on the output is EBADF (not EINVAL as in splice).
    let ap_out = open(di.clone(), OpenFlags::O_WRONLY | OpenFlags::O_APPEND);
    let (mut a, mut b) = (0u64, 0u64);
    assert_eq!(copy_file_range(&rd_in, &mut a, &ap_out, &mut b, 4, 0, NO_FSIZE_LIMIT),
        errno(Errno::Ebadf));
}

/// Two files whose inodes report different filesystem identities (different
/// `st_dev`) are EXDEV. In a booted kernel each mount carries its own
/// superblock `s_dev`; here the identity is stamped explicitly so the rule is
/// exercised without standing up two mounts.
#[test]
fn copy_file_range_across_filesystems_is_exdev() {
    let a = TmpfsFs::new(String::from("a"));
    let b = TmpfsFs::new(String::from("b"));
    let si = a.root_inode().create_child("s", 0o644, &CreateCtx::root()).unwrap();
    let di = b.root_inode().create_child("d", 0o644, &CreateCtx::root()).unwrap();
    si.set_fsid(0x5100_0001);
    di.set_fsid(0x5100_0002);
    let seed = open(si.clone(), OpenFlags::O_RDWR);
    assert_eq!(seed.write(b"abcd").unwrap(), 4);
    let src = open(si, OpenFlags::empty());
    let dst = open(di, OpenFlags::O_WRONLY);
    let (mut p, mut q) = (0u64, 0u64);
    assert_eq!(copy_file_range(&src, &mut p, &dst, &mut q, 4, 0, NO_FSIZE_LIMIT),
        errno(Errno::Exdev));
}

/// `sync_file_range` argument ladder over a real description: unknown flags are
/// EINVAL, negative/wrapping offsets are EINVAL, and a legal call succeeds
/// without requiring FMODE_WRITE (Linux inspects `f_mode` nowhere).
#[test]
fn sync_file_range_argument_ladder() {
    let (_fs, src, _dst, si, _di) = fixture(b"abcdefghij");
    assert_eq!(sync_file_range(&src, 0, 0, 0), 0);
    assert_eq!(sync_file_range(&src, 0, 4, SYNC_FILE_RANGE_WRITE), 0);
    let all = SYNC_FILE_RANGE_WAIT_BEFORE | SYNC_FILE_RANGE_WRITE | SYNC_FILE_RANGE_WAIT_AFTER;
    assert_eq!(sync_file_range(&src, 0, 0, all), 0);
    assert_eq!(sync_file_range(&src, 0, 0, all | 8), errno(Errno::Einval), "unknown flag bit");
    assert_eq!(sync_file_range(&src, -1, 4, 0), errno(Errno::Einval));
    assert_eq!(sync_file_range(&src, 0, -1, 0), errno(Errno::Einval));
    assert_eq!(sync_file_range(&src, i64::MAX, 2, 0), errno(Errno::Einval), "endbyte wraps");
    // A read-only description is fine; the syscall never checks the access mode.
    let ro = open(si, OpenFlags::empty());
    assert_eq!(sync_file_range(&ro, 0, 8, SYNC_FILE_RANGE_WRITE), 0);
}

/// A pipe (or any non REG/BLK/DIR inode) is ESPIPE, not EINVAL
/// (`fs/sync.c:265-268`).
#[test]
fn sync_file_range_on_a_pipe_is_espipe() {
    let inode = fs::pipe::make_pipe_inode();
    let f = open(inode, OpenFlags::O_RDWR);
    assert_eq!(sync_file_range(&f, 0, 0, 0), errno(Errno::Espipe));
    // ... and the flag/offset checks still come FIRST.
    assert_eq!(sync_file_range(&f, 0, 0, 0x10), errno(Errno::Einval));
    assert_eq!(sync_file_range(&f, -8, 0, 0), errno(Errno::Einval));
}

/// `readahead` succeeds with 0 on a readable regular file, and is EBADF /
/// EINVAL — never EPERM — for the rejections. The pre-fix routing answered 0
/// for every fd that happened to be open, including a write-only one.
#[test]
fn readahead_ladder_over_real_inodes() {
    let (_fs, src, dst, si, _di) = fixture(b"abcdefghij");
    assert_eq!(readahead(&src, 0, 10), 0);
    assert_eq!(readahead(&src, 0, 0), 0, "count 0 means to EOF");
    // Write-only description → EBADF.
    assert_eq!(readahead(&dst, 0, 10), errno(Errno::Ebadf));
    // Negative offset / a count that is negative as loff_t → EINVAL.
    assert_eq!(readahead(&src, -1, 10), errno(Errno::Einval));
    assert_eq!(readahead(&src, 0, 1u64 << 63), errno(Errno::Einval));
    // A pipe has no address space → EINVAL (NOT ESPIPE: `readahead(2)` filters
    // on S_ISREG||S_ISBLK before `generic_fadvise` can report ESPIPE).
    let p = open(fs::pipe::make_pipe_inode(), OpenFlags::empty());
    assert_eq!(readahead(&p, 0, 8), errno(Errno::Einval));
    // A directory is EINVAL too.
    let dir = open(_fs.root_inode(), OpenFlags::empty());
    assert_eq!(readahead(&dir, 0, 8), errno(Errno::Einval));
    let _ = si;
}
