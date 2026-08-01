//! `vfs_fallocate` (Linux `fs/open.c:250-352`) driven over REAL tmpfs inodes
//! and real descriptions — no mocks. Pins the error ladder, whose order is not
//! the order the arguments suggest: one `EINVAL` for the range and nothing
//! else, `EOPNOTSUPP` for every unsupported mode, inode-flag rejections ahead
//! of the file-type ladder, and the `EFBIG` caps last.

extern crate alloc;

use alloc::string::String;
use alloc::sync::Arc;
use std::sync::OnceLock;

use boot_info::{BootInfo, BootMemKind, BootMemRegion};
use fs::fallocate::{vfs_fallocate, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE,
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_NO_HIDE_STALE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_UNSHARE_RANGE,
    FALLOC_FL_WRITE_ZEROES, FALLOC_FL_ZERO_RANGE};
use fs::tmpfs::TmpfsFs;
use syscall::errno::Errno;
use sched::{SchedClass, Task};
use vfs::{CreateCtx, Dentry, File, FileType, InodeRef, OpenFlags};

const FILE_MODE: u32 = 0o644;
const DIR_MODE: u32 = 0o755;
const OFF: i64 = 0;
const LEN: i64 = 8192;
/// Any mode carrying a real mode bit — the append-only gate's positive case.
const ALLOCATE_RANGE: u32 = 0;

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

static TASK: OnceLock<&'static Task> = OnceLock::new();

/// The calling task the syscall shim resolves. Nothing in the ladder consults
/// it (Linux `vfs_fallocate` is task-free), so one shared instance suffices.
fn task() -> &'static Task {
    *TASK.get_or_init(|| &*alloc::boxed::Box::leak(alloc::boxed::Box::new(
        Task::new(0xFA11, "falloc-ladder", SchedClass::Normal { weight: 1024 }))))
}

static PMM: OnceLock<()> = OnceLock::new();
const HOSTED_PMM_POOL: usize = 16 * 1024 * 1024;

/// The success arms reach shmem, which commits REAL frames.
fn boot_hosted_pmm() {
    PMM.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(HOSTED_PMM_POOL, 4096).unwrap();
        // SAFETY: non-zero, page-aligned host allocation leaked for the test-binary lifetime.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "hosted PMM pool allocation failed");
        let regions = [BootMemRegion { base_pa: 0, len: HOSTED_PMM_POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1, memmap_ptr: regions.as_ptr(), seed: [0u8; 32], boot_ns: 0,
            rsdp_pa: 0, hhdm_offset: buf, bsp_lapic_id: 0, _pad: 0,
        };
        // SAFETY: BootInfo names a live region slice for this call; HHDM maps to leaked host memory.
        unsafe { pmm::setup::init_from_boot_info(&info).expect("pmm init"); }
        pmm::setup::init_page_meta((HOSTED_PMM_POOL as u64) / 4096);
    });
}

struct Fixture { _fs: Arc<TmpfsFs>, root: InodeRef }

fn fixture() -> Fixture {
    boot_hosted_pmm();
    let fs = TmpfsFs::new(String::from("falloc"));
    let root = fs.root_inode();
    Fixture { _fs: fs, root }
}

fn description(inode: &InodeRef, flags: OpenFlags) -> Arc<File> {
    File::new(Arc::clone(inode), Dentry::new_root(Arc::clone(inode)), flags)
}

/// A writable description over a fresh regular tmpfs file.
fn rw_file(f: &Fixture, name: &str) -> (InodeRef, Arc<File>) {
    let ino = f.root.create_child(name, FILE_MODE, &CreateCtx::root()).expect("create");
    let file = description(&ino, OpenFlags::O_RDWR);
    (ino, file)
}

/// A writable description over a node of `ft` created by `mknod(2)`.
fn rw_special(f: &Fixture, name: &str, ft: FileType) -> Arc<File> {
    f.root.mknod_child(name, vfs::mk_mode(ft, FILE_MODE as u16) as u16, 0, &CreateCtx::root())
        .expect("mknod");
    let ino = f.root.lookup(name).expect("lookup");
    description(&ino, OpenFlags::O_RDWR)
}

#[test]
fn range_check_owns_the_only_einval() {
    let f = fixture();
    let (_ino, file) = rw_file(&f, "range");

    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, -1, LEN), e(Errno::Einval), "offset < 0");
    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, i64::MIN, LEN), e(Errno::Einval));
    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, OFF, 0), e(Errno::Einval), "len == 0 is an error, not a no-op");
    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, OFF, -1), e(Errno::Einval), "len < 0");
    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, OFF, LEN), 0, "a valid range succeeds");
}

/// The range check is step 1 and the mode gate step 2, so a bad range on a bad
/// mode reports the range.
#[test]
fn range_check_precedes_the_mode_gate() {
    let f = fixture();
    let (_ino, file) = rw_file(&f, "order");

    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_NO_HIDE_STALE, -1, LEN), e(Errno::Einval));
    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_NO_HIDE_STALE, OFF, LEN), e(Errno::Eopnotsupp));
}

/// The mode gate is step 2 and the `FMODE_WRITE` check step 4, so a bad mode on
/// a read-only description reports the mode, not `EBADF`.
#[test]
fn mode_gate_precedes_the_writability_check() {
    let f = fixture();
    let ino = f.root.create_child("ro", FILE_MODE, &CreateCtx::root()).expect("create");
    let ro = description(&ino, OpenFlags::O_RDONLY);

    assert_eq!(vfs_fallocate(task(), &ro, FALLOC_FL_NO_HIDE_STALE, OFF, LEN), e(Errno::Eopnotsupp));
    assert_eq!(vfs_fallocate(task(), &ro, ALLOCATE_RANGE, OFF, LEN), e(Errno::Ebadf), "no FMODE_WRITE");
}

/// `O_PATH` carries neither READ nor WRITE, so it is `EBADF` here as well as at
/// `fdget` — the reason the syscall shim's fd lookup is not duplicated inside.
#[test]
fn o_path_and_read_only_descriptions_are_ebadf() {
    let f = fixture();
    let ino = f.root.create_child("paths", FILE_MODE, &CreateCtx::root()).expect("create");

    for flags in [OpenFlags::O_RDONLY, OpenFlags::O_PATH] {
        let d = description(&ino, flags);
        assert_eq!(vfs_fallocate(task(), &d, ALLOCATE_RANGE, OFF, LEN), e(Errno::Ebadf), "{flags:?}");
    }
    assert_eq!(vfs_fallocate(task(), &description(&ino, OpenFlags::O_WRONLY), ALLOCATE_RANGE, OFF, LEN), 0);
}

/// "On append-only files only space preallocation is supported": mode 0 and
/// bare `KEEP_SIZE` pass, every real mode bit is `EPERM`.
#[test]
fn append_only_admits_preallocation_and_nothing_else() {
    let f = fixture();
    let (ino, file) = rw_file(&f, "append");
    ino.set_i_flags(vfs::S_APPEND);

    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, OFF, LEN), 0, "plain preallocation is allowed");
    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_KEEP_SIZE, OFF, LEN), 0, "KEEP_SIZE alone is a flag, not a mode");
    for mode in [FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, FALLOC_FL_ZERO_RANGE,
                 FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE, FALLOC_FL_UNSHARE_RANGE,
                 FALLOC_FL_WRITE_ZEROES] {
        assert_eq!(vfs_fallocate(task(), &file, mode, OFF, LEN), e(Errno::Eperm), "mode {mode:#x} on append-only");
    }
}

#[test]
fn immutable_rejects_even_plain_preallocation() {
    let f = fixture();
    let (ino, file) = rw_file(&f, "immutable");
    ino.set_i_flags(vfs::S_IMMUTABLE);

    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, OFF, LEN), e(Errno::Eperm));
    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_KEEP_SIZE, OFF, LEN), e(Errno::Eperm));
}

/// `IS_SWAPFILE` — swapon owns the block map, so no mode may move it.
#[test]
fn active_swapfile_is_etxtbsy() {
    let f = fixture();
    let (ino, file) = rw_file(&f, "swapfile");
    ino.set_i_flags(vfs::S_SWAPFILE);

    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, OFF, LEN), e(Errno::Etxtbsy));
    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, OFF, LEN), e(Errno::Etxtbsy));
}

/// Three distinct errnos for three wrong types, and none of them is `EINVAL`.
#[test]
fn file_type_ladder_is_espipe_eisdir_enodev() {
    let f = fixture();
    let fifo = rw_special(&f, "fifo", FileType::Fifo);
    let sock = rw_special(&f, "sock", FileType::Socket);
    let chr  = rw_special(&f, "chr", FileType::CharDev);
    let dir = f.root.mkdir("d", DIR_MODE, &CreateCtx::root()).expect("mkdir");
    let dir_file = description(&dir, OpenFlags::O_RDWR);

    assert_eq!(vfs_fallocate(task(), &fifo, ALLOCATE_RANGE, OFF, LEN), e(Errno::Espipe));
    assert_eq!(vfs_fallocate(task(), &dir_file, ALLOCATE_RANGE, OFF, LEN), e(Errno::Eisdir));
    assert_eq!(vfs_fallocate(task(), &sock, ALLOCATE_RANGE, OFF, LEN), e(Errno::Enodev));
    assert_eq!(vfs_fallocate(task(), &chr, ALLOCATE_RANGE, OFF, LEN), e(Errno::Enodev));
    let link = f.root.symlink_child("l", b"fifo", &CreateCtx::root());
    assert!(link.is_ok());
    let sym = description(&f.root.lookup("l").expect("lookup symlink"), OpenFlags::O_RDWR);
    assert_eq!(vfs_fallocate(task(), &sym, ALLOCATE_RANGE, OFF, LEN), e(Errno::Enodev));
}

/// The inode-flag rejections are steps 5-7 and the type ladder steps 9-11, so
/// an immutable directory reports `EPERM` and never reaches `EISDIR`.
#[test]
fn inode_flag_rejections_precede_the_file_type_ladder() {
    let f = fixture();
    let dir = f.root.mkdir("locked", DIR_MODE, &CreateCtx::root()).expect("mkdir");
    let dir_file = description(&dir, OpenFlags::O_RDWR);
    assert_eq!(vfs_fallocate(task(), &dir_file, ALLOCATE_RANGE, OFF, LEN), e(Errno::Eisdir), "baseline");

    dir.set_i_flags(vfs::S_IMMUTABLE);
    assert_eq!(vfs_fallocate(task(), &dir_file, ALLOCATE_RANGE, OFF, LEN), e(Errno::Eperm));
    dir.set_i_flags(vfs::S_SWAPFILE);
    assert_eq!(vfs_fallocate(task(), &dir_file, ALLOCATE_RANGE, OFF, LEN), e(Errno::Etxtbsy));
}

/// The type ladder is steps 9-11 and the arithmetic cap step 12, so a wrapping
/// range on a FIFO still reports the type.
#[test]
fn wraparound_is_efbig_and_the_type_ladder_precedes_it() {
    let f = fixture();
    let (_ino, file) = rw_file(&f, "wrap");
    let fifo = rw_special(&f, "wrapfifo", FileType::Fifo);

    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, i64::MAX, 1), e(Errno::Efbig));
    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, i64::MAX - 1, 4), e(Errno::Efbig));
    assert_eq!(vfs_fallocate(task(), &fifo, ALLOCATE_RANGE, i64::MAX, 1), e(Errno::Espipe));
}

/// Every oxide superblock reports `s_maxbytes == MAX_LFS_FILESIZE`, so a range
/// that survives the `check_add_overflow` step is representable by definition
/// and the `s_maxbytes` arm is reached only by a backend that lowers the cap.
#[test]
fn s_maxbytes_cap_sits_at_max_lfs_filesize() {
    let fs_ty = vfs::fs::FsType::new("maxfs", 0x1601, vfs::fs::FsFlags::empty(),
        alloc::boxed::Box::new(|_, _, _, _, _| Err(vfs::VfsError::Enotty)));
    let sb = vfs::SuperBlock::new(fs_ty, Arc::new(vfs::SimpleSuperOps {
        magic: 0x1601, block_size: 4096, options: String::new(),
    }), 0x1601, 0x1601, 4096, String::from("maxfs"), Arc::new(()));
    assert_eq!(sb.s_maxbytes(), vfs::superblock::MAX_LFS_FILESIZE);
    assert_eq!(sb.s_maxbytes(), i64::MAX as u64);
}
