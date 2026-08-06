//! `shmem_fallocate` (Linux `mm/shmem.c`) reached through the real
//! `vfs_fallocate` ladder over real tmpfs inodes. Pins the two things only the
//! backend can decide: which modes it serves, and that it checks
//! `RLIMIT_FSIZE` even under `FALLOC_FL_KEEP_SIZE` — the deliberate split from
//! ext4, which checks it only when the range grows the file.

extern crate alloc;

use alloc::boxed::Box;
use alloc::string::String;
use alloc::sync::Arc;
use core::ptr;
use core::sync::atomic::{AtomicPtr, Ordering};
use std::sync::{Mutex, OnceLock};

use boot_info::{BootInfo, BootMemKind, BootMemRegion};
use fs::fallocate::{vfs_fallocate, FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE,
    FALLOC_FL_KEEP_SIZE, FALLOC_FL_PUNCH_HOLE, FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_WRITE_ZEROES,
    FALLOC_FL_ZERO_RANGE};
use fs::tmpfs::TmpfsFs;
use sched::{SchedClass, Task};
use syscall::errno::Errno;
use vfs::{CreateCtx, Dentry, File, InodeRef, OpenFlags};

/// Serialises the `sched::current` hook these tests install.
static TEST_LOCK: Mutex<()> = Mutex::new(());
static CURRENT: AtomicPtr<Task> = AtomicPtr::new(ptr::null_mut());
static TASK: OnceLock<&'static Task> = OnceLock::new();

/// Shim-resolved caller argument; the ladder itself never reads it.
fn task() -> &'static Task {
    *TASK.get_or_init(|| &*Box::leak(Box::new(
        Task::new(0xFA12, "falloc-backend", SchedClass::Normal { weight: 1024 }))))
}

const FILE_MODE: u32 = 0o644;
const ALLOCATE_RANGE: u32 = 0;
const LEN: i64 = 8192;
const PATTERN: u8 = 0xA7;

fn e(err: Errno) -> i64 { -(err.as_i32() as i64) }

fn hooked_current() -> Option<&'static Task> {
    let p = CURRENT.load(Ordering::Acquire);
    // SAFETY: tests store only leaked Task pointers and clear the slot before returning.
    if p.is_null() { None } else { Some(unsafe { &*p }) }
}

fn install_current(fsize_limit: u64) {
    let task = Box::leak(Box::new(Task::new(0x7A11, "falloc-test", SchedClass::Normal { weight: 1024 })));
    task.set_rlimit(sched::rlimit::rlim::FSIZE, (fsize_limit, fsize_limit));
    CURRENT.store(task as *const Task as *mut Task, Ordering::Release);
    sched::set_current_hook(hooked_current);
    fs::truncate::install_rlimit_fsize_hook();
}

fn clear_current() {
    CURRENT.store(ptr::null_mut(), Ordering::Release);
    sched::set_current_hook(hooked_current);
    vfs::clear_rlimit_fsize_hook();
}

static PMM: OnceLock<()> = OnceLock::new();
const HOSTED_PMM_POOL: usize = 16 * 1024 * 1024;

/// shmem commits REAL frames, so the backend needs a live PMM to exercise.
fn boot_hosted_pmm() {
    PMM.get_or_init(|| {
        let layout = std::alloc::Layout::from_size_align(HOSTED_PMM_POOL, 4096).unwrap();
        // SAFETY: non-zero, page-aligned host allocation leaked for the test-binary lifetime.
        let buf = unsafe { std::alloc::alloc_zeroed(layout) } as u64;
        assert!(buf != 0, "hosted PMM pool allocation failed");
        let regions = [BootMemRegion { base_pa: 0, len: HOSTED_PMM_POOL as u64, kind: BootMemKind::Usable }];
        let info = BootInfo {
            memmap_count: 1, memmap_ptr: regions.as_ptr(), seed: [0u8; 32], boot_ns: 0,
            rsdp_pa: 0, hhdm_offset: buf, framebuffer: boot_info::BootFramebuffer::EMPTY, bsp_lapic_id: 0, _pad: 0,
        };
        // SAFETY: BootInfo names a live region slice for this call; HHDM maps to leaked host memory.
        unsafe { pmm::setup::init_from_boot_info(&info).expect("pmm init"); }
        pmm::setup::init_page_meta((HOSTED_PMM_POOL as u64) / 4096);
    });
}

struct Fixture { _fs: Arc<TmpfsFs>, root: InodeRef }

fn fixture() -> Fixture {
    boot_hosted_pmm();
    let fs = TmpfsFs::new(String::from("falloc-tmpfs"));
    let root = fs.root_inode();
    Fixture { _fs: fs, root }
}

fn rw_file(f: &Fixture, name: &str) -> (InodeRef, Arc<File>) {
    let ino = f.root.create_child(name, FILE_MODE, &CreateCtx::root()).expect("create");
    let file = File::new(Arc::clone(&ino), Dentry::new_root(Arc::clone(&ino)), OpenFlags::O_RDWR);
    (ino, file)
}

/// `shmem_fallocate` mode mask: only `KEEP_SIZE` and `PUNCH_HOLE`. The VFS
/// ladder accepts ZERO_RANGE / UNSHARE_RANGE / COLLAPSE / INSERT /
/// WRITE_ZEROES, so these `EOPNOTSUPP`s are the BACKEND's answer, which is the
/// whole point of handing the raw mode down.
#[test]
fn shmem_serves_only_preallocation_and_hole_punching() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let (_ino, file) = rw_file(&f, "modes");

    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, 0, LEN), 0);
    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_KEEP_SIZE, 0, LEN), 0);
    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, LEN), 0);
    for mode in [FALLOC_FL_ZERO_RANGE, FALLOC_FL_ZERO_RANGE | FALLOC_FL_KEEP_SIZE,
                 FALLOC_FL_UNSHARE_RANGE, FALLOC_FL_UNSHARE_RANGE | FALLOC_FL_KEEP_SIZE,
                 FALLOC_FL_COLLAPSE_RANGE, FALLOC_FL_INSERT_RANGE, FALLOC_FL_WRITE_ZEROES] {
        assert_eq!(vfs_fallocate(task(), &file, mode, 0, LEN), e(Errno::Eopnotsupp), "mode {mode:#x}");
    }
}

#[test]
fn allocate_range_extends_i_size_and_keep_size_does_not() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let (ino, file) = rw_file(&f, "sizes");

    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, 0, LEN), 0);
    assert_eq!(ino.size(), LEN as u64, "mode 0 moves the file's end");

    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_KEEP_SIZE, LEN, LEN), 0);
    assert_eq!(ino.size(), LEN as u64, "KEEP_SIZE commits pages past EOF without resizing");
}

/// A hole reads as zeros and leaves `i_size` alone.
#[test]
fn punch_hole_zeroes_the_range_without_resizing() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    clear_current();
    let f = fixture();
    let (ino, file) = rw_file(&f, "punch");
    let payload = alloc::vec![PATTERN; LEN as usize];
    assert_eq!(ino.write(0, &payload).expect("write"), LEN as usize);
    assert_eq!(ino.size(), LEN as u64);

    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, LEN), 0);
    assert_eq!(ino.size(), LEN as u64, "punching never changes the size");
    let mut back = alloc::vec![PATTERN; LEN as usize];
    ino.read(0, &mut back).expect("read");
    assert!(back.iter().all(|b| *b == 0), "a punched range must read as zeros");
}

/// "We need to check rlimit even when FALLOC_FL_KEEP_SIZE" — shmem commits real
/// pages either way, so the caller's soft `RLIMIT_FSIZE` binds on the END of the
/// range and not on `i_size`. `inode_newsize_ok` posts `SIGXFSZ` before `EFBIG`.
#[test]
fn rlimit_fsize_binds_even_under_keep_size() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = fixture();
    let (ino, file) = rw_file(&f, "rlimit");
    install_current(LEN as u64);

    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_KEEP_SIZE, 0, LEN), 0, "exactly at the limit is allowed");
    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_KEEP_SIZE, 0, LEN + 1), e(Errno::Efbig),
        "KEEP_SIZE does NOT exempt shmem from RLIMIT_FSIZE");
    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, 0, LEN + 1), e(Errno::Efbig));
    assert_eq!(ino.size(), 0, "a rejected request must not move i_size");

    install_current(sched::rlimit::INFINITY);
    assert_eq!(vfs_fallocate(task(), &file, ALLOCATE_RANGE, 0, LEN + 1), 0, "RLIM_INFINITY imposes no cap");
    clear_current();
}

/// Hole punching deallocates, so it is never blocked by `RLIMIT_FSIZE`.
#[test]
fn rlimit_fsize_does_not_bind_hole_punching() {
    let _g = TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let f = fixture();
    let (_ino, file) = rw_file(&f, "punch-rlimit");
    install_current(1);

    assert_eq!(vfs_fallocate(task(), &file, FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE, 0, LEN), 0);
    clear_current();
}
