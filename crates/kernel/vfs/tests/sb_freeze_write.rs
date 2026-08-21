//! superblock D27 — sb freeze gate on the write(2) path + freeze/thaw round-trip.
//!
//! `File::write`/`pwrite`/`write_iter` now take `sb_start_write` (Linux
//! `file_start_write`) before the data dispatch: a write to a FROZEN superblock
//! blocks until `thaw_super` and then proceeds. `freeze_super`/`thaw_super` are
//! what the FIFREEZE/FITHAW ioctls invoke, so this exercises that round-trip too.

use std::sync::Arc;
use std::sync::{Condvar, Mutex, MutexGuard};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::thread;
use std::time::Duration;

use vfs::superblock::{FileSystemType, SbStatFs, SuperBlock, SuperOps};
use vfs::{
    default_inode_ops, mk_mode, Dentry, File, FileOps, FileType, Inode, InodeBuilder, InodeRef,
    KResult, OpenFlags, VfsError,
};

static SERIAL: Mutex<()> = Mutex::new(());
static WAIT: (Mutex<WaitState>, Condvar) = (Mutex::new(WaitState { parked: false, wake: false }), Condvar::new());

struct WaitState { parked: bool, wake: bool }

fn guard() -> MutexGuard<'static, ()> {
    SERIAL.lock().unwrap_or_else(|e| e.into_inner())
}

fn install_wait_hooks() {
    let (m, _) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    st.parked = false;
    st.wake = false;
    drop(st);
    vfs::superblock::set_freeze_wait_hooks(park_hook, schedule_hook, wake_hook);
}

fn park_hook(_key: usize) {
    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    st.parked = true;
    cv.notify_all();
}

fn schedule_hook() {
    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    while !st.wake {
        st = cv.wait(st).unwrap_or_else(|e| e.into_inner());
    }
}

fn wake_hook(_key: usize) {
    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    st.wake = true;
    cv.notify_all();
}

struct FrType;
impl FileSystemType for FrType {
    fn name(&self) -> &str { "frzfs" }
    fn mount(&self, _s: Option<&str>, _o: &str) -> KResult<Arc<SuperBlock>> { Err(VfsError::Einval) }
}
struct FrOps;
impl SuperOps for FrOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    // freeze_fs/thaw_fs use the trait no-op defaults (no on-disk backend here).
}
struct CountFreezeOps { freezes: AtomicU32 }
impl SuperOps for CountFreezeOps {
    fn statfs(&self) -> KResult<SbStatFs> { Ok(SbStatFs::default()) }
    fn freeze_fs(&self) -> KResult<()> {
        self.freezes.fetch_add(1, Ordering::Release);
        Ok(())
    }
}

// A regular-file data path that always accepts the bytes — so a successful
// write returns the buffer length and the frozen-EROFS path is isolated to the
// sb gate, not a missing backend op.
struct AcceptOps;
impl FileOps for AcceptOps {
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> { Ok(buf.len()) }
}
struct BlockingData {
    entered: Mutex<bool>,
    release: Mutex<bool>,
    cv:      Condvar,
}
struct BlockingOps { data: Arc<BlockingData> }
impl FileOps for BlockingOps {
    fn write(&self, _inode: &Inode, _off: u64, buf: &[u8]) -> KResult<usize> {
        {
            let mut entered = self.data.entered.lock().unwrap_or_else(|e| e.into_inner());
            *entered = true;
            self.data.cv.notify_all();
        }
        let mut release = self.data.release.lock().unwrap_or_else(|e| e.into_inner());
        while !*release {
            release = self.data.cv.wait(release).unwrap_or_else(|e| e.into_inner());
        }
        Ok(buf.len())
    }
}

fn sb() -> Arc<SuperBlock> {
    SuperBlock::new(Arc::new(FrType), Arc::new(FrOps), 0x1234, 9, 4096, "frzfs".into(), Arc::new(()))
}
fn sb_counting() -> (Arc<SuperBlock>, Arc<CountFreezeOps>) {
    let ops = Arc::new(CountFreezeOps { freezes: AtomicU32::new(0) });
    (SuperBlock::new(Arc::new(FrType), ops.clone(), 0x5678, 9, 4096, "frzfs".into(), Arc::new(())), ops)
}
fn reg_inode(sb: &Arc<SuperBlock>) -> InodeRef {
    InodeBuilder::new(2, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(AcceptOps))
        .sb(Arc::downgrade(sb)).nlink(1).build()
}
fn blocking_inode(sb: &Arc<SuperBlock>, data: Arc<BlockingData>) -> InodeRef {
    InodeBuilder::new(3, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(BlockingOps { data }))
        .sb(Arc::downgrade(sb)).nlink(1).build()
}
fn rw_file(inode: &InodeRef) -> Arc<File> {
    let d = Dentry::new(None, "f".into(), inode.clone());
    File::new(inode.clone(), d, OpenFlags::O_RDWR)
}

#[test]
fn write_to_frozen_sb_blocks_until_thaw_then_writes() {
    let _serial = guard();
    install_wait_hooks();
    let sb = sb();
    let ino = reg_inode(&sb);
    let f = rw_file(&ino);

    // Unfrozen: write admitted, returns the byte count.
    assert_eq!(f.write(b"hello"), Ok(5), "unfrozen write admitted");
    assert_eq!(sb.sb_writers(), 0, "writer count balanced after write");

    // Freeze (FIFREEZE): now FROZEN at COMPLETE level.
    assert_eq!(sb.freeze_super(), Ok(()), "freeze_super succeeds");
    assert!(sb.is_frozen(), "sb reports frozen");

    let done = Arc::new(AtomicBool::new(false));
    let t_done = done.clone();
    let t_file = f.clone();
    let th = thread::spawn(move || {
        assert_eq!(t_file.write(b"x"), Ok(1), "write resumes after thaw");
        t_done.store(true, Ordering::Release);
    });
    let (m, cv) = &WAIT;
    let mut st = m.lock().unwrap_or_else(|e| e.into_inner());
    while !st.parked {
        st = cv.wait(st).unwrap_or_else(|e| e.into_inner());
    }
    drop(st);
    thread::sleep(Duration::from_millis(20));
    assert!(!done.load(Ordering::Acquire), "writer remains blocked while frozen");
    assert_eq!(sb.sb_writers(), 0, "parked writer is not counted as in-flight");

    // Thaw (FITHAW): writes re-admitted.
    assert_eq!(sb.thaw_super(), Ok(()), "thaw_super succeeds");
    th.join().expect("writer thread joins");
    assert!(done.load(Ordering::Acquire), "writer completed after thaw");
    assert!(!sb.is_frozen(), "sb no longer frozen");
    assert_eq!(f.write(b"world!"), Ok(6), "write re-admitted after thaw");
    assert_eq!(sb.sb_writers(), 0, "writer count balanced after re-admitted write");
    vfs::superblock::clear_freeze_wait_hooks();
}

#[test]
fn freeze_waits_for_inflight_writer_before_freeze_fs() {
    let _serial = guard();
    install_wait_hooks();
    let (sb, ops) = sb_counting();
    let data = Arc::new(BlockingData {
        entered: Mutex::new(false),
        release: Mutex::new(false),
        cv:      Condvar::new(),
    });
    let ino = blocking_inode(&sb, data.clone());
    let f = rw_file(&ino);

    let writer = thread::spawn(move || {
        assert_eq!(f.write(b"hold"), Ok(4), "writer completes after release");
    });
    {
        let mut entered = data.entered.lock().unwrap_or_else(|e| e.into_inner());
        while !*entered {
            entered = data.cv.wait(entered).unwrap_or_else(|e| e.into_inner());
        }
    }
    assert_eq!(sb.sb_writers(), 1, "writer is counted in-flight");

    let freeze_done = Arc::new(AtomicBool::new(false));
    let t_done = freeze_done.clone();
    let t_sb = sb.clone();
    let freezer = thread::spawn(move || {
        assert_eq!(t_sb.freeze_super(), Ok(()), "freeze succeeds after writer drain");
        t_done.store(true, Ordering::Release);
    });
    thread::sleep(Duration::from_millis(20));
    assert!(!freeze_done.load(Ordering::Acquire), "freeze waits for in-flight writer");
    assert_eq!(ops.freezes.load(Ordering::Acquire), 0, "freeze_fs not called before writer drains");
    // Linux releases s_umount while draining the WRITE freeze level. A
    // reader must therefore enter here even though freeze_super is blocked on
    // the still-active writer; retaining s_umount would deadlock this control.
    sb.with_s_umount_read(|| ());

    {
        let mut release = data.release.lock().unwrap_or_else(|e| e.into_inner());
        *release = true;
        data.cv.notify_all();
    }
    writer.join().expect("writer joins");
    freezer.join().expect("freezer joins");
    assert_eq!(ops.freezes.load(Ordering::Acquire), 1, "freeze_fs called after drain");
    assert_eq!(sb.thaw_super(), Ok(()), "thaw after freeze");
    vfs::superblock::clear_freeze_wait_hooks();
}

#[test]
fn fifreeze_fithaw_roundtrip_semantics() {
    let _serial = guard();
    let sb = sb();

    // FIFREEZE on an already-frozen sb → EBUSY.
    assert_eq!(sb.freeze_super(), Ok(()), "first freeze ok");
    assert_eq!(sb.freeze_super(), Err(VfsError::Ebusy), "second freeze EBUSY");

    // FITHAW resumes; a second FITHAW on an unfrozen sb → EINVAL.
    assert_eq!(sb.thaw_super(), Ok(()), "first thaw ok");
    assert_eq!(sb.thaw_super(), Err(VfsError::Einval), "thaw of unfrozen sb EINVAL");

    // Round-trip again to confirm the gate fully reset.
    assert_eq!(sb.freeze_super(), Ok(()), "re-freeze after thaw ok");
    assert!(sb.is_frozen());
    assert_eq!(sb.thaw_super(), Ok(()), "re-thaw ok");
    assert!(!sb.is_frozen());
}
