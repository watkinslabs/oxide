//! `inode->i_rwsem` (D29) + `O_APPEND` cross-writer atomicity (D37).
//!
//! Covers the three SAFETY contracts the locking change must hold:
//!   1. `lock_rename` orders the two parent `i_rwsem`s DETERMINISTICALLY (by
//!      address), so two concurrent renames naming the pair in opposite arg
//!      order acquire in the SAME order — no ABBA hang — and a same-directory
//!      rename locks the single `i_rwsem` exactly ONCE (re-locking the
//!      non-reentrant spin-rwsem would self-deadlock).
//!   2. `O_APPEND` writes from two DIFFERENT open file descriptions on one
//!      inode are mutually atomic under the exclusive `i_rwsem` (per-description
//!      `f_pos_lock` alone cannot serialize across descriptions).
//!   3. Nested directory locking: shared readers are concurrent, an exclusive
//!      holder excludes a shared reader, and the rank order (`i_rwsem` 40 below
//!      the dcache) never inverts.
//!
//! Each potentially-blocking acquisition runs on a worker thread joined through
//! an mpsc `recv_timeout` watchdog, so a regression that DEADLOCKS fails the
//! test (assert) instead of hanging CI.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use vfs::inode::Inode;
use vfs::{default_file_ops, default_inode_ops, lock_rename, mk_mode, Dentry, File,
          FileType, InodeBuilder, InodeRef, KResult, OpenFlags};

const WATCHDOG: Duration = Duration::from_secs(10);

fn dir(ino: u64) -> InodeRef {
    InodeBuilder::new(ino, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops()).build()
}

/// Run `f` on a worker thread; FAIL (not hang) if it does not finish within the
/// watchdog window — the deadlock detector for every blocking lock test.
fn within_watchdog<F: FnOnce() + Send + 'static>(what: &str, f: F) {
    let (tx, rx) = mpsc::channel();
    let h = thread::spawn(move || { f(); let _ = tx.send(()); });
    assert!(rx.recv_timeout(WATCHDOG).is_ok(), "{what}: deadlocked / timed out");
    h.join().unwrap();
}

// ---------------------------------------------------------------------------
// 1. lock_rename — deterministic ordering
// ---------------------------------------------------------------------------

/// Same-directory rename: both parents are the SAME inode, so `lock_rename`
/// must lock its single `i_rwsem` ONCE. A double-lock would self-deadlock the
/// non-reentrant spin-rwsem and the watchdog would fire.
#[test]
fn lock_rename_same_dir_locks_once() {
    let d = dir(1);
    within_watchdog("same-dir lock_rename", move || {
        let g = lock_rename(&d, &d);
        drop(g);
    });
}

/// Two concurrent renames naming the SAME pair of directories in OPPOSITE
/// argument order must not deadlock: address-order acquisition gives both the
/// same order. Loop many times to shake out any ABA window.
#[test]
fn lock_rename_opposite_order_no_deadlock() {
    let a = dir(10);
    let b = dir(11);
    within_watchdog("cross-order lock_rename", move || {
        let a2 = Arc::clone(&a);
        let b2 = Arc::clone(&b);
        let t1 = thread::spawn(move || {
            for _ in 0..5_000 { let g = lock_rename(&a, &b); drop(g); }
        });
        let t2 = thread::spawn(move || {
            for _ in 0..5_000 { let g = lock_rename(&b2, &a2); drop(g); }
        });
        t1.join().unwrap();
        t2.join().unwrap();
    });
}

/// `lock_rename` actually takes the exclusive locks (it is not a no-op): while
/// one thread holds `lock_rename(a,b)`, a second thread's `lock_rename(b,a)`
/// must BLOCK until the first releases — observed via an ordering flag.
#[test]
fn lock_rename_is_mutually_exclusive() {
    let a = dir(20);
    let b = dir(21);
    let released_first = Arc::new(AtomicBool::new(false));
    let second_saw_release = Arc::new(AtomicBool::new(false));

    let rf = Arc::clone(&released_first);
    let ss = Arc::clone(&second_saw_release);
    let a2 = Arc::clone(&a);
    let b2 = Arc::clone(&b);

    within_watchdog("mutual exclusion", move || {
        let g1 = lock_rename(&a, &b);
        let waiter = thread::spawn(move || {
            // Blocks here until g1 drops; the flag must already be set by then.
            let g2 = lock_rename(&b2, &a2);
            ss.store(rf.load(Ordering::Acquire), Ordering::Release);
            drop(g2);
        });
        thread::sleep(Duration::from_millis(50));
        released_first.store(true, Ordering::Release);
        drop(g1);
        waiter.join().unwrap();
    });
    assert!(second_saw_release.load(Ordering::Acquire),
            "second lock_rename acquired before the first released — not exclusive");
}

// ---------------------------------------------------------------------------
// 2. O_APPEND under i_rwsem — cross-description atomicity
// ---------------------------------------------------------------------------

/// Growable in-memory regular file. `write` SLEEPS briefly while applying, so
/// the size-read→write window in `File::write` is wide: without the exclusive
/// `i_rwsem`, two appenders would both read the same stale size and clobber.
struct MemData { data: Mutex<Vec<u8>> }
struct SlowAppendOps;
impl vfs::FileOps for SlowAppendOps {
    fn write(&self, inode: &Inode, off: u64, buf: &[u8]) -> KResult<usize> {
        // Widen the race window deterministically: a stale-size appender from a
        // second description would write at the same `off` during this sleep.
        thread::sleep(Duration::from_millis(20));
        let m = inode.private::<MemData>().unwrap();
        let mut d = m.data.lock().unwrap();
        let off = off as usize;
        if off + buf.len() > d.len() { d.resize(off + buf.len(), 0); }
        d[off..off + buf.len()].copy_from_slice(buf);
        inode.set_size(d.len() as u64);
        Ok(buf.len())
    }
}

fn mk_memfile(initial: &[u8]) -> InodeRef {
    InodeBuilder::new(0xA9, mk_mode(FileType::Regular, 0o644), default_inode_ops(), Arc::new(SlowAppendOps))
        .size(initial.len() as u64)
        .private(Arc::new(MemData { data: Mutex::new(initial.to_vec()) }))
        .build()
}

fn mem_bytes(ino: &InodeRef) -> Vec<u8> { ino.private::<MemData>().unwrap().data.lock().unwrap().clone() }

/// A SEPARATE `File` (open file description) per appender — so `f_pos_lock`
/// (which is per-description) provides NO mutual serialization; only the
/// inode's `i_rwsem` does. Each appends a distinct byte pattern; the result
/// must preserve every byte (no clobber) and total exactly initial + sum.
#[test]
fn append_distinct_descriptions_are_atomic() {
    const N: usize = 4;
    const L: usize = 8;
    let ino = mk_memfile(b"HEAD");

    let mut handles = Vec::new();
    for k in 0..N {
        let i: InodeRef = Arc::clone(&ino);
        let d = Dentry::new(None, "f".into(), Arc::clone(&i));
        // Distinct description each: NOT a shared Arc<File>.
        let f = File::new(i, d, OpenFlags::O_WRONLY | OpenFlags::O_APPEND);
        handles.push(thread::spawn(move || {
            f.write(&[b'a' + k as u8; L]).unwrap();
        }));
    }
    for h in handles { h.join().unwrap(); }

    let bytes = mem_bytes(&ino);
    assert_eq!(bytes.len(), 4 + N * L, "every append must extend; none overwrite another");
    assert_eq!(&bytes[..4], b"HEAD", "the file head must survive all appends");
    // Each per-thread pattern must appear in full exactly once (count of each
    // distinct byte == L), proving no two appends landed on the same offset.
    for k in 0..N {
        let c = b'a' + k as u8;
        let cnt = bytes.iter().filter(|&&x| x == c).count();
        assert_eq!(cnt, L, "appender {k}'s bytes were partially clobbered");
    }
}

// ---------------------------------------------------------------------------
// 3. Nested dir lock ordering / shared vs exclusive
// ---------------------------------------------------------------------------

/// Two `inode_lock_shared` holders on the SAME inode are concurrent (a reader
/// never excludes another reader). Both guards live simultaneously without a
/// deadlock.
#[test]
fn shared_readers_are_concurrent() {
    let d = dir(30);
    within_watchdog("concurrent shared readers", move || {
        let g1 = d.inode_lock_shared();
        let g2 = d.inode_lock_shared();
        let _ = (&*g1, &*g2);
        drop(g1);
        drop(g2);
    });
}

/// An exclusive `inode_lock` EXCLUDES a shared reader: while held, a second
/// thread's `inode_lock_shared` blocks until release.
#[test]
fn exclusive_excludes_shared() {
    let d = dir(31);
    let released = Arc::new(AtomicBool::new(false));
    let saw = Arc::new(AtomicBool::new(false));
    let rel = Arc::clone(&released);
    let saw2 = Arc::clone(&saw);
    let d2 = Arc::clone(&d);

    within_watchdog("exclusive vs shared", move || {
        let w = d.inode_lock();
        let reader = thread::spawn(move || {
            let r = d2.inode_lock_shared(); // blocks until the writer drops
            saw2.store(rel.load(Ordering::Acquire), Ordering::Release);
            drop(r);
        });
        thread::sleep(Duration::from_millis(50));
        released.store(true, Ordering::Release);
        drop(w);
        reader.join().unwrap();
    });
    assert!(saw.load(Ordering::Acquire),
            "shared reader acquired while exclusive held — rank/exclusion broken");
}

/// Nested ordering smoke: hold `lock_rename(a,b)` (two rank-40 `i_rwsem`s) while
/// a THIRD directory's shared lock is taken and released on another thread — no
/// deadlock, mirroring a lookup proceeding on an unrelated dir during a rename.
#[test]
fn rename_lock_with_unrelated_shared_lookup() {
    static INO: AtomicU64 = AtomicU64::new(40);
    let a = dir(INO.fetch_add(1, Ordering::Relaxed));
    let b = dir(INO.fetch_add(1, Ordering::Relaxed));
    let c = dir(INO.fetch_add(1, Ordering::Relaxed));
    within_watchdog("rename + unrelated lookup", move || {
        let g = lock_rename(&a, &b);
        let t = thread::spawn(move || {
            for _ in 0..1_000 { let r = c.inode_lock_shared(); drop(r); }
        });
        t.join().unwrap();
        drop(g);
    });
}
