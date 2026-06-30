//! Lease-break + dnotify event DELIVERY primitives (file-D21 / syscalls-D36).
//! The storage/validation (`set_lease`/`set_dnotify`) already existed; these
//! drive the new delivery layer the open path + dir-mutation hooks call:
//!   * `lease_conflict` / `lease_break_signal` / `lease_force_break` — a
//!     conflicting open finds the holder, signals it via the fown→SIGIO hook,
//!     and force-breaks on timeout (the syscall layer owns the wait/yield).
//!   * `dnotify_emit` — a dir mutation signals the watching fd, one-shot unless
//!     DN_MULTISHOT.
//!   * `F_GET/SET_RW_HINT` round-trip on the `File`.

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::{Cred, Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags,
          default_file_ops, default_inode_ops, mk_mode};

const SIGIO: i32 = 29;
const F_RDLCK: i32 = 0;
const F_WRLCK: i32 = 1;
const F_UNLCK: i32 = 2;

/// The lease / dnotify registries and the SIGIO hook are process-global; serialize.
static GATE: Mutex<()> = Mutex::new(());

static GOT_OWNER: AtomicI32 = AtomicI32::new(0);
static GOT_SIG: AtomicI32 = AtomicI32::new(0);
static GOT_FIRES: AtomicU32 = AtomicU32::new(0);

fn capture_hook(owner: i32, sig: i32, _uid: u32, _euid: u32) {
    GOT_OWNER.store(owner, Ordering::Release);
    GOT_SIG.store(sig, Ordering::Release);
    GOT_FIRES.fetch_add(1, Ordering::Release);
}

fn reg_inode() -> InodeRef {
    InodeBuilder::new(7, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}
fn dir_inode() -> InodeRef {
    InodeBuilder::new(8, mk_mode(FileType::Directory, 0o755), default_inode_ops(), default_file_ops()).build()
}
fn file_on(ino: &InodeRef) -> Arc<File> {
    let dentry = Dentry::new(None, "f".into(), Arc::clone(ino));
    File::new(Arc::clone(ino), dentry, OpenFlags::O_RDONLY)
}

#[test]
fn conflicting_open_breaks_lease_and_signals_holder() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let ino = reg_inode();
    let holder = file_on(&ino);
    // Holder takes a write lease and is registered (what F_SETLEASE does).
    holder.set_lease(F_WRLCK);
    holder.f_setown(4321, &Cred::root());
    vfs::file::lease_register(&holder);
    assert_eq!(vfs::file::lease_registered(), 1, "one registered lease holder");

    // A write lease conflicts with ANY open (read or write).
    assert!(vfs::file::lease_conflict(&ino, false), "write lease vs read open conflicts");
    assert!(vfs::file::lease_conflict(&ino, true),  "write lease vs write open conflicts");

    // The conflicting open signals the holder (default SIGIO to its f_owner).
    GOT_FIRES.store(0, Ordering::Release);
    vfs::file::lease_break_signal(&ino, true);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "holder signalled once");
    assert_eq!(GOT_OWNER.load(Ordering::Acquire), 4321, "signal routed to f_owner");
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGIO, "default SIGIO (no F_SETSIG)");

    // Holder never downgrades → the break-timeout force-breaks the lease.
    vfs::file::lease_force_break(&ino, true);
    assert_eq!(holder.lease(), F_UNLCK, "force-break drops the lease to F_UNLCK");
    assert!(!vfs::file::lease_conflict(&ino, true), "no conflict after break → open proceeds");
    assert_eq!(vfs::file::lease_registered(), 0, "holder unregistered after break");
}

#[test]
fn read_lease_only_breaks_on_write_open() {
    let _g = GATE.lock().unwrap();
    let ino = reg_inode();
    let holder = file_on(&ino);
    holder.set_lease(F_RDLCK);
    holder.f_setown(10, &Cred::root());
    vfs::file::lease_register(&holder);
    // A read open does NOT break a read lease; a write open does.
    assert!(!vfs::file::lease_conflict(&ino, false), "read lease + read open: no conflict");
    assert!(vfs::file::lease_conflict(&ino, true),   "read lease + write open: conflict");
    holder.set_lease(F_UNLCK);
    vfs::file::lease_unregister(&holder);
    assert_eq!(vfs::file::lease_registered(), 0);
}

#[test]
fn no_lease_open_is_zero_cost_false() {
    let _g = GATE.lock().unwrap();
    let ino = reg_inode();
    // The common boot path: no lease anywhere → fast-path false, no scan.
    assert_eq!(vfs::file::lease_registered(), 0, "no leases registered");
    assert!(!vfs::file::lease_conflict(&ino, true), "no lease → never conflicts");
}

#[test]
fn dir_mutation_fires_dnotify_oneshot() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let dir = dir_inode();
    let watch = file_on(&dir);
    watch.set_dnotify(vfs::file::DN_CREATE);
    watch.f_setown(777, &Cred::root());
    vfs::file::dnotify_register(&watch);
    assert_eq!(vfs::file::dnotify_registered(), 1, "one armed watch");

    // A create in the watched dir signals the watcher.
    GOT_FIRES.store(0, Ordering::Release);
    vfs::file::dnotify_emit(&dir, vfs::file::DN_CREATE);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "create fires the watch");
    assert_eq!(GOT_OWNER.load(Ordering::Acquire), 777, "routed to the watcher's owner");

    // dnotify is one-shot without DN_MULTISHOT: cleared + unregistered after firing.
    assert_eq!(watch.dnotify(), 0, "one-shot watch cleared after firing");
    assert_eq!(vfs::file::dnotify_registered(), 0, "watch unregistered");
    GOT_FIRES.store(0, Ordering::Release);
    vfs::file::dnotify_emit(&dir, vfs::file::DN_CREATE);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0, "no second delivery after one-shot");
}

#[test]
fn dnotify_mask_filters_events_and_multishot_persists() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let dir = dir_inode();
    let watch = file_on(&dir);
    const DN_MULTISHOT: u32 = 0x8000_0000;
    watch.set_dnotify(vfs::file::DN_DELETE | DN_MULTISHOT);
    watch.f_setown(55, &Cred::root());
    vfs::file::dnotify_register(&watch);

    // A non-matching event (DN_CREATE) does not fire a DN_DELETE-only watch.
    GOT_FIRES.store(0, Ordering::Release);
    vfs::file::dnotify_emit(&dir, vfs::file::DN_CREATE);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0, "mask filters non-matching events");

    // DN_MULTISHOT keeps firing across repeated matching mutations.
    vfs::file::dnotify_emit(&dir, vfs::file::DN_DELETE);
    vfs::file::dnotify_emit(&dir, vfs::file::DN_DELETE);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 2, "multishot fires every time");
    assert_eq!(vfs::file::dnotify_registered(), 1, "multishot watch persists");
    watch.set_dnotify(0);
    vfs::file::dnotify_unregister(&watch);
}

#[test]
fn rw_hint_round_trip() {
    let ino = reg_inode();
    let f = file_on(&ino);
    assert_eq!(f.rw_hint(), 0, "default RWH_WRITE_LIFE_NOT_SET");
    f.set_rw_hint(3); // RWH_WRITE_LIFE_MEDIUM
    assert_eq!(f.rw_hint(), 3, "F_SET_RW_HINT stored, F_GET_RW_HINT reads back");
    f.set_rw_hint(0);
    assert_eq!(f.rw_hint(), 0, "reset to NOT_SET");
}
