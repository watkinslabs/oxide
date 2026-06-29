//! `f_owner` / `fown_struct` + `F_SETSIG`/`F_GETSIG` model on `File`
//! (file-D13). Pre-fix `File` carried only a bare `owner: AtomicI32` — no
//! captured owner credentials and no per-fd async-I/O signal, so SIGIO could
//! not be `kill_pid_info`-permission-checked against the requesting creds and
//! `F_SETSIG` had nowhere to land. These tests drive the real `File` accessors
//! and assert the Linux `f_setown`/`f_getown`/`f_setsig`/`send_sigio` shape.

use std::sync::atomic::{AtomicI32, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::{Cred, Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags,
          default_file_ops, default_inode_ops, mk_mode};

/// Default `SIGIO` number (asm-generic, both arches) — the signal `fasync`
/// delivers when `F_SETSIG` was never called.
const SIGIO: i32 = 29;
/// A realtime signal a process might select via `F_SETSIG`.
const SIGRTMIN: i32 = 34;
/// `O_ASYNC`/`FASYNC` raw bit (asm-generic). `set_fl` stores it; toggling it
/// (de)registers the fd for fasync.
const O_ASYNC: u32 = 0o20000;

/// The fasync registry and the SIGIO delivery hook are process-global statics.
/// Serialize the tests that touch them so parallel `cargo test` threads don't
/// see each other's registrations / installed hook.
static GATE: Mutex<()> = Mutex::new(());

// Captured args from the last `set_sigio_hook` delivery, for assertions.
static GOT_OWNER: AtomicI32 = AtomicI32::new(0);
static GOT_SIG: AtomicI32 = AtomicI32::new(0);
static GOT_UID: AtomicU32 = AtomicU32::new(0);
static GOT_FIRES: AtomicU32 = AtomicU32::new(0);

fn capture_hook(owner: i32, sig: i32, uid: u32, _euid: u32) {
    GOT_OWNER.store(owner, Ordering::Release);
    GOT_SIG.store(sig, Ordering::Release);
    GOT_UID.store(uid, Ordering::Release);
    GOT_FIRES.fetch_add(1, Ordering::Release);
}

fn mk_anon() -> InodeRef {
    InodeBuilder::new(7, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops()).build()
}

fn file() -> Arc<File> {
    let ino: InodeRef = mk_anon();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

/// A non-root cred used to prove the owner credentials are snapshotted.
fn user(uid: u32) -> Cred {
    let mut c = Cred::root();
    c.uid = uid;
    c
}

#[test]
fn fresh_file_has_no_owner_no_sig() {
    let f = file();
    assert_eq!(f.f_getown(), 0, "no F_SETOWN yet → target 0");
    assert_eq!(f.sig(), 0, "no F_SETSIG yet → 0 (default SIGIO)");
    assert_eq!(f.f_owner_creds(), (0, 0), "no owner creds captured yet");
}

#[test]
fn setown_records_target_and_creds() {
    let f = file();
    f.f_setown(4321, &user(1000));
    assert_eq!(f.f_getown(), 4321, "F_GETOWN returns the F_SETOWN target");
    assert_eq!(f.f_owner_creds(), (1000, 1000), "uid/euid snapshot from the setter's cred");
    // Negative target = process group, faithfully round-tripped.
    f.f_setown(-77, &user(1000));
    assert_eq!(f.f_getown(), -77, "negative target (-pgrp) preserved");
}

#[test]
fn setown_target_is_owner_field_used_by_syscall() {
    // The legacy `owner` field the fcntl shim writes/reads must stay in sync
    // with the model setter (single pid source of truth).
    let f = file();
    f.f_setown(99, &Cred::root());
    assert_eq!(f.owner.load(std::sync::atomic::Ordering::Acquire), 99);
}

#[test]
fn setsig_overrides_default_else_sigio() {
    let f = file();
    // Default: fasync delivers SIGIO when no F_SETSIG.
    assert_eq!(f.fasync_signal(SIGIO), SIGIO, "unset signum → default SIGIO");
    f.set_sig(SIGRTMIN);
    assert_eq!(f.sig(), SIGRTMIN, "F_GETSIG returns the F_SETSIG value");
    assert_eq!(f.fasync_signal(SIGIO), SIGRTMIN, "set signum overrides the default");
    // Reset to 0 restores the default (Linux F_SETSIG 0).
    f.set_sig(0);
    assert_eq!(f.fasync_signal(SIGIO), SIGIO, "F_SETSIG 0 restores default SIGIO");
}

#[test]
fn fasync_register_unregister_tracks_o_async_fds() {
    let _g = GATE.lock().unwrap();
    let f = file();
    let before = vfs::file::fasync_registered();
    vfs::file::fasync_register(&f);
    assert_eq!(vfs::file::fasync_registered(), before + 1, "register adds one live fd");
    // Idempotent: re-registering the same description does not double-count.
    vfs::file::fasync_register(&f);
    assert_eq!(vfs::file::fasync_registered(), before + 1, "register is idempotent");
    vfs::file::fasync_unregister(&f);
    assert_eq!(vfs::file::fasync_registered(), before, "unregister removes it");
}

#[test]
fn dropping_a_registered_file_self_prunes() {
    let _g = GATE.lock().unwrap();
    let before = vfs::file::fasync_registered();
    {
        let f = file();
        vfs::file::fasync_register(&f);
        assert_eq!(vfs::file::fasync_registered(), before + 1);
    } // f dropped: its Weak expires, pruned on next touch.
    assert_eq!(vfs::file::fasync_registered(), before, "dead weak pruned after drop");
}

#[test]
fn kill_fasync_delivers_to_owner_via_hook() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, &user(1000));
    // No O_ASYNC yet: kill_fasync is a no-op (Linux only signals FASYNC fds).
    GOT_FIRES.store(0, Ordering::Release);
    f.kill_fasync(SIGIO);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0, "no O_ASYNC → no delivery");
    // Enable O_ASYNC, then deliver: hook fires with owner + default SIGIO + creds.
    f.set_fl(OpenFlags::from_bits_retain(O_ASYNC));
    assert!(f.is_async(), "O_ASYNC stored via set_fl");
    f.kill_fasync(SIGIO);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "delivered once");
    assert_eq!(GOT_OWNER.load(Ordering::Acquire), 1234, "owner forwarded");
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGIO, "default SIGIO when no F_SETSIG");
    assert_eq!(GOT_UID.load(Ordering::Acquire), 1000, "owner cred snapshot forwarded");
    // F_SETSIG overrides the delivered signal.
    f.set_sig(SIGRTMIN);
    f.kill_fasync(SIGIO);
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGRTMIN, "F_SETSIG overrides default");
    // The inode-keyed fan reaches a registered fd on that inode.
    vfs::file::fasync_register(&f);
    GOT_FIRES.store(0, Ordering::Release);
    vfs::file::kill_fasync(f.inode(), SIGIO);
    assert!(GOT_FIRES.load(Ordering::Acquire) >= 1, "inode fan reaches the registered fd");
    vfs::file::fasync_unregister(&f);
}

#[test]
fn lease_and_dnotify_round_trip() {
    let f = file();
    assert_eq!(f.lease(), 2, "default lease = F_UNLCK(2)");
    f.set_lease(1);
    assert_eq!(f.lease(), 1, "F_WRLCK lease stored");
    f.set_lease(2);
    assert_eq!(f.lease(), 2, "F_UNLCK drops the lease");
    assert_eq!(f.dnotify(), 0, "no dnotify watch by default");
    f.set_dnotify(0x2);
    assert_eq!(f.dnotify(), 0x2, "DN_MODIFY watch stored");
}
