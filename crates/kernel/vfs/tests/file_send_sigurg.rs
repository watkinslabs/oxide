//! `send_sigurg(file)` — the unconditional `SIGURG` an out-of-band arrival
//! posts to the receiving description's `f_owner`.
//!
//! This is the notification a socket's urgent path owes its owner, and it is
//! INDEPENDENT of the fasync/`O_ASYNC` path: the canonical
//! `fcntl(F_SETOWN, getpid())` + `send(MSG_OOB)` flow enables no signal-driven
//! I/O at all, and the fasync path deliberately suppresses a plain `SIGURG`,
//! so before this existed that flow delivered nothing whatsoever.

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::{Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags, PollSubscribers,
          default_file_ops, default_inode_ops, mk_mode};

/// A realtime signal a process might select via `F_SETSIG`.
const SIGRTMIN: i32 = 34;
/// `O_ASYNC`/`FASYNC` raw bit (asm-generic).
const O_ASYNC: u32 = 0o20000;

use vfs::file::{owner_type, SIGIO, SIGURG};
use vfs::file::reason::{POLL_IN, POLL_PRI};

/// The SIGIO delivery hook is a process-global static. Serialize the tests
/// that install it so parallel `cargo test` threads don't see each other's.
static GATE: Mutex<()> = Mutex::new(());

static GOT_OWNER: AtomicI32 = AtomicI32::new(0);
static GOT_TYPE: AtomicI32 = AtomicI32::new(0);
static GOT_SIG: AtomicI32 = AtomicI32::new(0);
static GOT_UID: AtomicU32 = AtomicU32::new(0);
static GOT_EUID: AtomicU32 = AtomicU32::new(0);
static GOT_FIRES: AtomicU32 = AtomicU32::new(0);
static GOT_CODE: AtomicI32 = AtomicI32::new(0);
static GOT_BAND: AtomicI64 = AtomicI64::new(0);
static GOT_FD: AtomicI32 = AtomicI32::new(0);
static GOT_QUEUED: AtomicU32 = AtomicU32::new(0);

fn capture_hook(ev: vfs::file::AsyncSignal) {
    GOT_OWNER.store(ev.owner, Ordering::Release);
    GOT_TYPE.store(ev.ty, Ordering::Release);
    GOT_SIG.store(ev.sig, Ordering::Release);
    GOT_UID.store(ev.uid, Ordering::Release);
    GOT_EUID.store(ev.euid, Ordering::Release);
    GOT_CODE.store(ev.code, Ordering::Release);
    GOT_BAND.store(ev.band, Ordering::Release);
    GOT_FD.store(ev.fd, Ordering::Release);
    GOT_QUEUED.store(ev.queued as u32, Ordering::Release);
    GOT_FIRES.fetch_add(1, Ordering::Release);
}

fn mk_anon() -> InodeRef {
    InodeBuilder::new(7, mk_mode(FileType::Regular, 0o644), default_inode_ops(), default_file_ops())
        .poll_subs(PollSubscribers::new()).build()
}

fn file() -> Arc<File> {
    let ino: InodeRef = mk_anon();
    let dentry = Dentry::new(None, "f".into(), Arc::clone(&ino));
    File::new(ino, dentry, OpenFlags::O_RDONLY)
}

#[test]
fn no_owner_signals_nobody_and_reports_no_owner() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    GOT_FIRES.store(0, Ordering::Release);
    assert!(!f.send_sigurg(), "no F_SETOWN ⇒ nothing to signal");
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0);
}

// The headline: neither O_ASYNC nor a fasync registration is a precondition.
#[test]
fn setown_alone_receives_sigurg() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, owner_type::F_OWNER_PID, 1000, 1001);
    assert!(!f.is_async(), "no O_ASYNC — the flow under test never sets it");
    assert_eq!(vfs::file::fasync_registered(f.inode()), 0, "and no fasync registration");
    GOT_FIRES.store(0, Ordering::Release);
    assert!(f.send_sigurg(), "an owner is recorded");
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "urgent arrival signalled the owner");
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGURG);
    assert_eq!(GOT_OWNER.load(Ordering::Acquire), 1234);
    assert_eq!(GOT_TYPE.load(Ordering::Acquire), owner_type::F_OWNER_PID);
    assert_eq!(GOT_UID.load(Ordering::Acquire), 1000, "the F_SETOWN-time creds decide sigio_perm");
    assert_eq!(GOT_EUID.load(Ordering::Acquire), 1001);
}

// A plain signal with `SEND_SIG_PRIV`, so no `_sigpoll` record: si_code,
// si_band and si_fd are not part of this notification.
#[test]
fn the_owner_signal_carries_no_sigpoll_record() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(9, owner_type::F_OWNER_TID, 0, 0);
    f.send_sigurg();
    assert_eq!(GOT_QUEUED.load(Ordering::Acquire), 0, "plain signal, not a queued record");
    assert_eq!(GOT_CODE.load(Ordering::Acquire), 0);
    assert_eq!(GOT_BAND.load(Ordering::Acquire), 0);
    assert_eq!(GOT_FD.load(Ordering::Acquire), -1, "no descriptor is named");
}

// `F_SETSIG` redirects the FASYNC notification, not this one. Redirecting both
// would leave the plain-SIGURG receiver — the common case — with no signal.
#[test]
fn setsig_does_not_redirect_the_owner_signal() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, owner_type::F_OWNER_PID, 0, 0);
    f.set_sig(SIGRTMIN);
    f.send_sigurg();
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGURG, "still SIGURG, not the F_SETSIG signal");
    assert_eq!(GOT_QUEUED.load(Ordering::Acquire), 0);
}

// A process group owner delivers to the group, and `F_GETOWN`'s legacy
// negative encoding is not what reaches the hook.
#[test]
fn a_process_group_owner_is_forwarded_as_a_group() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(77, owner_type::F_OWNER_PGRP, 0, 0);
    assert_eq!(f.f_getown(), -77, "the legacy encoding is a getter concern only");
    f.send_sigurg();
    assert_eq!(GOT_OWNER.load(Ordering::Acquire), 77, "the stored id stays positive");
    assert_eq!(GOT_TYPE.load(Ordering::Acquire), owner_type::F_OWNER_PGRP);
}

// The two notifications are independent and neither subsumes the other: the
// fasync half still suppresses a plain SIGURG, and still delivers the F_SETSIG
// signal — with its `_sigpoll` record — on top of the owner signal.
#[test]
fn the_fasync_half_keeps_its_own_suppression_rule() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, owner_type::F_OWNER_PID, 0, 0);
    let _ = f.set_fl(OpenFlags::from_bits_retain(O_ASYNC));
    GOT_FIRES.store(0, Ordering::Release);
    f.kill_fasync(SIGURG, POLL_PRI);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0, "no F_SETSIG ⇒ the fasync half is silent");
    assert!(f.send_sigurg(), "the owner signal fires regardless");
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1);
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGURG);
    // With F_SETSIG the fasync half speaks too, and carries the record.
    f.set_sig(SIGRTMIN);
    f.set_fasync_state(6, true);
    f.kill_fasync(SIGURG, POLL_PRI);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 2);
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGRTMIN);
    assert_eq!(GOT_QUEUED.load(Ordering::Acquire), 1);
    assert_eq!(GOT_BAND.load(Ordering::Acquire), vfs::file::band_for(POLL_PRI));
    f.set_fasync_state(6, false);
}

// Priority readiness classifies to SIGURG, ordinary readiness to SIGIO — the
// two default signals now have one owner each rather than a copy per site.
#[test]
fn the_default_async_signals_have_one_definition() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, owner_type::F_OWNER_PID, 0, 0);
    f.set_sig(SIGRTMIN);
    f.set_fasync_state(2, true);
    GOT_FIRES.store(0, Ordering::Release);
    let subs = f.inode().poll_subscribers().expect("poll source");
    subs.notify_mask(vfs::POLL_IN);
    assert_eq!(GOT_CODE.load(Ordering::Acquire), POLL_IN, "data readiness is the SIGIO reason");
    subs.notify_mask(vfs::POLL_IN | vfs::POLL_PRI);
    assert_eq!(GOT_CODE.load(Ordering::Acquire), POLL_PRI, "urgent outranks data");
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 2);
    assert_eq!(SIGIO, 29);
    assert_eq!(SIGURG, 23);
    f.set_fasync_state(2, false);
}
