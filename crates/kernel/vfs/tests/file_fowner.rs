//! `f_owner` / `fown_struct` + `F_SETSIG`/`F_GETSIG` model on `File`
//! (file-D13). Pre-fix `File` carried only a bare `owner: AtomicI32` — no
//! captured owner credentials and no per-fd async-I/O signal, so SIGIO could
//! not be `kill_pid_info`-permission-checked against the requesting creds and
//! `F_SETSIG` had nowhere to land. These tests drive the real `File` accessors
//! and assert the Linux `f_setown`/`f_getown`/`f_setsig`/`send_sigio` shape.

use std::sync::atomic::{AtomicI32, AtomicI64, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};

use vfs::{Dentry, File, FileType, InodeBuilder, InodeRef, OpenFlags, PollSubscribers,
          default_file_ops, default_inode_ops, mk_mode};

/// Default `SIGIO` number (asm-generic, both arches) — the signal `fasync`
/// delivers when `F_SETSIG` was never called.
const SIGIO: i32 = 29;
/// A realtime signal a process might select via `F_SETSIG`.
const SIGRTMIN: i32 = 34;
/// `O_ASYNC`/`FASYNC` raw bit (asm-generic). `set_fl` stores it; toggling it
/// (de)registers the fd for fasync.
const O_ASYNC: u32 = 0o20000;
/// `SIGURG` — the default signal for out-of-band readiness.
const SIGURG: i32 = 23;

use vfs::file::reason::{POLL_ERR, POLL_HUP, POLL_IN, POLL_MSG, POLL_OUT, POLL_PRI};

/// The SIGIO delivery hook is a process-global static. Serialize the tests that
/// install it so parallel `cargo test` threads don't see each other's hook.
static GATE: Mutex<()> = Mutex::new(());

// Captured args from the last `set_sigio_hook` delivery, for assertions.
static GOT_OWNER: AtomicI32 = AtomicI32::new(0);
static GOT_SIG: AtomicI32 = AtomicI32::new(0);
static GOT_UID: AtomicU32 = AtomicU32::new(0);
static GOT_FIRES: AtomicU32 = AtomicU32::new(0);
static GOT_CODE: AtomicI32 = AtomicI32::new(0);
static GOT_BAND: AtomicI64 = AtomicI64::new(0);
static GOT_FD: AtomicI32 = AtomicI32::new(0);
static GOT_QUEUED: AtomicU32 = AtomicU32::new(0);

fn capture_hook(ev: vfs::file::AsyncSignal) {
    GOT_OWNER.store(ev.owner, Ordering::Release);
    GOT_SIG.store(ev.sig, Ordering::Release);
    GOT_UID.store(ev.uid, Ordering::Release);
    GOT_CODE.store(ev.code, Ordering::Release);
    GOT_BAND.store(ev.band, Ordering::Release);
    GOT_FD.store(ev.fd, Ordering::Release);
    GOT_QUEUED.store(ev.queued as u32, Ordering::Release);
    GOT_FIRES.fetch_add(1, Ordering::Release);
}

/// A source with a poll queue — the only kind Linux gives an `f_op->fasync`,
/// and therefore the only kind that can carry a fasync registration.
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
fn fresh_file_has_no_owner_no_sig() {
    let f = file();
    assert_eq!(f.f_getown(), 0, "no F_SETOWN yet → target 0");
    assert_eq!(f.sig(), 0, "no F_SETSIG yet → 0 (default SIGIO)");
    assert_eq!(f.f_owner_creds(), (0, 0), "no owner creds captured yet");
}

#[test]
fn setown_records_target_and_creds() {
    let f = file();
    f.f_setown(4321, vfs::file::owner_type::F_OWNER_PID, 1000, 1001);
    assert_eq!(f.f_getown(), 4321, "F_GETOWN returns the F_SETOWN target");
    assert_eq!(f.f_owner_creds(), (1000, 1001),
        "real and effective uid are snapshotted SEPARATELY — sigio_perm reads them differently");
    // Negative target = process group, faithfully round-tripped.
    f.f_setown(-77, vfs::file::owner_type::F_OWNER_PID, 1000, 1001);
    assert_eq!(f.f_getown(), -77, "negative target (-pgrp) preserved");
}

// `F_SETOWN_EX` records a `pid_type`; `F_GETOWN_EX` must report the SAME one.
// Inferring the type from the id's sign — which is what this did — collapses
// F_OWNER_TID and F_OWNER_PID into one value, so a thread-directed owner came
// back as process-directed and the signal went to the wrong pending set.
#[test]
fn owner_type_round_trips_and_tid_is_distinct_from_pid() {
    use vfs::file::owner_type::{F_OWNER_PGRP, F_OWNER_PID, F_OWNER_TID};
    let f = file();
    assert_eq!(f.f_owner_type(), F_OWNER_PID, "default pid_type is PIDTYPE_TGID");
    f.f_setown(42, F_OWNER_TID, 0, 0);
    assert_eq!(f.f_owner_type(), F_OWNER_TID, "TID is not folded into PID");
    assert_eq!(f.f_getown(), 42, "a thread owner is reported positive");
    f.f_setown(42, F_OWNER_PID, 0, 0);
    assert_eq!(f.f_owner_type(), F_OWNER_PID);
    // Legacy `F_GETOWN` reports a process group as a NEGATIVE pgid; the stored
    // id itself stays positive so delivery does not have to un-negate it.
    f.f_setown(77, F_OWNER_PGRP, 0, 0);
    assert_eq!(f.f_owner_type(), F_OWNER_PGRP);
    assert_eq!(f.f_getown(), -77, "F_GETOWN's legacy negative-pgid encoding");
}

// `FMODE_CREATED` was defined and asserted in a bit-layout test, but no path
// ever SET it and no path ever read it — `fcntl(F_CREATED_QUERY)` is its
// consumer and did not exist.
#[test]
fn fmode_created_is_off_until_the_open_path_publishes_it() {
    use vfs::Fmode;
    let f = file();
    assert!(!f.f_mode().contains(Fmode::CREATED), "a plain open did not create the file");
    f.set_created();
    assert!(f.f_mode().contains(Fmode::CREATED), "F_CREATED_QUERY reads this back");
    assert!(f.f_mode().contains(Fmode::READ), "folding CREATED in preserves the access bits");
}

#[test]
fn setown_target_is_owner_field_used_by_syscall() {
    // The legacy `owner` field the fcntl shim writes/reads must stay in sync
    // with the model setter (single pid source of truth).
    let f = file();
    f.f_setown(99, vfs::file::owner_type::F_OWNER_PID, 0, 0);
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
    let ino = f.inode().clone();
    let before = vfs::file::fasync_registered(&ino);
    assert!(vfs::file::fasync_register(&f), "a source with a poll queue accepts fasync");
    assert_eq!(vfs::file::fasync_registered(&ino), before + 1, "register adds one live fd");
    // Idempotent: re-registering the same description does not double-count.
    vfs::file::fasync_register(&f);
    assert_eq!(vfs::file::fasync_registered(&ino), before + 1, "register is idempotent");
    vfs::file::fasync_unregister(&f);
    assert_eq!(vfs::file::fasync_registered(&ino), before, "unregister removes it");
}

// The list hangs off the SOURCE, so a registration on one inode is invisible to
// another — the global registry this replaced had to filter every event by
// inode, which is a second copy of the same relation.
#[test]
fn fasync_registration_is_per_source() {
    let a = file();
    let b = file();
    vfs::file::fasync_register(&a);
    assert_eq!(vfs::file::fasync_registered(a.inode()), 1);
    assert_eq!(vfs::file::fasync_registered(b.inode()), 0, "other source unaffected");
    vfs::file::fasync_unregister(&a);
}

#[test]
fn dropping_a_registered_file_self_prunes() {
    let _g = GATE.lock().unwrap();
    let ino = mk_anon();
    let mk = || {
        let d = Dentry::new(None, "f".into(), Arc::clone(&ino));
        File::new(Arc::clone(&ino), d, OpenFlags::O_RDONLY)
    };
    let before = vfs::file::fasync_registered(&ino);
    {
        let f = mk();
        vfs::file::fasync_register(&f);
        assert_eq!(vfs::file::fasync_registered(&ino), before + 1);
    } // f dropped: its Weak expires, pruned on next touch.
    assert_eq!(vfs::file::fasync_registered(&ino), before, "dead weak pruned after drop");
}

#[test]
fn kill_fasync_delivers_to_owner_via_hook() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, vfs::file::owner_type::F_OWNER_PID, 1000, 1000);
    // No O_ASYNC yet: kill_fasync is a no-op (Linux only signals FASYNC fds).
    GOT_FIRES.store(0, Ordering::Release);
    f.kill_fasync(SIGIO, POLL_IN);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0, "no O_ASYNC → no delivery");
    // Enable O_ASYNC, then deliver: hook fires with owner + default SIGIO + creds.
    let _ = f.set_fl(OpenFlags::from_bits_retain(O_ASYNC));
    assert!(f.is_async(), "O_ASYNC stored via set_fl");
    f.kill_fasync(SIGIO, POLL_IN);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "delivered once");
    assert_eq!(GOT_OWNER.load(Ordering::Acquire), 1234, "owner forwarded");
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGIO, "default SIGIO when no F_SETSIG");
    assert_eq!(GOT_UID.load(Ordering::Acquire), 1000, "owner cred snapshot forwarded");
    assert_eq!(GOT_QUEUED.load(Ordering::Acquire), 0,
        "no F_SETSIG ⇒ the plain SEND_SIG_PRIV SIGIO arm, no queued _sigpoll record");
    // F_SETSIG overrides the delivered signal.
    f.set_sig(SIGRTMIN);
    f.kill_fasync(SIGIO, POLL_IN);
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGRTMIN, "F_SETSIG overrides default");
    // The source-keyed fan reaches a registered fd on that source.
    vfs::file::fasync_register(&f);
    GOT_FIRES.store(0, Ordering::Release);
    vfs::file::kill_fasync(f.inode(), SIGIO, POLL_IN);
    assert!(GOT_FIRES.load(Ordering::Acquire) >= 1, "source fan reaches the registered fd");
    vfs::file::fasync_unregister(&f);
}

// `F_SETSIG` exists so the handler can learn WHICH descriptor fired. Before the
// `_sigpoll` arm the delivery carried neither si_band nor si_fd, so a queued
// SIGIO handler read zeros and had to re-poll every watched fd.
#[test]
fn setsig_delivery_carries_the_sigpoll_band_and_fd() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, vfs::file::owner_type::F_OWNER_PID, 0, 0);
    f.set_sig(SIGRTMIN);
    // `fasync_insert_entry` records fa_fd from the `f_op->fasync` argument.
    f.set_fasync_state(11, true);
    assert_eq!(f.fasync_fd(), 11, "fa_fd recorded from the F_SETFL(O_ASYNC) fd");
    GOT_FIRES.store(0, Ordering::Release);
    f.kill_fasync(SIGIO, POLL_IN);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1);
    assert_eq!(GOT_QUEUED.load(Ordering::Acquire), 1, "F_SETSIG ⇒ queued _sigpoll record");
    assert_eq!(GOT_FD.load(Ordering::Acquire), 11, "si_fd names the ready descriptor");
    assert_eq!(GOT_CODE.load(Ordering::Acquire), POLL_IN, "si_code is the POLL_* reason");
    assert_eq!(GOT_BAND.load(Ordering::Acquire), vfs::file::band_for(POLL_IN),
        "si_band is band_table[POLL_IN]");
    f.set_fasync_state(11, false);
}

// A source's readiness wake drives its fasync holders — the reason nothing
// needed to be added at 100-odd event sites. Before this the fasync list was a
// global registry that NO production path ever fanned out to, so `O_ASYNC` was
// inert for every backend.
#[test]
fn a_readiness_wake_delivers_to_the_sources_fasync_holders() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, vfs::file::owner_type::F_OWNER_PID, 0, 0);
    f.set_sig(SIGRTMIN);
    f.set_fasync_state(3, true);
    GOT_FIRES.store(0, Ordering::Release);
    f.inode().poll_subscribers().expect("poll source").notify_mask(vfs::POLL_IN);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1, "the poll wake signalled the O_ASYNC fd");
    assert_eq!(GOT_CODE.load(Ordering::Acquire), POLL_IN);
    assert_eq!(GOT_SIG.load(Ordering::Acquire), SIGRTMIN);
    f.set_fasync_state(3, false);
}

// Out-of-band readiness is `SIGURG`, and Linux refuses to fire plain SIGURG at
// a description that asked for no queued signal — SIGURG has its own default
// signalling path.
#[test]
fn urgent_readiness_is_sigurg_and_is_suppressed_without_setsig() {
    let _g = GATE.lock().unwrap();
    vfs::file::set_sigio_hook(capture_hook);
    let f = file();
    f.f_setown(1234, vfs::file::owner_type::F_OWNER_PID, 0, 0);
    f.set_fasync_state(5, true);
    GOT_FIRES.store(0, Ordering::Release);
    f.kill_fasync(SIGURG, POLL_PRI);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 0, "no F_SETSIG ⇒ SIGURG suppressed");
    f.set_sig(SIGRTMIN);
    f.kill_fasync(SIGURG, POLL_PRI);
    assert_eq!(GOT_FIRES.load(Ordering::Acquire), 1);
    assert_eq!(GOT_BAND.load(Ordering::Acquire), vfs::file::band_for(POLL_PRI));
    f.set_fasync_state(5, false);
}

// `sig_specific_sicodes`: a signal that already defines its own si_codes gets
// `SI_SIGIO` instead of an ambiguous `POLL_*`. SIGPOLL(==SIGIO) is the one
// exception — the POLL_* codes ARE its si_codes.
#[test]
fn sicode_is_si_sigio_for_signals_with_their_own_si_codes() {
    const SI_SIGIO: i32 = -5;
    const SIGCHLD: i32 = 17;
    const SIGSEGV: i32 = 11;
    assert_eq!(vfs::file::sicode_for(SIGIO, POLL_IN), POLL_IN, "SIGPOLL keeps the POLL_* code");
    assert_eq!(vfs::file::sicode_for(SIGRTMIN, POLL_IN), POLL_IN, "an RT signal keeps it too");
    assert_eq!(vfs::file::sicode_for(SIGCHLD, POLL_IN), SI_SIGIO);
    assert_eq!(vfs::file::sicode_for(SIGSEGV, POLL_HUP), SI_SIGIO);
}

// `band_table` reason-to-POLL-mask map. An out-of-range reason reports `~0`.
#[test]
fn band_table_matches_the_linux_reason_to_mask_map() {
    use vfs::file::band_for;
    assert_eq!(band_for(POLL_IN),  (vfs::POLL_IN | vfs::POLL_RDNORM) as i64);
    assert_eq!(band_for(POLL_OUT), (vfs::POLL_OUT | vfs::POLL_WRNORM | vfs::inode::POLL_WRBAND) as i64);
    assert_eq!(band_for(POLL_MSG), (vfs::POLL_IN | vfs::POLL_RDNORM | vfs::inode::POLL_MSG) as i64);
    assert_eq!(band_for(POLL_ERR), vfs::POLL_ERR as i64);
    assert_eq!(band_for(POLL_PRI), (vfs::POLL_PRI | vfs::inode::POLL_RDBAND) as i64);
    assert_eq!(band_for(POLL_HUP), (vfs::POLL_HUP | vfs::POLL_ERR) as i64);
    assert_eq!(band_for(0), !0, "no such reason");
    assert_eq!(band_for(vfs::file::reason::NSIGPOLL + 1), !0);
}

// Error and hangup outrank data, and urgent data outranks ordinary data — the
// precedence Linux's hand-written `sk_wake_async` call sites encode.
#[test]
fn a_readiness_mask_classifies_to_one_reason_by_linux_precedence() {
    use vfs::file::reason_for_mask;
    assert_eq!(reason_for_mask(vfs::POLL_IN), Some(POLL_IN));
    assert_eq!(reason_for_mask(vfs::POLL_OUT), Some(POLL_OUT));
    assert_eq!(reason_for_mask(vfs::POLL_IN | vfs::POLL_OUT), Some(POLL_IN));
    assert_eq!(reason_for_mask(vfs::POLL_IN | vfs::POLL_PRI), Some(POLL_PRI));
    assert_eq!(reason_for_mask(vfs::POLL_IN | vfs::POLL_HUP), Some(POLL_HUP));
    assert_eq!(reason_for_mask(vfs::POLL_HUP | vfs::POLL_ERR), Some(POLL_ERR));
    assert_eq!(reason_for_mask(0), None, "nothing became ready ⇒ no signal");
}

#[test]
fn lease_and_dnotify_round_trip() {
    let f = file();
    assert_eq!(f.lease_of(vfs::file::FL_LEASE), 2, "default lease = F_UNLCK(2)");
    f.set_lease_of(vfs::file::FL_LEASE, 1);
    assert_eq!(f.lease_of(vfs::file::FL_LEASE), 1, "F_WRLCK lease stored");
    f.set_lease_of(vfs::file::FL_NONE, 2);
    assert_eq!(f.lease_of(vfs::file::FL_LEASE), 2, "F_UNLCK drops the lease");
    assert_eq!(f.dnotify(), 0, "no dnotify watch by default");
    f.set_dnotify(0x2);
    assert_eq!(f.dnotify(), 0x2, "DN_MODIFY watch stored");
}
