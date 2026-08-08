// An out-of-band byte signals the RECEIVER's `f_owner`, end to end: the send
// path through the real ring, the description bound to the receiving queue,
// and the signal that reaches the owner.
//
// The canonical flow this pins is `fcntl(F_SETOWN, getpid())` +
// `send(MSG_OOB)`, which enables no signal-driven I/O at all: before the owner
// notification existed, it delivered nothing, because the fasync path
// deliberately suppresses a plain SIGURG.

use super::*;
use core::sync::atomic::{AtomicI32, AtomicU32, Ordering};

/// The vfs SIGIO hook is a process-global; every test here holds the shared
/// AF_UNIX test guard so no two install or read it at once.
static FIRES: AtomicU32 = AtomicU32::new(0);
static SIG: AtomicI32 = AtomicI32::new(0);
static OWNER: AtomicI32 = AtomicI32::new(0);

fn capture(ev: vfs::file::AsyncSignal) {
    SIG.store(ev.sig, Ordering::Release);
    OWNER.store(ev.owner, Ordering::Release);
    FIRES.fetch_add(1, Ordering::Release);
}

/// A pair whose `end` receive queue is owned by a description with `owner` set
/// as its `f_owner`. # C: O(1)
fn receiver(end: UnixEnd, owner: i32)
    -> (alloc::sync::Arc<UnixPair>, alloc::sync::Arc<vfs::File>)
{
    let pair = UnixPair::new();
    let file = anon_file();
    crate::unix_sock::gc::register_file(&file, &pair.gc_node(end));
    file.f_setown(owner, vfs::file::owner_type::F_OWNER_PID, 0, 0);
    (pair, file)
}

#[test]
fn an_out_of_band_byte_signals_the_receivers_owner() {
    let _serial = test_guard();
    vfs::file::set_sigio_hook(capture);
    let (pair, file) = receiver(UnixEnd::B, 4242);
    assert!(!file.is_async(), "no O_ASYNC — F_SETOWN alone must be enough");
    FIRES.store(0, Ordering::Release);
    pair.write(UnixEnd::A, b"abc").unwrap();
    assert_eq!(FIRES.load(Ordering::Acquire), 0, "ordinary data is not urgent");
    pair.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert_eq!(FIRES.load(Ordering::Acquire), 1, "the urgent byte signalled the owner");
    assert_eq!(SIG.load(Ordering::Acquire), vfs::file::SIGURG);
    assert_eq!(OWNER.load(Ordering::Acquire), 4242);
    // The byte is still delivered by its own receive; the signal is a
    // notification, not a consumption.
    assert_eq!(pair.recv_oob(UnixEnd::B, false, false), Some(b'X'));
}

// The signal goes to the socket that RECEIVES the byte. Signalling the sender's
// own owner would notify the process that already knows.
#[test]
fn the_sender_side_owner_is_not_signalled() {
    let _serial = test_guard();
    vfs::file::set_sigio_hook(capture);
    // Bind the description to the SENDING end's queue only.
    let (pair, _file) = receiver(UnixEnd::A, 77);
    FIRES.store(0, Ordering::Release);
    pair.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert_eq!(FIRES.load(Ordering::Acquire), 0, "the writer's own owner is not the target");
    // Sent the other way, the same description is the receiver and is signalled.
    pair.write_oob_byte(UnixEnd::B, b'Y').unwrap();
    assert_eq!(FIRES.load(Ordering::Acquire), 1);
    assert_eq!(OWNER.load(Ordering::Acquire), 77);
}

// A socket userspace holds no descriptor for has no owner to signal, and the
// send must not care.
#[test]
fn a_receiver_with_no_description_is_signalled_and_sends_fine() {
    let _serial = test_guard();
    vfs::file::set_sigio_hook(capture);
    let pair = UnixPair::new();
    FIRES.store(0, Ordering::Release);
    assert_eq!(pair.write_oob_byte(UnixEnd::A, b'X').unwrap(), 1);
    assert_eq!(FIRES.load(Ordering::Acquire), 0);
    assert!(pair.has_oob(UnixEnd::B), "the byte still arrived");
}

// A description that never called F_SETOWN has nothing to signal, which is not
// the same as having no description.
#[test]
fn a_description_with_no_owner_is_not_signalled() {
    let _serial = test_guard();
    vfs::file::set_sigio_hook(capture);
    let pair = UnixPair::new();
    let file = anon_file();
    crate::unix_sock::gc::register_file(&file, &pair.gc_node(UnixEnd::B));
    FIRES.store(0, Ordering::Release);
    pair.write_oob_byte(UnixEnd::A, b'X').unwrap();
    assert_eq!(FIRES.load(Ordering::Acquire), 0, "no F_SETOWN ⇒ no target");
}
