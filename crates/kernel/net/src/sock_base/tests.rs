// Hosted coverage for the one socket base: what an admitted generic write
// stores, and that the read table answers from that same word.

use super::*;
use crate::sock_opts::sol_socket::get::{SockView, Value};

fn inet() -> sol::OptSock {
    sol::OptSock { family: crate::socket_args::AF_INET as u16, stream: true, tcp: true,
                   udp: false, peek_off_capable: false }
}

fn view() -> SockView { SockView { sock: inet(), ..Default::default() } }

fn read(base: &SockBase, optname: u64) -> Value {
    sol::get::value(optname, 16, base, &view()).expect("the option is answered")
}

/// Every generic write lands in the base, and the read table answers from it —
/// so a family that embeds the base cannot store a value its own read misses.
#[test]
fn every_generic_write_reads_back_from_the_base() {
    let base = SockBase::default();
    let cases: [(Action, u64, Value); 12] = [
        (Action::Reuseaddr(1), sol::SO_REUSEADDR, Value::Int(1)),
        (Action::Reuseport(1), sol::SO_REUSEPORT, Value::Int(1)),
        (Action::Keepalive(1), sol::SO_KEEPALIVE, Value::Int(1)),
        (Action::Broadcast(1), sol::SO_BROADCAST, Value::Int(1)),
        (Action::Oobinline(1), sol::SO_OOBINLINE, Value::Int(1)),
        (Action::SndBuf(9216), sol::SO_SNDBUF, Value::Int(9216)),
        (Action::RcvBuf(4608), sol::SO_RCVBUF, Value::Int(4608)),
        (Action::Priority(6), sol::SO_PRIORITY, Value::Int(6)),
        (Action::Mark(0x2a), sol::SO_MARK, Value::Int(0x2a)),
        (Action::Timeout { send: true, ns: 2_000_000_000 }, sol::SO_SNDTIMEO_OLD,
            Value::Timeval { sec: 2, usec: 0 }),
        (Action::Timeout { send: false, ns: 3_500_000_000 }, sol::SO_RCVTIMEO_NEW,
            Value::Timeval { sec: 3, usec: 500_000 }),
        (Action::Linger { on: true, seconds: 11 }, sol::SO_LINGER,
            Value::Linger { on: 1, seconds: 11 }),
    ];
    for (action, optname, expected) in cases {
        assert!(base.apply(action), "the base owns {action:?}");
        assert_eq!(read(&base, optname), expected, "read-back of {action:?}");
    }
}

/// The timestamp word and its companion selector are one home, not two.
#[test]
fn the_timestamp_word_is_one_home() {
    let base = SockBase::default();
    assert!(base.apply(Action::Timestamping { flags: 0x11, bind_phc: 3, new: true }));
    assert_eq!(base.timestamping.load(Ordering::Acquire), 0x11);
    assert_eq!(read(&base, sol::SO_TIMESTAMPING_NEW),
        Value::Timestamping { flags: 0x11, bind_phc: 3 });
}

/// A receive-buffer write also takes the receive-buffer lock, in both the
/// dedicated switch the transport reads and the lock word the option reports.
#[test]
fn a_receive_buffer_write_takes_the_lock() {
    let base = SockBase::default();
    assert!(!base.rcvbuf_locked.load(Ordering::Acquire));
    assert!(base.apply(Action::RcvBuf(8192)));
    assert!(base.rcvbuf_locked.load(Ordering::Acquire));
    assert_eq!(read(&base, sol::SO_BUF_LOCK), Value::Int(sol::SOCK_RCVBUF_LOCK));
    // Clearing the lock word clears the switch with it.
    assert!(base.apply(Action::Scalar { slot: Scalar::BufLock, value: 0 }));
    assert!(!base.rcvbuf_locked.load(Ordering::Acquire));
}

/// The credential and label switches are the shared types, and the label is
/// NOT a bit in the generic flag word — one home, whichever family asks.
#[test]
fn the_credential_and_label_switches_have_one_home_each() {
    let base = SockBase::default();
    let unix = SockView {
        sock: sol::OptSock { family: crate::socket_args::AF_UNIX as u16, stream: true,
                             tcp: false, udp: false, peek_off_capable: false },
        ..Default::default() };
    assert!(base.apply(Action::Passcred(1)));
    assert!(base.passcred.on());
    assert_eq!(sol::get::value(sol::SO_PASSCRED, 4, &base, &unix), Ok(Value::Int(1)));
    assert!(base.apply(Action::Flag { bit: flag::SCM_SECURITY, on: true }));
    assert!(base.scm_security.on());
    assert!(!base.generic.flag(flag::SCM_SECURITY));
    assert_eq!(sol::get::value(sol::SO_PASSSEC, 4, &base, &unix), Ok(Value::Int(1)));
}

/// The device binding is the one action the base cannot finish alone: the
/// family must resolve the index against its own namespace first, so the base
/// refuses it rather than storing an unvalidated interface.
#[test]
fn the_device_binding_is_handed_back_to_the_family() {
    let base = SockBase::default();
    assert!(!base.apply(Action::BindToIfindex(3)));
    assert_eq!(base.bound_ifindex.load(Ordering::Acquire), 0);
    assert!(!base.bound_device());
    base.bind_to_ifindex(3);
    assert!(base.bound_device());
    assert_eq!(read(&base, sol::SO_BINDTOIFINDEX), Value::Int(3));
    // A socket that already has a device is judged by the re-binding ladder.
    assert!(base.set_env(sol::OptCaps::default()).bound_device);
}

/// A family that starts from its own buffer budget still reads it back through
/// the one table.
#[test]
fn a_family_chosen_buffer_budget_reads_back() {
    let base = SockBase::with_buffers(1024, 2048);
    assert_eq!(read(&base, sol::SO_SNDBUF), Value::Int(1024));
    assert_eq!(read(&base, sol::SO_RCVBUF), Value::Int(2048));
    assert_eq!(base.sndbuf_bytes(), 1024);
    assert_eq!(base.rcvbuf_bytes(), 2048);
}

/// Both timeouts are unset by default and report the wait-forever value.
#[test]
fn both_timeouts_start_unset() {
    let base = SockBase::default();
    assert_eq!(base.sndtimeo(), 0);
    assert_eq!(base.rcvtimeo(), 0);
    assert_eq!(base.sndtimeo_u64(), 0);
    assert_eq!(base.rcvtimeo_u64(), 0);
    assert_eq!(read(&base, sol::SO_RCVTIMEO_OLD), Value::Timeval { sec: 0, usec: 0 });
}

/// The device-binding READ answers a name, not a scalar: an unbound socket
/// gets the empty answer, and a bound one is refused for a buffer smaller
/// than a whole interface name BEFORE the interface is resolved at all.
#[test]
fn the_device_binding_read_screens_the_buffer_before_it_resolves() {
    let base = SockBase::default();
    assert_eq!(base.bound_device_name(0, 0), Ok(None));
    assert_eq!(base.bound_device_name(0, 64), Ok(None));
    base.bind_to_ifindex(4242);
    assert_eq!(base.bound_device_name(0, 15), Err(syscall::errno::Errno::Einval));
    // With room, the resolution runs — and an index no interface owns is
    // ENODEV rather than a fabricated name.
    assert_eq!(base.bound_device_name(0, 16), Err(syscall::errno::Errno::Enodev));
}
