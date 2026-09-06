//! Readiness contract: argument shape, one-shot token, publish-before-notify.

use super::*;
use crate::{Inbound, Rect};
use std::os::fd::{AsRawFd, IntoRawFd};

fn pipe() -> (OwnedFd, OwnedFd) {
    let mut fds = [0 as RawFd; 2];
    // SAFETY: pipe2 writes exactly two descriptors into the local array and the
    // raw values are immediately wrapped in owning handles.
    let rc = unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) };
    assert_eq!(rc, 0);
    // SAFETY: both descriptors come from a successful pipe2 and are unowned.
    unsafe { (OwnedFd::from_raw_fd(fds[0]), OwnedFd::from_raw_fd(fds[1])) }
}

/// Non-blocking peek: has the readiness token been written yet?
fn signalled(fd: RawFd) -> bool {
    let mut poll = libc::pollfd { fd, events: libc::POLLIN, revents: 0 };
    // SAFETY: a single initialized pollfd with a zero timeout; poll does not retain it.
    unsafe { libc::poll(&mut poll, 1, 0) == 1 && poll.revents & libc::POLLIN != 0 }
}

fn snapshot() -> MonitorSnapshot {
    let rect = Rect { left: 0, top: 0, right: 1920, bottom: 1080 };
    MonitorSnapshot { desktop: 0, monitor: rect, work_area: rect }
}

struct Recorder { reader: RawFd, sends: usize, ready_before_publish: bool, fail: bool }
impl NativeTransport for Recorder {
    fn recv(&mut self) -> Result<Option<Inbound>, TransportError> { Ok(None) }
    fn send(&mut self, _event: BridgeEvent) -> Result<(), TransportError> {
        self.sends += 1;
        if signalled(self.reader) { self.ready_before_publish = true; }
        if self.fail { Err(TransportError::Disconnected) } else { Ok(()) }
    }
}

#[test]
fn arguments_require_the_bridge_fd_and_accept_a_readiness_fd() {
    assert_eq!(parse_args(&["--fd", "0"]), Ok(Options { ready_fd: None }));
    assert_eq!(parse_args(&["--fd", "0", "--ready-fd", "3"]), Ok(Options { ready_fd: Some(3) }));
    assert_eq!(parse_args(&["--ready-fd", "9", "--fd", "0"]), Ok(Options { ready_fd: Some(9) }));
}

#[test]
fn arguments_reject_stdio_readiness_and_malformed_forms() {
    let empty: [&str; 0] = [];
    assert_eq!(parse_args(&empty), Err(UsageError));
    assert_eq!(parse_args(&["--fd", "1"]), Err(UsageError));
    assert_eq!(parse_args(&["--fd"]), Err(UsageError));
    assert_eq!(parse_args(&["--fd", "0", "--ready-fd", "2"]), Err(UsageError));
    assert_eq!(parse_args(&["--fd", "0", "--ready-fd", "x"]), Err(UsageError));
    assert_eq!(parse_args(&["--fd", "0", "--ready-fd"]), Err(UsageError));
    assert_eq!(parse_args(&["--ready-fd", "3"]), Err(UsageError));
    assert_eq!(parse_args(&["--fd", "0", "--wat", "3"]), Err(UsageError));
}

#[test]
fn notify_writes_one_token_then_closes_the_descriptor() {
    let (reader, writer) = pipe();
    notify(writer.into_raw_fd()).unwrap();
    let mut buffer = [0u8; 4];
    // SAFETY: reads into a local buffer from an owned pipe read end.
    let count = unsafe { libc::read(reader.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    assert_eq!(count, 1);
    assert_eq!(buffer[0], READY_TOKEN);
    // SAFETY: same owned descriptor; a closed write end reports end of file.
    let eof = unsafe { libc::read(reader.as_raw_fd(), buffer.as_mut_ptr().cast(), buffer.len()) };
    assert_eq!(eof, 0);
}

#[test]
fn readiness_follows_publication_of_the_monitor_snapshot() {
    let (reader, writer) = pipe();
    let mut transport = Recorder { reader: reader.as_raw_fd(), sends: 0, ready_before_publish: false, fail: false };
    publish_then_notify(&mut transport, snapshot(), Some(writer.into_raw_fd())).unwrap();
    assert_eq!(transport.sends, 1);
    assert!(!transport.ready_before_publish, "readiness was signalled before the monitor snapshot was published");
    assert!(signalled(reader.as_raw_fd()));
}

#[test]
fn a_failed_publication_signals_nothing() {
    let (reader, writer) = pipe();
    let mut transport = Recorder { reader: reader.as_raw_fd(), sends: 0, ready_before_publish: false, fail: true };
    let fd = writer.into_raw_fd();
    assert!(publish_then_notify(&mut transport, snapshot(), Some(fd)).is_err());
    assert!(!signalled(reader.as_raw_fd()));
    // SAFETY: the failure path left the descriptor unconsumed; close it once here.
    unsafe { libc::close(fd) };
}

#[test]
fn a_launcher_that_asked_for_no_readiness_fd_still_publishes() {
    let (reader, _writer) = pipe();
    let mut transport = Recorder { reader: reader.as_raw_fd(), sends: 0, ready_before_publish: false, fail: false };
    publish_then_notify(&mut transport, snapshot(), None).unwrap();
    assert_eq!(transport.sends, 1);
}
