//! The loop drains what is ready and waits once, not once per item.

use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

use crate::eventloop::{run, wait_readable, EventSource, WAIT_FOREVER};

/// A source that consumes one byte per `step`, counting how often the loop
/// had to wait. One byte stands for one bridge record.
struct Bytes { stream: UnixStream, budget: usize, seen: usize, waits: usize }

#[derive(Debug, Eq, PartialEq)]
enum Done { Budget }

impl EventSource for Bytes {
    type Error = Done;
    fn step(&mut self) -> Result<bool, Done> {
        if self.seen == self.budget { return Err(Done::Budget); }
        let mut byte = [0u8; 1];
        match self.stream.read(&mut byte) {
            Ok(1) => { self.seen += 1; Ok(true) }
            Ok(_) => Err(Done::Budget),
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(false),
            Err(_) => Err(Done::Budget),
        }
    }
    fn wait_fds(&self) -> [RawFd; 2] { [self.stream.as_raw_fd(), self.stream.as_raw_fd()] }
    fn before_wait(&mut self) -> Result<(), Done> { self.waits += 1; Ok(()) }
}

fn source(budget: usize) -> (UnixStream, Bytes) {
    let (peer, mine) = UnixStream::pair().unwrap();
    mine.set_nonblocking(true).unwrap();
    (peer, Bytes { stream: mine, budget, seen: 0, waits: 0 })
}

#[test]
fn a_burst_already_queued_is_drained_without_waiting_between_items() {
    let (mut peer, mut bytes) = source(64);
    peer.write_all(&[b'r'; 64]).unwrap();
    assert_eq!(run(&mut bytes, |_| Done::Budget), Done::Budget);
    assert_eq!(bytes.seen, 64);
    // Every one of the 64 was already there, so the loop never had to wait.
    assert_eq!(bytes.waits, 0);
}

#[test]
fn an_idle_loop_waits_once_per_arrival_instead_of_spinning() {
    let (mut peer, mut bytes) = source(3);
    peer.write_all(&[b'r']).unwrap();
    let writer = std::thread::spawn(move || {
        for _ in 0..2 { std::thread::sleep(Duration::from_millis(20)); peer.write_all(&[b'r']).unwrap(); }
        peer
    });
    assert_eq!(run(&mut bytes, |_| Done::Budget), Done::Budget);
    let _peer = writer.join().unwrap();
    assert_eq!(bytes.seen, 3);
    // Two arrivals came while the loop was idle. A loop that slept instead of
    // waiting on the descriptor would have gone round tens of times over the
    // same 40ms.
    assert_eq!(bytes.waits, 2);
}

#[test]
fn an_arrival_during_the_wait_is_handled_without_a_sleep_sized_delay() {
    let (mut peer, mut bytes) = source(1);
    let writer = std::thread::spawn(move || { std::thread::sleep(Duration::from_millis(30)); let at = Instant::now(); peer.write_all(&[b'r']).unwrap(); (peer, at) });
    let start = Instant::now();
    assert_eq!(run(&mut bytes, |_| Done::Budget), Done::Budget);
    let finished = Instant::now();
    let (_peer, sent) = writer.join().unwrap();
    assert!(finished.duration_since(sent) < Duration::from_millis(5), "wake took {:?} after the write", finished.duration_since(sent));
    assert!(finished.duration_since(start) >= Duration::from_millis(30));
}

#[test]
fn a_wait_reports_only_the_descriptors_that_are_readable() {
    let (mut left_peer, left) = UnixStream::pair().unwrap();
    let (_right_peer, right) = UnixStream::pair().unwrap();
    let fds = [left.as_raw_fd(), right.as_raw_fd()];
    assert_eq!(wait_readable(&fds, 0).unwrap(), 0);
    left_peer.write_all(&[b'r']).unwrap();
    assert_eq!(wait_readable(&fds, WAIT_FOREVER).unwrap(), 1);
}
