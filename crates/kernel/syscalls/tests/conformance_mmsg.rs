//! F721 host-oracle differential conformance — the batched message paths,
//! rows 299 `recvmmsg` and 307 `sendmmsg`. Host side = real `recvmmsg` /
//! `sendmmsg` / `getsockopt(SO_ERROR)` on real loopback sockets on THIS
//! machine's Linux kernel (`conformance::sockets`); oxide side = the REAL
//! batch compositions — `syscalls::mmsg_batch::run` (ungated) driven by the
//! shared scripted socket `mmsg_batch::fake`, and `socket::send_batch`
//! (ungated) driven by a netlink fixture.
//!
//! Nothing here re-implements a batch loop: the fake supplies only the
//! mechanical ABI steps (resolve a descriptor, run one receive, publish one
//! length), and every decision under test — the compat refusal, timeout
//! validation, pending-error precedence, entry flags, what ends a batch, what
//! a partial batch reports and latches — is made by the same code the slot
//! files call. Each case names the queue it builds; the fake is scripted from
//! that fixture, never from the host's answer.

extern crate alloc;

use alloc::sync::Arc;
use alloc::vec::Vec;

use conformance::corpus::{Case, run_corpus};
use conformance::outcome::Outcome;
use conformance::sockets::{self, RecvBatch, UdpPair};

use net::uapi::{MSG_CMSG_COMPAT, MSG_DONTWAIT, MSG_ERRQUEUE, MSG_WAITFORONE};
use socket::{BatchIo, BatchSpec, Error, ImportMode, KResult, Message, SendContext, send_batch};
use syscall::errno::Errno;
use syscalls::mmsg_batch::fake::{Entry, Fake, drive};

/// One 64-byte receive buffer per entry is what the host fixture builds, so
/// every queued datagram lands whole and the count is the only variable.
fn host_recv(pair: &UdpPair, batch: &RecvBatch) -> Outcome {
    sockets::recvmmsg(pair.rx, batch)
}

fn neg(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn oxide(result: i64) -> Outcome { Outcome::from_oxide_rv(result) }

// ------------------------------------------------ what admits a batch ----

/// The native entry never speaks the compat message layout, and says so
/// before it looks at the descriptor: a closed fd does NOT turn this into
/// `EBADF`.
fn compat_layout_before_bad_descriptor() -> (Outcome, Outcome) {
    let mut batch = RecvBatch::new(1, MSG_CMSG_COMPAT as i32);
    batch.flags = MSG_CMSG_COMPAT as i32;
    let host = sockets::recvmmsg(-1, &batch);
    let mut fake = Fake::queued(1);
    fake.resolve = Err(neg(Errno::Ebadf));
    let (result, _) = drive(MSG_CMSG_COMPAT, 1, fake);
    (host, oxide(result))
}

/// Same refusal on a socket with a message already waiting — the flag is
/// rejected, the queue is untouched.
fn compat_layout_on_a_ready_socket() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 1);
    let host = host_recv(&pair, &RecvBatch::new(1, (MSG_CMSG_COMPAT | MSG_DONTWAIT) as i32));
    let (result, _) = drive(MSG_CMSG_COMPAT | MSG_DONTWAIT, 1, Fake::queued(1));
    (host, oxide(result))
}

/// A malformed timeout outranks a bad descriptor: it is read and validated
/// before the fd is resolved.
fn negative_timeout_before_bad_descriptor() -> (Outcome, Outcome) {
    let mut batch = RecvBatch::new(1, 0);
    batch.timeout = Some((-1, 0));
    let host = sockets::recvmmsg(-1, &batch);
    let mut fake = Fake::queued(1);
    fake.timeout = Some((-1, 0));
    fake.resolve = Err(neg(Errno::Ebadf));
    let (result, _) = drive(0, 1, fake);
    (host, oxide(result))
}

/// A nanosecond count that reaches a whole second is the same refusal.
fn whole_second_nsec_before_bad_descriptor() -> (Outcome, Outcome) {
    let mut batch = RecvBatch::new(1, 0);
    batch.timeout = Some((0, 1_000_000_000));
    let host = sockets::recvmmsg(-1, &batch);
    let mut fake = Fake::queued(1);
    fake.timeout = Some((0, 1_000_000_000));
    fake.resolve = Err(neg(Errno::Ebadf));
    let (result, _) = drive(0, 1, fake);
    (host, oxide(result))
}

/// A zero timeout is valid, not an error — so the bad descriptor is what the
/// caller hears about.
fn valid_timeout_then_bad_descriptor() -> (Outcome, Outcome) {
    let mut batch = RecvBatch::new(1, 0);
    batch.timeout = Some((0, 0));
    let host = sockets::recvmmsg(-1, &batch);
    let mut fake = Fake::queued(1);
    fake.timeout = Some((0, 0));
    fake.resolve = Err(neg(Errno::Ebadf));
    let (result, _) = drive(0, 1, fake);
    (host, oxide(result))
}

/// A socket's pending error outranks the whole batch, and reporting it
/// consumes it — the caller is told once.
fn a_pending_error_precedes_the_batch() -> (Outcome, Outcome) {
    let dead = sockets::udp_dead_peer();
    let host = sockets::recvmmsg(dead.fd, &RecvBatch::new(1, MSG_DONTWAIT as i32));
    let mut fake = Fake::queued(0);
    fake.pending = Errno::Econnrefused.as_i32();
    let (result, _) = drive(MSG_DONTWAIT, 1, fake);
    (host, oxide(result))
}

/// An error-queue read is how that error is meant to be COLLECTED, so the
/// batch does not intercept it first: the read reaches the (empty) queue and
/// the pending error is still there afterwards.
fn an_error_queue_read_leaves_the_pending_error() -> (Outcome, Outcome) {
    let dead = sockets::udp_dead_peer();
    let _ = sockets::recvmmsg(dead.fd, &RecvBatch::new(1, (MSG_ERRQUEUE | MSG_DONTWAIT) as i32));
    let host = Outcome::ok(sockets::so_error(dead.fd) as i64);
    let mut fake = Fake::queued(0);
    fake.pending = Errno::Econnrefused.as_i32();
    let (_, fake) = drive(MSG_ERRQUEUE | MSG_DONTWAIT, 1, fake);
    (host, Outcome::ok(fake.pending as i64))
}

// ------------------------------------------------------ what a batch does --

/// A zero-length batch delivers nothing even with a message waiting.
fn zero_length_batch_on_a_ready_socket() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 1);
    let host = host_recv(&pair, &RecvBatch::new(0, MSG_DONTWAIT as i32));
    let (result, _) = drive(MSG_DONTWAIT, 0, Fake::queued(1));
    (host, oxide(result))
}

/// A batch longer than the queue reports what was there.
fn drains_the_whole_queue_nonblocking() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 3);
    let host = host_recv(&pair, &RecvBatch::new(5, MSG_DONTWAIT as i32));
    let (result, _) = drive(MSG_DONTWAIT, 5, Fake::queued(3));
    (host, oxide(result))
}

/// An empty queue with nothing delivered reports the failure itself.
fn empty_queue_nonblocking_is_the_failure() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    let host = host_recv(&pair, &RecvBatch::new(4, MSG_DONTWAIT as i32));
    let (result, _) = drive(MSG_DONTWAIT, 4, Fake::queued(0));
    (host, oxide(result))
}

/// `UIO_MAXIOV` is `sendmmsg`'s bound alone: a `vlen` above it neither errors
/// nor truncates here. The queue is built DEEPER than that bound and measured
/// with plain `recv(2)`, so a clamp on either side changes the answer — a
/// copy of the send bound in the receive path silently truncated long batches
/// (`B1676`).
fn vlen_beyond_uio_maxiov_is_not_a_receive_bound() -> (Outcome, Outcome) {
    /// Enough one-byte datagrams to overrun the send bound, with headroom.
    const QUEUED: usize = 1400;
    /// Receive-buffer headroom for that queue; the kernel caps what it grants.
    const RCVBUF: i32 = 4 * 1024 * 1024;
    /// Entries offered, above both the bound and the queue.
    const VLEN: u32 = 2000;
    let gauge = sockets::udp_pair_with_rcvbuf(RCVBUF);
    sockets::queue_datagrams(&gauge, QUEUED);
    let depth = sockets::drain_count(&gauge);
    assert!(depth > socket::UIO_MAXIOV as usize,
        "the fixture must out-queue the bound it is testing for, got {depth}");
    let pair = sockets::udp_pair_with_rcvbuf(RCVBUF);
    sockets::queue_datagrams(&pair, QUEUED);
    let host = host_recv(&pair, &RecvBatch::new(VLEN, MSG_DONTWAIT as i32));
    let (result, _) = drive(MSG_DONTWAIT, VLEN as u64, Fake::queued(depth));
    (host, oxide(result))
}

/// `MSG_WAITFORONE` drains what is queued once the first message lands
/// rather than waiting again for each further entry.
fn waitforone_returns_the_queue_without_waiting() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 2);
    let host = host_recv(&pair, &RecvBatch::new(4, MSG_WAITFORONE as i32));
    let (result, _) = drive(MSG_WAITFORONE, 4, Fake::queued(2));
    (host, oxide(result))
}

/// …and having drained it, the batch ends cleanly: nothing is latched. A
/// receive still carrying `MSG_WAITFORONE` semantics past the queue would
/// have waited again, and the fake reports that as an errno the batch then
/// latches — which the host says is not there.
fn waitforone_leaves_nothing_latched_after_the_drain() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 2);
    let _ = host_recv(&pair, &RecvBatch::new(4, MSG_WAITFORONE as i32));
    let host = Outcome::ok(sockets::so_error(pair.rx) as i64);
    let (_, fake) = drive(MSG_WAITFORONE, 4, Fake::queued(2));
    (host, Outcome::ok(fake.latched.unwrap_or(0) as i64))
}

/// The remaining timeout is written back only once a message has landed.
fn timeout_is_written_back_after_a_delivery() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 1);
    let mut batch = RecvBatch::new(3, MSG_DONTWAIT as i32);
    batch.timeout = Some((TIMEOUT_SEC, 0));
    let (_, written) = sockets::recvmmsg_timeout_writeback(pair.rx, &batch);
    let mut fake = Fake::queued(1);
    fake.timeout = Some((TIMEOUT_SEC, 0));
    fake.remaining = alloc::vec![Some(TIMEOUT_LEFT_NS)];
    let (_, fake) = drive(MSG_DONTWAIT, 3, fake);
    (Outcome::ok(written as i64), Outcome::ok(fake.copied_timeout as i64))
}

/// An empty nonblocking return leaves the caller's timespec alone.
fn timeout_is_untouched_when_nothing_landed() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    let mut batch = RecvBatch::new(3, MSG_DONTWAIT as i32);
    batch.timeout = Some((TIMEOUT_SEC, 0));
    let (_, written) = sockets::recvmmsg_timeout_writeback(pair.rx, &batch);
    let mut fake = Fake::queued(0);
    fake.timeout = Some((TIMEOUT_SEC, 0));
    let (_, fake) = drive(MSG_DONTWAIT, 3, fake);
    (Outcome::ok(written as i64), Outcome::ok(fake.copied_timeout as i64))
}

/// Long enough that no scheduling delay can spend it, short enough that a
/// case which does block is a test failure rather than a hang.
const TIMEOUT_SEC: i64 = 5;
/// What the fake reports is left after the one delivery — any non-zero value
/// keeps the batch going, the writeback is what is under test.
const TIMEOUT_LEFT_NS: u64 = 4 * 1_000_000_000;

// ------------------------------------------- what a partial batch reports --

/// An entry whose `msg_iov` cannot be read fails; with a message already
/// delivered the batch reports the COUNT, not the errno.
fn a_failing_entry_after_a_delivery_reports_the_count() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 2);
    let mut batch = RecvBatch::new(2, MSG_DONTWAIT as i32);
    batch.bad_iov_at = Some(1);
    let host = host_recv(&pair, &batch);
    let (result, _) = drive(MSG_DONTWAIT, 2,
        Fake::new(alloc::vec![Entry::Got { oob: false }, Entry::Failed(neg(Errno::Efault))]));
    (host, oxide(result))
}

/// …and the errno it swallowed becomes the socket's pending error, which the
/// caller collects with `getsockopt(SO_ERROR)` or the next receive.
fn a_swallowed_failure_is_latched_as_the_pending_error() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 2);
    let mut batch = RecvBatch::new(2, MSG_DONTWAIT as i32);
    batch.bad_iov_at = Some(1);
    let _ = host_recv(&pair, &batch);
    let host = Outcome::ok(sockets::so_error(pair.rx) as i64);
    let (_, fake) = drive(MSG_DONTWAIT, 2,
        Fake::new(alloc::vec![Entry::Got { oob: false }, Entry::Failed(neg(Errno::Efault))]));
    (host, Outcome::ok(fake.latched.unwrap_or(0) as i64))
}

/// A dry queue is not an error to remember: nothing is latched behind a
/// partial batch that simply ran out of messages.
fn a_dry_queue_after_a_delivery_latches_nothing() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 1);
    let _ = host_recv(&pair, &RecvBatch::new(3, MSG_DONTWAIT as i32));
    let host = Outcome::ok(sockets::so_error(pair.rx) as i64);
    let (_, fake) = drive(MSG_DONTWAIT, 3, Fake::queued(1));
    (host, Outcome::ok(fake.latched.unwrap_or(0) as i64))
}

/// A first-entry failure has no count to protect, so it IS the answer — and
/// nothing is latched.
fn a_first_entry_failure_is_the_answer() -> (Outcome, Outcome) {
    let pair = sockets::udp_pair();
    sockets::queue_datagrams(&pair, 1);
    let mut batch = RecvBatch::new(2, MSG_DONTWAIT as i32);
    batch.bad_iov_at = Some(0);
    let host = host_recv(&pair, &batch);
    let (result, _) = drive(MSG_DONTWAIT, 2,
        Fake::new(alloc::vec![Entry::Failed(neg(Errno::Efault)), Entry::Got { oob: false }]));
    (host, oxide(result))
}

// -------------------------------------------------------------- sendmmsg --

/// One netlink socket per batch, with every message a well-formed minimal
/// request — the send side's real work-fn path, not a model.
struct NetlinkBatch {
    sent: u32,
}

impl BatchIo for NetlinkBatch {
    fn file(&mut self) -> KResult<Arc<vfs::File>> {
        let namespace = network_namespace::initial();
        let endpoint = Arc::new(netlink::NetlinkSocket::new(netlink::proto::NETLINK_ROUTE, &namespace));
        let inode = netlink::make_netlink_socket_inode(endpoint);
        let dentry = vfs::Dentry::new(None, alloc::string::String::from("socket"), inode.clone());
        Ok(vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR))
    }
    fn import(&mut self, _index: u32, _mode: ImportMode) -> KResult<Message> { Err(Error::Eio) }
    fn import_envelope(&mut self, _index: u32) -> KResult<Option<Message>> {
        Ok(Some(Message { requested_len: NLMSG_MIN_REQUEST, ..Message::default() }))
    }
    fn import_payload(&mut self, _index: u32, message: &mut Message) -> KResult<()> {
        message.payload = Vec::from(MINIMAL_NLMSG);
        Ok(())
    }
    fn publish(&mut self, _index: u32, _len: u32) -> KResult<()> { self.sent += 1; Ok(()) }
}

/// A 16-byte `nlmsghdr` with no body: `nlmsg_len`, `NLMSG_NOOP`, no flags.
const MINIMAL_NLMSG: [u8; 16] = [16, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
const NLMSG_MIN_REQUEST: usize = MINIMAL_NLMSG.len();

/// Entries above `UIO_MAXIOV` are neither sent nor an error: Linux clamps the
/// batch and reports the clamp as its count.
fn sendmmsg_batch_is_bounded_at_uio_maxiov() -> (Outcome, Outcome) {
    const OVERSIZED: u32 = socket::UIO_MAXIOV + 76;
    let host = sockets::sendmmsg_discard(OVERSIZED);
    let task = sched::Task::new(4237, "mmsgdiff", sched::SchedClass::Normal { weight: 1024 });
    let ctx = SendContext::new(&task);
    let mut io = NetlinkBatch { sent: 0 };
    let sent = send_batch(&ctx, BatchSpec { len: OVERSIZED, flags: 0 }, &mut io);
    (host, oxide(sent.map(|n| n as i64).unwrap_or_else(|e| -(e.errno() as i64))))
}

const CASES: &[Case] = &[
    Case { id: "recvmmsg.compat_layout_before_bad_descriptor", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: compat_layout_before_bad_descriptor },
    Case { id: "recvmmsg.compat_layout_on_a_ready_socket", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: compat_layout_on_a_ready_socket },
    Case { id: "recvmmsg.negative_timeout_before_bad_descriptor", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: negative_timeout_before_bad_descriptor },
    Case { id: "recvmmsg.whole_second_nsec_before_bad_descriptor", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: whole_second_nsec_before_bad_descriptor },
    Case { id: "recvmmsg.valid_timeout_then_bad_descriptor", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: valid_timeout_then_bad_descriptor },
    Case { id: "recvmmsg.a_pending_error_precedes_the_batch", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: a_pending_error_precedes_the_batch },
    Case { id: "recvmmsg.an_error_queue_read_leaves_the_pending_error", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: an_error_queue_read_leaves_the_pending_error },
    Case { id: "recvmmsg.zero_length_batch_on_a_ready_socket", known_divergence: None, skip: None,
        compare_ret_on_success: true, run: zero_length_batch_on_a_ready_socket },
    Case { id: "recvmmsg.drains_the_whole_queue_nonblocking", known_divergence: None, skip: None,
        compare_ret_on_success: true, run: drains_the_whole_queue_nonblocking },
    Case { id: "recvmmsg.empty_queue_nonblocking_is_the_failure", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: empty_queue_nonblocking_is_the_failure },
    Case { id: "recvmmsg.vlen_beyond_uio_maxiov_is_not_a_receive_bound", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: vlen_beyond_uio_maxiov_is_not_a_receive_bound },
    Case { id: "recvmmsg.waitforone_returns_the_queue_without_waiting", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: waitforone_returns_the_queue_without_waiting },
    Case { id: "recvmmsg.waitforone_leaves_nothing_latched_after_the_drain", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: waitforone_leaves_nothing_latched_after_the_drain },
    Case { id: "recvmmsg.timeout_is_written_back_after_a_delivery", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: timeout_is_written_back_after_a_delivery },
    Case { id: "recvmmsg.timeout_is_untouched_when_nothing_landed", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: timeout_is_untouched_when_nothing_landed },
    Case { id: "recvmmsg.a_failing_entry_after_a_delivery_reports_the_count", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: a_failing_entry_after_a_delivery_reports_the_count },
    Case { id: "recvmmsg.a_swallowed_failure_is_latched_as_the_pending_error", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: a_swallowed_failure_is_latched_as_the_pending_error },
    Case { id: "recvmmsg.a_dry_queue_after_a_delivery_latches_nothing", known_divergence: None,
        skip: None, compare_ret_on_success: true, run: a_dry_queue_after_a_delivery_latches_nothing },
    Case { id: "recvmmsg.a_first_entry_failure_is_the_answer", known_divergence: None, skip: None,
        compare_ret_on_success: false, run: a_first_entry_failure_is_the_answer },
    Case { id: "sendmmsg.batch_is_bounded_at_uio_maxiov", known_divergence: None, skip: None,
        compare_ret_on_success: true, run: sendmmsg_batch_is_bounded_at_uio_maxiov },
];

#[test]
fn mmsg_conformance_corpus() {
    let report = run_corpus(CASES);
    assert_eq!(report.total, CASES.len());
}
