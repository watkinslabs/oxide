use alloc::{collections::VecDeque, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use sched;
use vfs;

#[cfg(target_os = "oxide-kernel")]
use super::wake_peer_subs;
use super::{EndCred, UnixEnd};

/// Outcome of [`UnixPair::read_or_park`]: data drained, peer-closed EOF, or the
/// caller was registered on the reader wait list and must now `schedule()`.
#[cfg(target_os = "oxide-kernel")]
pub enum ReadOutcome {
    Data(Vec<u8>),
    Eof,
    Parked,
}

/// DIAG (debug-dbus): scan an AF_UNIX SOCK_STREAM write for the login1 session
/// interface or a D-Bus error name; dump a capped hex-free ASCII view tagged
/// with the writer tid so the failing method call / error reply is visible.
#[cfg(feature = "debug-dbus")]
fn trace_dbus_stream(data: &[u8]) {
    fn has(h: &[u8], n: &[u8]) -> bool { h.windows(n.len()).any(|w| w == n) }
    // GetSessionByPID/GetSessionByPIDFD carry a trailing uint32 pid in the body;
    // decode the last 4 bytes (LE) so a pid/vpid-namespace mismatch is visible
    // (the arg is the final aligned body field of these single-`u` calls).
    if has(data, b"GetSessionByPID") && data.len() >= 4 {
        let n = data.len();
        let pid = u32::from_le_bytes([data[n-4], data[n-3], data[n-2], data[n-1]]);
        klog::write_raw(b"[GETSESSBYPID arg_pid=");
        klog::write_dec_u64(pid as u64);
        klog::write_raw(b" caller=");
        if let Some(c) = sched::live::current() {
            klog::write_dec_u64(c.tid as u64);
            klog::write_raw(b"/");
            klog::write_raw(c.name.as_bytes());
        }
        klog::write_raw(b"]\n");
    }
    // Widen to the gdm private connection: dump EVERY D-Bus frame written by a
    // gdm process (daemon or session-worker) so the Hello handshake + any
    // reentrant call/reply that stalls the greeter is visible in-order.
    let is_tgt = sched::live::current()
        .and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s|
            s.contains("gdm") || s.contains("polkit") || s.contains("dbus-broker")
            || s.contains("upower") || s.contains("switcheroo") || s.contains("accounts")) })
        .unwrap_or(false);
    let hit = is_tgt
        || has(data, b"login1")
        || has(data, b"PolicyKit1")        // polkit name-acquisition / activation
        || has(data, b"RequestName")
        || has(data, b"StartServiceByName")
        || has(data, b"NameAcquired")
        || has(data, b"io.systemd")        // Varlink userdb queries (from any proc)
        || has(data, b"UserRecord")        // Varlink userdb replies
        || has(data, b"GroupRecord")
        || has(data, b"groupMembers")
        || has(data, b"org.freedesktop.DBus.Error");
    if !hit { return; }
    let n = core::cmp::min(data.len(), 384);
    klog::write_raw(b"[DBUS t=");
    if let Some(c) = sched::live::current() {
        klog::write_dec_u64(c.tid as u64);
        klog::write_raw(b" ");
        klog::write_raw(c.name.as_bytes());
    }
    klog::write_raw(b"] ");
    // Replace non-printable bytes with '.' so the D-Bus binary header doesn't
    // corrupt the serial stream; the ASCII strings (paths/interfaces/errors)
    // remain legible.
    for &b in &data[..n] {
        let c = if (0x20..0x7f).contains(&b) { b } else { b'.' };
        klog::write_raw(&[c]);
    }
    klog::write_raw(b"\n");
}

/// One stream-pair in-kernel: two unidirectional byte queues.
/// F171: per-direction WaitList lets a parked reader (Inode::read)
/// wake precisely when its ring grows.
/// F181a: each end's epoll-subscriber list is registered via
/// `register_end_subs` so write()/close_writer wake only the
/// peer end's subscribers, not every epoll on the box.
pub struct UnixPair {
    pub a_to_b: Spinlock<UnixRing, UnixLockClass>,
    pub b_to_a: Spinlock<UnixRing, UnixLockClass>,
    /// Reader of a_to_b (UnixEnd::B's read side) parks here.
    /// Writer (UnixEnd::A's write) wakes it after pushing.
    #[cfg(target_os = "oxide-kernel")]
    pub a_to_b_waiters: sched::live::WaitList,
    #[cfg(target_os = "oxide-kernel")]
    pub b_to_a_waiters: sched::live::WaitList,
    /// End A's epoll subscribers (the InetSocket on end A). Wakeable
    /// when a_to_b advances? No — end A reads from b_to_a. So this
    /// is woken when end B writes (write(end=B) advances b_to_a).
    pub end_a_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    pub end_b_subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    /// Peer credentials per end (`SO_PEERCRED`).
    pub cred_a: EndCred,
    pub cred_b: EndCred,
    /// The listener's bound `sun_path` this pair was accept()ed from
    /// (`connect(path)`). It is the LOCAL name of end A (the server-side
    /// accepted socket, which inherits the listener path in Linux) and the
    /// PEER name of end B (the connecting client). `None` for a socketpair /
    /// an unbound listener (abstract-autobind not yet retained). Used by
    /// `getsockname`/`getpeername` to report the real path.
    pub bind_path: Spinlock<Option<Vec<u8>>, UnixLockClass>,
}

/// One directional byte queue plus its in-band SCM_RIGHTS bursts.
///
/// S8 fix: SCM_RIGHTS fds on a SOCK_STREAM are NOT held in a FIFO
/// decoupled from byte position (the old `a_to_b_fds`/`b_to_a_fds`
/// queues), because that let a recvmsg pop the front burst regardless
/// of which bytes it read and desync a D-Bus reply's fd onto an earlier
/// fd-less message (logind Inhibit/CreateSession fd dropped). Instead
/// each burst is tagged with the absolute stream offset of the FIRST
/// byte it rides with (`produced` at the carrying write), matching
/// Linux `unix_stream_read_generic` where an skb's `fp` fds ride that
/// skb's first byte. `produced`/`consumed` are monotonic byte counters.
pub struct UnixRing {
    pub buf: VecDeque<u8>,
    pub closed_writer: bool,
    /// Total bytes ever pushed into `buf` (monotonic; drains don't lower it).
    pub produced: u64,
    /// Total bytes ever drained from `buf` (monotonic).
    pub consumed: u64,
    /// SCM_RIGHTS bursts, each tagged with the absolute stream offset of
    /// the first byte they ride with. FIFO / ascending by offset.
    pub fds: VecDeque<(u64, Vec<Arc<vfs::File>>)>,
}

impl UnixRing {
    /// # C: O(1)
    fn new() -> Self {
        Self {
            buf: VecDeque::new(),
            closed_writer: false,
            produced: 0,
            consumed: 0,
            fds: VecDeque::new(),
        }
    }
}

impl UnixPair {
    /// Build an empty pair.
    /// # C: O(1)
    pub fn new() -> alloc::sync::Arc<Self> {
        alloc::sync::Arc::new(Self {
            a_to_b: Spinlock::new(UnixRing::new()),
            b_to_a: Spinlock::new(UnixRing::new()),
            #[cfg(target_os = "oxide-kernel")]
            a_to_b_waiters: sched::live::WaitList::new(),
            #[cfg(target_os = "oxide-kernel")]
            b_to_a_waiters: sched::live::WaitList::new(),
            end_a_subs: Spinlock::new(None),
            end_b_subs: Spinlock::new(None),
            cred_a: EndCred::new(),
            cred_b: EndCred::new(),
            bind_path: Spinlock::new(None),
        })
    }

    /// Record the listener's bound `sun_path` this pair was connected to.
    /// Called by the registry `connect(path)` before the ends go live.
    /// # C: O(path len)
    pub fn set_bind_path(&self, path: Vec<u8>) {
        *self.bind_path.lock() = Some(path);
    }

    /// The peer's bound `sun_path` as seen from `end`. Linux: the client
    /// (`end == B`) sees the listener's path it connected to; the accepted
    /// server socket (`end == A`) sees the client's address — unnamed here.
    /// # C: O(path len)
    pub fn peer_path(&self, end: UnixEnd) -> Option<Vec<u8>> {
        match end {
            UnixEnd::B => self.bind_path.lock().clone(),
            UnixEnd::A => None,
        }
    }

    /// The local bound `sun_path` as seen from `end`. Linux: the accepted
    /// server socket (`end == A`) inherits the listener path; the client
    /// (`end == B`) is unnamed. # C: O(path len)
    pub fn local_path(&self, end: UnixEnd) -> Option<Vec<u8>> {
        match end {
            UnixEnd::A => self.bind_path.lock().clone(),
            UnixEnd::B => None,
        }
    }

    /// Snapshot the `{pid,uid,gid}` owning `end` (`SO_PEERCRED` source).
    /// # C: O(1)
    pub fn set_end_cred(&self, end: crate::UnixEnd, pid: u32, uid: u32, gid: u32) {
        match end {
            crate::UnixEnd::A => self.cred_a.set(pid, uid, gid),
            crate::UnixEnd::B => self.cred_b.set(pid, uid, gid),
        }
    }

    /// The PEER's `{pid,uid,gid}` as seen from `end` (peer of A is B).
    /// # C: O(1)
    pub fn peer_cred(&self, end: crate::UnixEnd) -> (u32, u32, u32) {
        match end {
            crate::UnixEnd::A => self.cred_b.get(),
            crate::UnixEnd::B => self.cred_a.get(),
        }
    }

    /// F181a: register an end's epoll-subscriber list. Called when
    /// an InetSocket is bound to this pair's end (socketpair,
    /// AF_UNIX accept, AF_UNIX connect). Writes wake only the
    /// opposite end's subscribers.
    /// # C: O(1)
    pub fn register_end_subs(&self, end: UnixEnd, subs: &alloc::sync::Arc<vfs::PollSubscribers>) {
        let slot = match end {
            UnixEnd::A => &self.end_a_subs,
            UnixEnd::B => &self.end_b_subs,
        };
        *slot.lock() = Some(alloc::sync::Arc::downgrade(subs));
    }

    /// Returns the WaitList the reader of `end` should park on.
    /// `end == A` reads from b_to_a; `end == B` reads from a_to_b.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn reader_waiters(&self, end: UnixEnd) -> &sched::live::WaitList {
        match end {
            UnixEnd::A => &self.b_to_a_waiters,
            UnixEnd::B => &self.a_to_b_waiters,
        }
    }

    /// Append `data` from `end` into the ring it writes to.
    /// Returns the number of bytes accepted (full byte count for v1).
    /// # C: O(data.len())
    pub fn write(&self, end: UnixEnd, data: &[u8]) -> usize {
        self.write_inner(end, data, Vec::new())
    }

    /// Append `data` plus a SCM_RIGHTS burst, tagging the fds to the
    /// stream offset of `data`'s first byte so the peer's recvmsg
    /// delivers them exactly with that byte (Linux skb-`fp` semantics)
    /// rather than popping them ahead of their D-Bus message.
    /// # C: O(data.len() + fds)
    pub fn write_with_fds(&self, end: UnixEnd, data: &[u8], fds: Vec<Arc<vfs::File>>) -> usize {
        self.write_inner(end, data, fds)
    }

    /// # C: O(data.len() + fds)
    fn write_inner(&self, end: UnixEnd, data: &[u8], fds: Vec<Arc<vfs::File>>) -> usize {
        // DIAG (debug-dbus): dump AF_UNIX SOCK_STREAM messages that mention the
        // login1 session interface or carry a D-Bus error reply. dbus-broker
        // relays every method call/reply through these streams, so this captures
        // mutter's Properties.GetAll on /org/freedesktop/login1/session/<id> AND
        // logind's reply (method_return or org.freedesktop.DBus.Error.*). D-Bus
        // encodes object paths / interface / error names as inline ASCII, so a
        // substring scan of the wire buffer surfaces the exact failing call —
        // pinning why mutter's get_session_proxy() returns NULL ("no matching
        // session"). Default-off; zero bytes on the hot path.
        #[cfg(feature = "debug-dbus")]
        trace_dbus_stream(data);
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        if g.closed_writer {
            return 0;
        }
        // Tag the burst to the offset of the first byte of THIS write so a
        // reader delivers it with (never before) that byte.
        if !fds.is_empty() {
            // [SCMW] AF_UNIX SOCK_STREAM SCM_RIGHTS send probe: logs the
            // sender vpid + fd count of every fd-carrying write. On the
            // D-Bus system bus the only fd-carrying stream messages are
            // logind's CreateSessionWithPIDFD (leader pidfd) and its reply
            // (session_fd), so this maps every hop of the two-hop broker
            // relay with near-zero noise. Kept permanently behind the
            // `debug-scmfd` cargo feature (default-off).
            #[cfg(feature = "debug-scmfd")]
            {
                let vpid = sched::live::current().map(|c| c.visible_pid()).unwrap_or(0);
                klog::write_raw(b"[SCMW pid=");
                klog::write_dec_u64(vpid as u64);
                klog::write_raw(b" nfds=");
                klog::write_dec_u64(fds.len() as u64);
                klog::write_raw(b"]\n");
            }
            let off = g.produced;
            g.fds.push_back((off, fds));
        }
        g.buf.extend(data.iter().copied());
        let n = data.len();
        g.produced += n as u64;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            // SCM_CREDENTIALS: stamp the writing end with the live
            // sender creds so the peer's SO_PASSCRED recvmsg delivers
            // the real sender {pid,uid,gid}. Socketpair() seeds both
            // ends with creator creds; after fork the child's
            // write must re-stamp its end.
            if let Some(c) = sched::live::current() {
                use core::sync::atomic::Ordering::Relaxed;
                self.set_end_cred(
                    end,
                    c.visible_pid(),
                    c.creds.euid.load(Relaxed),
                    c.creds.egid.load(Relaxed),
                );
            }
            // debug-syscost DIAG: log dbus-broker's / polkit's connected-socket
            // writes (pair ptr + end + nbytes) to trace the polkit↔broker reply
            // path. dbus-broker writing end A → a_to_b IS the reply polkit waits
            // for on its ppoll (fd=6, empty read queue = no reply landed).
            #[cfg(feature = "debug-syscost")]
            {
                let nm = sched::live::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.clone()) }).unwrap_or_default();
                if nm.contains("dbus-broker") || nm.contains("polkit") {
                    klog::write_raw(b"[UXWRITE comm="); klog::write_raw(nm.as_bytes());
                    klog::write_raw(b" pair="); klog::write_hex_u64(self as *const _ as u64);
                    klog::write_raw(if matches!(end, UnixEnd::A) { b" end=A" } else { b" end=B" });
                    klog::write_raw(b" n="); klog::write_dec_u64(n as u64);
                    klog::write_raw(b"]\n");
                }
            }
            // Writer on `end` feeds the ring the OTHER end reads from.
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            // F181a: targeted epoll wake
            wake_peer_subs(self, end);
        }
        n
    }

    /// Drain up to `max` bytes from the ring `end` reads from, as a
    /// plain `read(2)`/`recvfrom(2)` with no control buffer.
    ///
    /// S8: this path has NO ancillary buffer, so any SCM_RIGHTS fds
    /// riding the drained bytes are DROPPED (Linux discards an skb's
    /// `fp` fds on a read without msg_control). It is byte-identical to
    /// the pre-fd behaviour for the caller: it drains all available
    /// bytes up to `max` (never caps at an fd boundary) and only returns
    /// empty when the ring is empty — so the blocking read path's
    /// park/wake timing is UNCHANGED and cannot lose a wakeup. Dropped
    /// fds are released AFTER the ring lock is dropped (fput may take
    /// other locks — never under the ring spinlock).
    /// # C: O(min(max, queue))
    pub fn read(&self, end: UnixEnd, max: usize) -> Vec<u8> {
        let mut drop_later: Vec<Arc<vfs::File>> = Vec::new();
        let out = {
            let mut g = match end {
                UnixEnd::A => self.b_to_a.lock(),
                UnixEnd::B => self.a_to_b.lock(),
            };
            let take = core::cmp::min(max, g.buf.len());
            let mut out = Vec::with_capacity(take);
            for _ in 0..take {
                out.push(g.buf.pop_front().unwrap());
            }
            g.consumed += take as u64;
            // Discard every burst whose first byte is now behind the
            // cursor (it rode bytes we just handed over without a cmsg).
            loop {
                match g.fds.front() {
                    Some((off, _)) if *off < g.consumed => {
                        let (_, f) = g.fds.pop_front().unwrap();
                        drop_later.extend(f);
                    }
                    _ => break,
                }
            }
            out
        };
        drop(drop_later);
        out
    }

    /// Linux `prepare_to_wait` for a blocking stream read: atomically, under
    /// the read-ring lock, either hand back available data / EOF, or register
    /// the caller on the reader wait list and report `Parked`. `write_inner`
    /// takes this SAME ring lock to push bytes and only wakes AFTER dropping
    /// it, so a writer is serialized behind us — it cannot slip a write+wake
    /// between our emptiness check and our park and lose the wakeup. This
    /// closes the check-then-park race in `read_unix_stream_blocking` that
    /// stalled the D-Bus private-connection stream read (gdm greeter). Caller
    /// MUST `schedule()` after a `Parked` return (the ring lock is released
    /// here). # C: O(min(max, queue))
    #[cfg(target_os = "oxide-kernel")]
    pub fn read_or_park(&self, end: UnixEnd, max: usize, deadline_ns: u64) -> ReadOutcome {
        let read_ring = match end {
            UnixEnd::A => &self.b_to_a,
            UnixEnd::B => &self.a_to_b,
        };
        let g = read_ring.lock();
        if !g.buf.is_empty() {
            drop(g);
            return ReadOutcome::Data(self.read(end, max));
        }
        if g.closed_writer {
            drop(g);
            return ReadOutcome::Eof;
        }
        // Register on the wait list while STILL holding the read-ring lock:
        // the writer must take this lock to push, so it can only wake us
        // after we are already on the list.
        // SAFETY: running task on this CPU; preempt-off owned by the syscall
        // stub; park_with_deadline marks Sleeping + enqueues on the WaitList;
        // the ring lock is dropped below and the caller owns the schedule().
        unsafe { self.reader_waiters(end).park_with_deadline(deadline_ns); }
        drop(g);
        ReadOutcome::Parked
    }

    /// Boundary-aware stream drain for recvmsg-with-control: return up to
    /// `max` bytes AND the SCM_RIGHTS burst attached to the first byte
    /// returned. A read never crosses an fd boundary, so fds are handed
    /// over with (and only with) the bytes of the write that carried
    /// them — matching Linux `unix_stream_read_generic`, where an skb's
    /// `fp` fds ride that skb's first byte and the read stops at the next
    /// `fp` skb.
    ///
    /// Unlike [`read`], this NEVER re-queues fds and never parks: fds at
    /// or behind the cursor are returned to the caller immediately (even
    /// with an empty payload — an fd-only message), so recvmsg's yield
    /// loop always makes progress and can never wedge. It is only reached
    /// from recvmsg (which busy-yields, not parks), so it cannot lose a
    /// WaitList wakeup.
    /// # C: O(min(max, queue))
    pub fn read_stream(&self, end: UnixEnd, max: usize) -> (Vec<u8>, Vec<Arc<vfs::File>>) {
        let mut g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        // Collect every burst tagged at or behind the cursor; cap the
        // read at the NEXT burst strictly ahead so its fds cannot ride an
        // earlier message's bytes.
        let mut fds_out: Vec<Arc<vfs::File>> = Vec::new();
        let mut cap = max;
        loop {
            match g.fds.front() {
                Some((off, _)) if *off <= g.consumed => {
                    let (_, f) = g.fds.pop_front().unwrap();
                    fds_out.extend(f);
                }
                Some((off, _)) => {
                    let dist = (*off - g.consumed) as usize;
                    cap = core::cmp::min(cap, dist);
                    break;
                }
                None => break,
            }
        }
        let take = core::cmp::min(cap, g.buf.len());
        let mut out = Vec::with_capacity(take);
        for _ in 0..take {
            out.push(g.buf.pop_front().unwrap());
        }
        g.consumed += take as u64;
        drop(g);
        // debug-syscost DIAG: log dbus-broker/polkit connected-socket READS (pair +
        // end + bytes). Distinguishes blocker #2: does dbus-broker READ polkit's
        // AUTH (n>0 → AUTH/creds processing issue) or NEVER (n=0/absent → read edge)?
        #[cfg(feature = "debug-syscost")]
        {
            let nm = sched::live::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.clone()) }).unwrap_or_default();
            if nm.contains("dbus-broker") || nm.contains("polkit") {
                klog::write_raw(b"[UXREAD comm="); klog::write_raw(nm.as_bytes());
                klog::write_raw(b" pair="); klog::write_hex_u64(self as *const _ as u64);
                klog::write_raw(if matches!(end, UnixEnd::A) { b" end=A" } else { b" end=B" });
                klog::write_raw(b" n="); klog::write_dec_u64(out.len() as u64);
                klog::write_raw(b"]\n");
            }
        }
        (out, fds_out)
    }

    /// MSG_PEEK variant of `read`: copy without draining.
    /// # C: O(min(max, queued))
    pub fn peek(&self, end: UnixEnd, max: usize) -> Vec<u8> {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        let take = core::cmp::min(max, g.buf.len());
        g.buf.iter().take(take).copied().collect()
    }

    /// Mark this end's writer side closed.
    /// # C: O(1)
    pub fn close_writer(&self, end: UnixEnd) {
        let mut g = match end {
            UnixEnd::A => self.a_to_b.lock(),
            UnixEnd::B => self.b_to_a.lock(),
        };
        g.closed_writer = true;
        drop(g);
        #[cfg(target_os = "oxide-kernel")]
        {
            let waiters = match end {
                UnixEnd::A => &self.a_to_b_waiters,
                UnixEnd::B => &self.b_to_a_waiters,
            };
            waiters.wake_all();
            wake_peer_subs(self, end);
        }
    }

    /// True when reads from `end` would observe EOF (peer closed + drained).
    /// # C: O(1)
    pub fn is_eof(&self, end: UnixEnd) -> bool {
        let g = match end {
            UnixEnd::A => self.b_to_a.lock(),
            UnixEnd::B => self.a_to_b.lock(),
        };
        g.closed_writer && g.buf.is_empty()
    }
}
