use alloc::{string::String, sync::Arc, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};
use sched;

use super::{GcLink, GcNode, GcPin, UnixEnd, UnixPair};
use vfs;

/// AF_UNIX path-bound stream endpoint. `bind(path)` reserves it in the
/// registry; `listen()` makes it connectable and enables its accept queue.
pub struct UnixListener {
    pub addr: UnixAddr,
    pub path: Vec<u8>,
    state: Spinlock<UnixListenerState, UnixLockClass>,
    /// F170: per-listener waitlist for `sys_accept`.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
    /// The listener socket's epoll subscribers.
    pub subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
    gc: GcNode,
}

struct UnixListenerState {
    listening: bool,
    closed: bool,
    receive_shutdown: bool,
    send_shutdown: bool,
    backlog: usize,
    accept_q: alloc::collections::VecDeque<(Arc<UnixPair>, GcLink)>,
    owner_cred: (u32, u32, u32),
    #[cfg(target_os = "oxide-kernel")]
    connect_sockets: Vec<alloc::sync::Weak<crate::sock::InetSocket>>,
}

#[cfg(target_os = "oxide-kernel")]
fn wake_connect_sockets(waiters: Vec<alloc::sync::Weak<crate::sock::InetSocket>>) {
    for waiter in waiters {
        if let Some(sock) = waiter.upgrade() { sock.connect_waiters.wake_all(); }
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum UnixConnectError {
    Refused,
    Full,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnixAddrKey {
    Abstract(Vec<u8>),
    Path { fsid: u64, ino: u64 },
}

#[derive(Clone)]
pub struct UnixAddr {
    pub key: UnixAddrKey,
    pub display: Vec<u8>,
}

impl UnixAddr {
    /// # C: O(N path)
    pub fn from_abstract_or_test_path(path: String) -> Self {
        let path = path.into_bytes();
        Self { key: UnixAddrKey::Abstract(path.clone()), display: path }
    }
    /// # C: O(1)
    pub fn from_inode(display: String, inode: &vfs::InodeRef) -> Self {
        Self { key: UnixAddrKey::Path { fsid: inode.fsid(), ino: inode.ino() as u64 }, display: display.into_bytes() }
    }
    /// # C: O(1)
    pub fn from_inode_bytes(display: Vec<u8>, inode: &vfs::InodeRef) -> Self {
        Self { key: UnixAddrKey::Path { fsid: inode.fsid(), ino: inode.ino() as u64 }, display }
    }

    /// # C: O(N path)
    pub fn from_sockaddr_path(path: Vec<u8>) -> Self {
        Self { key: UnixAddrKey::Abstract(path.clone()), display: path }
    }

    /// # C: O(1)
    pub fn is_pathname(&self) -> bool {
        matches!(self.key, UnixAddrKey::Path { .. })
    }
}

impl UnixListener {
    /// # C: O(1)
    pub fn new(addr: UnixAddr) -> Arc<Self> {
        let path = addr.display.clone();
        Arc::new(Self {
            addr,
            path,
            state: Spinlock::new(UnixListenerState {
                listening: false,
                closed: false,
                receive_shutdown: false,
                send_shutdown: false,
                backlog: 0,
                accept_q: alloc::collections::VecDeque::new(),
                owner_cred: (0, 0, 0),
                #[cfg(target_os = "oxide-kernel")]
                connect_sockets: Vec::new(),
            }),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
            subs: Spinlock::new(None),
            gc: GcNode::new(),
        })
    }

    /// Stable listening-socket identity. # C: O(1)
    pub fn gc_node(&self) -> GcNode { self.gc.clone() }

    /// Publish this bound stream socket and apply Linux backlog normalization.
    /// Queue capacity is `backlog + 1`, matching AF_UNIX connect accounting.
    /// # C: O(1)
    pub fn listen(&self, backlog: i32, somaxconn: usize) {
        self.listen_with_cred(backlog, somaxconn, None);
    }

    /// Publish a listener and atomically replace its peer credential snapshot.
    /// # C: O(1)
    pub(crate) fn listen_with_cred(&self, backlog: i32, somaxconn: usize, cred: Option<(u32, u32, u32)>) {
        let mut st = self.state.lock();
        if let Some(cred) = cred { st.owner_cred = cred; }
        st.backlog = crate::sysctl::normalize_listen_backlog(backlog, somaxconn);
        st.listening = !st.closed;
        #[cfg(target_os = "oxide-kernel")]
        let waiters = core::mem::take(&mut st.connect_sockets);
        drop(st);
        #[cfg(target_os = "oxide-kernel")]
        wake_connect_sockets(waiters);
    }

    /// Whether `listen(2)` completed for this bound address. # C: O(1)
    pub fn is_listening(&self) -> bool {
        let st = self.state.lock();
        st.listening && !st.closed
    }

    /// Normalized listen backlog. # C: O(1)
    pub fn backlog(&self) -> usize { self.state.lock().backlog }

    /// Number of connected clients awaiting accept. # C: O(1)
    pub fn pending_len(&self) -> usize { self.state.lock().accept_q.len() }

    /// Credentials published by the latest successful `listen(2)`.
    /// # C: O(1)
    pub fn owner_cred(&self) -> (u32, u32, u32) { self.state.lock().owner_cred }

    /// Linux listener readiness: readable only while accept can succeed.
    /// Listening sockets are not writable data endpoints. # C: O(1)
    pub fn poll_mask(&self) -> u32 {
        let state = self.state.lock();
        listener_poll_mask(&state)
    }

    /// Pop one pending connection and transfer its GC pin. # C: O(1)
    pub fn accept(&self) -> Result<(Arc<UnixPair>, GcPin), crate::NetError> {
        let mut st = self.state.lock();
        let pair = st.accept_q.pop_front();
        if pair.is_none() && (st.closed || st.receive_shutdown) { return Err(crate::NetError::Einval); }
        #[cfg(target_os = "oxide-kernel")]
        let waiters = if pair.is_some() { core::mem::take(&mut st.connect_sockets) } else { Vec::new() };
        drop(st);
        #[cfg(target_os = "oxide-kernel")]
        wake_connect_sockets(waiters);
        pair.map(|(pair, link)| { let pin = pair.gc_node(UnixEnd::A).pin(); drop(link); (pair, pin) }).ok_or(crate::NetError::Eagain)
    }

    /// Queue a connection unless close or backlog state forbids it.
    /// # C: O(1)
    pub(crate) fn connect_pair(&self, pair: Arc<UnixPair>) -> Result<Arc<UnixPair>, UnixConnectError> {
        let link = self.gc.link(&pair.gc_node(UnixEnd::A));
        let mut st = self.state.lock();
        if st.closed || st.receive_shutdown || !st.listening { return Err(UnixConnectError::Refused); }
        if st.accept_q.len() > st.backlog { return Err(UnixConnectError::Full); }
        let (pid, uid, gid) = st.owner_cred;
        pair.set_end_cred(UnixEnd::A, pid, uid, gid);
        st.accept_q.push_back((pair.clone(), link));
        drop(st);
        #[cfg(target_os = "oxide-kernel")]
        self.accept_waiters.wake_all();
        self.notify_subs();
        Ok(pair)
    }

    /// Atomically queue `pair` and commit the connecting socket state.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub(crate) fn connect_socket(&self, pair: Arc<UnixPair>, sock: &Arc<crate::sock::InetSocket>) -> Result<(), crate::NetError> {
        let link = self.gc.link(&pair.gc_node(UnixEnd::A));
        let mut st = self.state.lock();
        let mut kind = sock.kind.lock();
        match &*kind {
            crate::sock::SockKind::Unix(_, _) => return Err(crate::NetError::Eisconn),
            crate::sock::SockKind::UnixListener(_) => return Err(crate::NetError::Einval),
            crate::sock::SockKind::TcpInit => {}
            _ => return Err(crate::NetError::Einval),
        }
        if st.closed || st.receive_shutdown || !st.listening { return Err(crate::NetError::Econnrefused); }
        if st.accept_q.len() > st.backlog { return Err(crate::NetError::Eagain); }
        let (pid, uid, gid) = st.owner_cred;
        pair.set_end_cred(UnixEnd::A, pid, uid, gid);
        use core::sync::atomic::Ordering::Acquire;
        if sock.read_shut.load(Acquire) { pair.shutdown_reader(UnixEnd::B); }
        if sock.write_shut.load(Acquire) { pair.close_writer(UnixEnd::B); }
        st.accept_q.push_back((pair.clone(), link));
        pair.attach_end_error(UnixEnd::B, &sock.error); *kind = crate::sock::SockKind::Unix(pair, UnixEnd::B);
        drop(kind);
        drop(st);
        self.accept_waiters.wake_all();
        sock.connect_waiters.wake_all();
        self.notify_subs();
        Ok(())
    }

    /// Stop new connects and reset every connected-but-unaccepted client.
    /// # C: O(pending)
    pub fn close(&self) {
        let pending = {
            let mut st = self.state.lock();
            if st.closed { return; }
            st.closed = true;
            st.listening = false;
            let pending = core::mem::take(&mut st.accept_q);
            #[cfg(target_os = "oxide-kernel")]
            let waiters = core::mem::take(&mut st.connect_sockets);
            drop(st);
            #[cfg(target_os = "oxide-kernel")]
            wake_connect_sockets(waiters);
            pending
        };
        for (pair, pin) in pending { pair.abort_unaccepted(); drop(pin); } super::collect_scm_rights();
        #[cfg(target_os = "oxide-kernel")]
        {
            self.accept_waiters.wake_all();
        }
    }

    /// Latch Linux `shutdown(2)` directions without destroying a listener's
    /// pending accept queue. Read shutdown refuses new connects; queued
    /// children remain acceptable until the queue drains. # C: O(1)
    pub fn shutdown(&self, how: crate::uapi::ShutdownHow) {
        let mut state = self.state.lock();
        if how.read() { state.receive_shutdown = true; }
        if how.write() { state.send_shutdown = true; }
        let mask = listener_poll_mask(&state);
        #[cfg(target_os = "oxide-kernel")]
        let wake_accept = state.receive_shutdown;
        drop(state);
        #[cfg(target_os = "oxide-kernel")]
        if wake_accept { self.accept_waiters.wake_all(); }
        self.notify_subs_mask(mask);
    }

    /// Register the listener socket's epoll subscribers (called at listen()).
    /// # C: O(1)
    pub fn register_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Race-free accept park (Linux `prepare_to_wait`): under the `accept_q`
    /// `accept`) or arm the caller on `accept_waiters` and return `true`
    /// (caller MUST `schedule()`). `UnixRegistry::connect` pushes to `accept_q`
    /// UNDER this same lock and only `wake_all`s after dropping it, so a
    /// connect+wake cannot land between the emptiness re-check and the park and
    /// be lost — the missed-wake that stalled socket-activated userdb/userwork
    /// accepts 15–37 s each (tmpfiles-setup-dev-early's 249 s boot stall).
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_accept_wait(&self, deadline_ns: u64) -> bool {
        let st = self.state.lock();
        if !st.accept_q.is_empty() || st.closed || st.receive_shutdown { return false; }
        // SAFETY: process ctx (sys_accept); preempt-off owned by the syscall
        // stub; park_with_deadline marks Sleeping + enqueues on accept_waiters
        // while we hold accept_q — connect() must take accept_q to push, so it
        // cannot wake us before we are enqueued. Lock dropped below; caller
        // owns the schedule().
        unsafe { self.accept_waiters.park_interruptible_with_deadline(deadline_ns); }
        drop(st);
        true
    }

    /// Race-free backlog wait that also rechecks the connecting socket state.
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_socket_connect_wait(&self, sock: &Arc<crate::sock::InetSocket>, deadline_ns: u64) -> bool {
        let mut st = self.state.lock();
        let kind = sock.kind.lock();
        if !matches!(*kind, crate::sock::SockKind::TcpInit)
            || st.closed || st.receive_shutdown || !st.listening || st.accept_q.len() <= st.backlog
        {
            return false;
        }
        st.connect_sockets.push(Arc::downgrade(sock));
        // SAFETY: listener state then socket state is the same order used by
        // connect_socket; capacity changes wake the registered socket queue.
        unsafe { sock.connect_waiters.park_interruptible_with_deadline(deadline_ns); }
        drop(kind);
        drop(st);
        true
    }

    /// Remove one connect-call registration after wake, signal, or timeout.
    /// # C: O(waiters)
    #[cfg(target_os = "oxide-kernel")]
    pub fn unregister_socket_connect_wait(&self, sock: &Arc<crate::sock::InetSocket>) {
        let mut st = self.state.lock();
        if let Some(i) = st.connect_sockets.iter().position(|w| w.as_ptr() == Arc::as_ptr(sock)) {
            st.connect_sockets.remove(i);
        }
    }

    /// Wake epoll waiters on a new pending connection.
    /// # C: O(N_waiters)
    pub fn notify_subs(&self) {
        self.notify_subs_mask(vfs::POLL_IN);
    }

    /// Wake epoll waiters for a listener-owned state transition. # C: O(N_waiters)
    fn notify_subs_mask(&self, mask: u32) {
        if let Some(w) = self.subs.lock().as_ref() {
            if let Some(s) = w.upgrade() {
                s.notify_mask(mask);
            }
        }
    }
}

fn listener_poll_mask(state: &UnixListenerState) -> u32 {
    let mut mask = if state.accept_q.is_empty() { 0 } else { vfs::POLL_IN };
    if state.receive_shutdown { mask |= vfs::POLL_IN | vfs::POLL_RDHUP; }
    if state.receive_shutdown && state.send_shutdown { mask |= vfs::POLL_HUP; }
    mask
}
