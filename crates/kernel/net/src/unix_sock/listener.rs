use alloc::{collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};
use sched;

use super::UnixDgramQueue;
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
        if self.state.lock().accept_q.is_empty() { 0 } else { vfs::POLL_IN }
    }

    /// Pop one pending connection and transfer its GC pin. # C: O(1)
    pub fn accept(&self) -> Result<(Arc<UnixPair>, GcPin), crate::NetError> {
        let mut st = self.state.lock();
        let pair = st.accept_q.pop_front();
        if pair.is_none() && st.closed { return Err(crate::NetError::Einval); }
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
        if st.closed || !st.listening { return Err(UnixConnectError::Refused); }
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
        if st.closed || !st.listening { return Err(crate::NetError::Econnrefused); }
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
        if !st.accept_q.is_empty() || st.closed { return false; }
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
            || st.closed || !st.listening || st.accept_q.len() <= st.backlog
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
        if let Some(w) = self.subs.lock().as_ref() {
            if let Some(s) = w.upgrade() {
                s.notify_mask(vfs::POLL_IN);
            }
        }
    }
}

/// Process-global path → listener registry.
pub struct UnixRegistry {
    pub(crate) inner: Spinlock<BTreeMap<UnixAddrKey, Arc<UnixListener>>, UnixLockClass>,
    /// AF_UNIX SOCK_DGRAM path-bound queues (F121).
    pub(crate) dgrams: Spinlock<BTreeMap<UnixAddrKey, (Vec<u8>, Arc<UnixDgramQueue>)>, UnixLockClass>,
}

/// Linux AF_UNIX abstract namespace addresses are keyed by a leading
/// NUL byte, not by a filesystem pathname.
pub fn unix_path_is_abstract<P: AsRef<[u8]>>(path: P) -> bool {
    path.as_ref().first().copied() == Some(0)
}

/// Render a registry key the way `/proc/net/unix` reports it.
pub fn unix_path_display<P: AsRef<[u8]>>(path: P) -> Vec<u8> {
    let path = path.as_ref();
    if unix_path_is_abstract(path) {
        let mut out = Vec::with_capacity(path.len());
        out.push(b'@');
        out.extend_from_slice(&path[1..]);
        out
    } else {
        path.to_vec()
    }
}

impl UnixRegistry {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self {
            inner: Spinlock::new(BTreeMap::new()),
            dgrams: Spinlock::new(BTreeMap::new()),
        }
    }

    /// Bind a SOCK_DGRAM socket's queue to `path`. Eaddrinuse if already bound.
    /// # C: O(log N)
    pub fn dgram_bind_addr(&self, addr: UnixAddr, q: Arc<UnixDgramQueue>) -> Result<(), ()> {
        let mut g = self.dgrams.lock();
        if g.contains_key(&addr.key) {
            return Err(());
        }
        g.insert(addr.key, (addr.display, q));
        Ok(())
    }

    /// Bind a SOCK_DGRAM socket's queue to `path`. Eaddrinuse if already bound.
    /// # C: O(log N)
    pub fn dgram_bind(&self, path: String, q: Arc<UnixDgramQueue>) -> Result<(), ()> {
        self.dgram_bind_addr(UnixAddr::from_abstract_or_test_path(path), q)
    }

    /// Look up a SOCK_DGRAM queue by address.
    /// # C: O(log N)
    pub fn dgram_lookup_addr(&self, addr: &UnixAddr) -> Option<Arc<UnixDgramQueue>> {
        self.dgrams.lock().get(&addr.key).map(|(_, q)| q.clone())
    }

    /// Look up a SOCK_DGRAM queue by path.
    /// # C: O(log N)
    pub fn dgram_lookup(&self, path: &str) -> Option<Arc<UnixDgramQueue>> {
        self.dgram_lookup_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)))
    }

    /// Insert a listener for `path`. `Eaddrinuse` if already bound.
    /// # C: O(log N)
    pub fn bind_addr(&self, addr: UnixAddr) -> Result<Arc<UnixListener>, ()> {
        let mut g = self.inner.lock();
        if g.contains_key(&addr.key) {
            return Err(());
        }
        let l = UnixListener::new(addr.clone());
        g.insert(addr.key, l.clone());
        Ok(l)
    }

    /// Insert a listener for `path`. `Eaddrinuse` if already bound.
    /// # C: O(log N)
    pub fn bind(&self, path: String) -> Result<Arc<UnixListener>, ()> {
        self.bind_addr(UnixAddr::from_abstract_or_test_path(path))
    }

    /// Release a bound stream-listener path.
    pub fn unbind_addr(&self, addr: &UnixAddr) {
        let listener = self.inner.lock().remove(&addr.key);
        if let Some(listener) = listener { listener.close(); }
    }

    /// Remove a pathname rendezvous while leaving an open listener alive.
    /// # C: O(log N)
    pub fn unlink_addr(&self, addr: &UnixAddr) {
        self.inner.lock().remove(&addr.key);
    }

    /// Release a bound stream-listener path.
    pub fn unbind(&self, path: &str) {
        self.unbind_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)));
    }

    /// Release a bound dgram path.
    pub fn dgram_unbind_addr(&self, addr: &UnixAddr) {
        self.dgrams.lock().remove(&addr.key);
    }

    /// Release a bound dgram path.
    pub fn dgram_unbind(&self, path: &str) {
        self.dgram_unbind_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)));
    }

    /// Look up a bound stream-listener by AF_UNIX address.
    pub fn lookup_listener_addr(&self, addr: &UnixAddr) -> Option<Arc<UnixListener>> {
        self.inner.lock().get(&addr.key).cloned()
    }

    /// Look up a bound stream-listener by AF_UNIX address.
    pub fn lookup_listener(&self, addr: &str) -> Option<Arc<UnixListener>> {
        self.lookup_listener_addr(&UnixAddr::from_abstract_or_test_path(String::from(addr)))
    }

    /// True if `path` is registered as SOCK_STREAM listener or SOCK_DGRAM queue.
    pub fn is_bound(&self, path: &str) -> bool {
        let addr = UnixAddr::from_abstract_or_test_path(String::from(path));
        if self.inner.lock().contains_key(&addr.key) {
            return true;
        }
        self.dgrams.lock().contains_key(&addr.key)
    }

    /// True if `addr` is registered as SOCK_STREAM listener or SOCK_DGRAM queue.
    pub fn is_bound_addr(&self, addr: &UnixAddr) -> bool {
        if self.inner.lock().contains_key(&addr.key) {
            return true;
        }
        self.dgrams.lock().contains_key(&addr.key)
    }

    /// Snapshot all bound paths grouped by kind.
    pub fn snapshot_paths(&self) -> vec::Vec<(u16, Vec<u8>)> {
        let mut out: vec::Vec<(u16, Vec<u8>)> = vec::Vec::new();
        for v in self.inner.lock().values() {
            out.push((0x0001, v.path.clone()));
        }
        for (_, (path, _)) in self.dgrams.lock().iter() {
            out.push((0x0002, path.clone()));
        }
        out
    }

    /// Connect to `path`: allocate a new UnixPair and queue.
    pub fn connect_addr(&self, addr: &UnixAddr) -> Result<Arc<UnixPair>, UnixConnectError> {
        let pair = UnixPair::new();
        self.connect_pair_addr(addr, pair)
    }

    /// Queue a caller-initialized pair only after credentials/subscriptions
    /// are complete, so `accept(2)` cannot observe a partial endpoint.
    /// # C: O(log N)
    pub fn connect_pair_addr(&self, addr: &UnixAddr, pair: Arc<UnixPair>) -> Result<Arc<UnixPair>, UnixConnectError> {
        // DIAG (debug-dbus): log every AF_UNIX connect to a bus socket + whether a
        // listener was found. If mutter (uid 979) can't connect to the system bus
        // (/run/dbus/system_bus_socket), get_session_proxy() returns NULL with no
        // login1 traffic → "Failed to find any matching session".
        #[cfg(feature = "debug-dbus")]
        if addr.display.windows(3).any(|w| w == b"bus") {
            let found = self.lookup_listener_addr(addr).map(|l| l.is_listening()).unwrap_or(false);
            klog::write_raw(b"[DBUSCONN t=");
            if let Some(c) = sched::live::current() {
                klog::write_dec_u64(c.tid as u64);
                klog::write_raw(b" ");
                klog::write_raw(c.name.as_bytes());
            }
            klog::write_raw(if found { b" OK " } else { b" REFUSED " });
            klog::write_raw(&addr.display);
            klog::write_raw(b"\n");
        }
        let listener = self.lookup_listener_addr(addr).ok_or(UnixConnectError::Refused)?;
        pair.set_bind_path(listener.path.clone());
        let pair = listener.connect_pair(pair)?;
        #[cfg(feature = "debug-dbus")]
        {
            let nm = sched::live::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.clone()) }).unwrap_or_default();
            klog::write_raw(b"[UXCONNECT comm="); klog::write_raw(nm.as_bytes());
            klog::write_raw(b" pair="); klog::write_hex_u64(alloc::sync::Arc::as_ptr(&pair) as u64);
            klog::write_raw(b" path="); klog::write_raw(&addr.display);
            klog::write_raw(b"]\n");
        }
        Ok(pair)
    }

    /// Connect to `path`: allocate a new UnixPair and queue.
    pub fn connect(&self, path: &str) -> Result<Arc<UnixPair>, UnixConnectError> {
        self.connect_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)))
    }
}
