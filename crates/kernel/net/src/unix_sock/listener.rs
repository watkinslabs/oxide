use alloc::{collections::BTreeMap, string::String, sync::Arc, vec};

use sync::{Socket as UnixLockClass, Spinlock};
use sched;

use super::UnixDgramQueue;
use super::UnixPair;
use vfs;

/// AF_UNIX path-bound listener. `bind(path)` inserts one into
/// `UnixRegistry`; `connect(path)` looks it up + allocates a
/// fresh `UnixPair`, queues the listener's-side handle into the
/// listener's accept queue.
pub struct UnixListener {
    pub addr: UnixAddr,
    pub path: String,
    pub accept_q: Spinlock<alloc::collections::VecDeque<Arc<UnixPair>>, UnixLockClass>,
    /// F170: per-listener waitlist for `sys_accept`.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
    /// The listener socket's epoll subscribers.
    pub subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub enum UnixAddrKey {
    Abstract(String),
    Path { fsid: u64, ino: u64 },
}

#[derive(Clone)]
pub struct UnixAddr {
    pub key: UnixAddrKey,
    pub display: String,
}

impl UnixAddr {
    /// # C: O(N path)
    pub fn from_abstract_or_test_path(path: String) -> Self {
        if unix_path_is_abstract(&path) {
            Self { key: UnixAddrKey::Abstract(path.clone()), display: path }
        } else {
            Self { key: UnixAddrKey::Abstract(path.clone()), display: path }
        }
    }

    /// # C: O(1)
    pub fn from_inode(display: String, inode: &vfs::InodeRef) -> Self {
        Self { key: UnixAddrKey::Path { fsid: inode.fsid(), ino: inode.ino() as u64 }, display }
    }

    /// # C: O(N path)
    pub fn from_sockaddr_path(path: String) -> Self {
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
            accept_q: Spinlock::new(alloc::collections::VecDeque::new()),
            #[cfg(target_os = "oxide-kernel")]
            accept_waiters: sched::live::WaitList::new(),
            subs: Spinlock::new(None),
        })
    }

    /// Register the listener socket's epoll subscribers (called at listen()).
    /// # C: O(1)
    pub fn register_subs(&self, subs: &Arc<vfs::PollSubscribers>) {
        *self.subs.lock() = Some(Arc::downgrade(subs));
    }

    /// Race-free accept park (Linux `prepare_to_wait`): under the `accept_q`
    /// lock, either observe a queued connection (return `false`, caller retries
    /// `accept`) or arm the caller on `accept_waiters` and return `true`
    /// (caller MUST `schedule()`). `UnixRegistry::connect` pushes to `accept_q`
    /// UNDER this same lock and only `wake_all`s after dropping it, so a
    /// connect+wake cannot land between the emptiness re-check and the park and
    /// be lost — the missed-wake that stalled socket-activated userdb/userwork
    /// accepts 15–37 s each (tmpfiles-setup-dev-early's 249 s boot stall).
    /// # C: O(1)
    #[cfg(target_os = "oxide-kernel")]
    pub fn arm_accept_wait(&self, deadline_ns: u64) -> bool {
        let q = self.accept_q.lock();
        if !q.is_empty() { return false; }
        // SAFETY: process ctx (sys_accept); preempt-off owned by the syscall
        // stub; park_with_deadline marks Sleeping + enqueues on accept_waiters
        // while we hold accept_q — connect() must take accept_q to push, so it
        // cannot wake us before we are enqueued. Lock dropped below; caller
        // owns the schedule().
        unsafe { self.accept_waiters.park_with_deadline(deadline_ns); }
        drop(q);
        true
    }

    /// Wake epoll waiters on a new pending connection.
    /// # C: O(N_waiters)
    pub fn notify_subs(&self) {
        if let Some(w) = self.subs.lock().as_ref() {
            if let Some(s) = w.upgrade() {
                s.notify();
            }
        }
    }
}

/// Process-global path → listener registry.
pub struct UnixRegistry {
    pub(crate) inner: Spinlock<BTreeMap<UnixAddrKey, Arc<UnixListener>>, UnixLockClass>,
    /// AF_UNIX SOCK_DGRAM path-bound queues (F121).
    pub(crate) dgrams: Spinlock<BTreeMap<UnixAddrKey, (String, Arc<UnixDgramQueue>)>, UnixLockClass>,
}

/// Linux AF_UNIX abstract namespace addresses are keyed by a leading
/// NUL byte, not by a filesystem pathname.
pub fn unix_path_is_abstract(path: &str) -> bool {
    path.as_bytes().first().copied() == Some(0)
}

/// Render a registry key the way `/proc/net/unix` reports it.
pub fn unix_path_display(path: &str) -> String {
    if unix_path_is_abstract(path) {
        let mut out = String::from("@");
        out.push_str(core::str::from_utf8(&path.as_bytes()[1..]).unwrap_or(""));
        out
    } else {
        path.into()
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
    pub fn snapshot_paths(&self) -> vec::Vec<(u16, String)> {
        let mut out: vec::Vec<(u16, String)> = vec::Vec::new();
        for v in self.inner.lock().values() {
            out.push((0x0001, v.path.clone()));
        }
        for (_, (path, _)) in self.dgrams.lock().iter() {
            out.push((0x0002, path.clone()));
        }
        out
    }

    /// Connect to `path`: allocate a new UnixPair and queue.
    pub fn connect_addr(&self, addr: &UnixAddr) -> Option<Arc<UnixPair>> {
        // DIAG (debug-dbus): log every AF_UNIX connect to a bus socket + whether a
        // listener was found. If mutter (uid 979) can't connect to the system bus
        // (/run/dbus/system_bus_socket), get_session_proxy() returns NULL with no
        // login1 traffic → "Failed to find any matching session".
        #[cfg(feature = "debug-dbus")]
        if addr.display.as_bytes().windows(3).any(|w| w == b"bus") {
            let found = self.lookup_listener_addr(addr).is_some();
            klog::write_raw(b"[DBUSCONN t=");
            if let Some(c) = sched::live::current() {
                klog::write_dec_u64(c.tid as u64);
                klog::write_raw(b" ");
                klog::write_raw(c.name.as_bytes());
            }
            klog::write_raw(if found { b" OK " } else { b" REFUSED " });
            klog::write_raw(addr.display.as_bytes());
            klog::write_raw(b"\n");
        }
        let listener = self.lookup_listener_addr(addr)?;
        let pair = UnixPair::new();
        #[cfg(feature = "debug-dbus")]
        {
            let nm = sched::live::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.clone()) }).unwrap_or_default();
            klog::write_raw(b"[UXCONNECT comm="); klog::write_raw(nm.as_bytes());
            klog::write_raw(b" pair="); klog::write_hex_u64(alloc::sync::Arc::as_ptr(&pair) as u64);
            klog::write_raw(b" path="); klog::write_raw(addr.display.as_bytes());
            klog::write_raw(b"]\n");
        }
        // Retain the listener's canonical bound path so getsockname (end A,
        // the accepted server socket) and getpeername (end B, the client)
        // report the real sun_path — e.g. "/run/systemd/private".
        pair.set_bind_path(listener.path.clone());
        listener.accept_q.lock().push_back(pair.clone());
        // F170: wake any blocking accept() parked on this listener.
        #[cfg(target_os = "oxide-kernel")]
        listener.accept_waiters.wake_all();
        // Also wake an epoll_wait-blocked server.
        listener.notify_subs();
        Some(pair)
    }

    /// Connect to `path`: allocate a new UnixPair and queue.
    pub fn connect(&self, path: &str) -> Option<Arc<UnixPair>> {
        self.connect_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)))
    }
}
