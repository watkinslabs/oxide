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
    pub path: String,
    pub accept_q: Spinlock<alloc::collections::VecDeque<Arc<UnixPair>>, UnixLockClass>,
    /// F170: per-listener waitlist for `sys_accept`.
    #[cfg(target_os = "oxide-kernel")]
    pub accept_waiters: sched::live::WaitList,
    /// The listener socket's epoll subscribers.
    pub subs: Spinlock<Option<alloc::sync::Weak<vfs::PollSubscribers>>, UnixLockClass>,
}

impl UnixListener {
    /// # C: O(1)
    pub fn new(path: String) -> Arc<Self> {
        Arc::new(Self {
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
    pub(crate) inner: Spinlock<BTreeMap<String, Arc<UnixListener>>, UnixLockClass>,
    /// AF_UNIX SOCK_DGRAM path-bound queues (F121).
    pub(crate) dgrams: Spinlock<BTreeMap<String, Arc<UnixDgramQueue>>, UnixLockClass>,
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
    pub fn dgram_bind(&self, path: String, q: Arc<UnixDgramQueue>) -> Result<(), ()> {
        let mut g = self.dgrams.lock();
        if g.contains_key(&path) {
            return Err(());
        }
        g.insert(path, q);
        Ok(())
    }

    /// Look up a SOCK_DGRAM queue by path.
    /// # C: O(log N)
    pub fn dgram_lookup(&self, path: &str) -> Option<Arc<UnixDgramQueue>> {
        self.dgrams.lock().get(path).cloned()
    }

    /// Insert a listener for `path`. `Eaddrinuse` if already bound.
    /// # C: O(log N)
    pub fn bind(&self, path: String) -> Result<Arc<UnixListener>, ()> {
        let mut g = self.inner.lock();
        if g.contains_key(&path) {
            return Err(());
        }
        let l = UnixListener::new(path.clone());
        g.insert(path, l.clone());
        Ok(l)
    }

    /// Release a bound stream-listener path.
    pub fn unbind(&self, path: &str) {
        self.inner.lock().remove(path);
    }

    /// Release a bound dgram path.
    pub fn dgram_unbind(&self, path: &str) {
        self.dgrams.lock().remove(path);
    }

    /// Look up a bound stream-listener by AF_UNIX address.
    pub fn lookup_listener(&self, addr: &str) -> Option<Arc<UnixListener>> {
        self.inner.lock().get(addr).cloned()
    }

    /// True if `path` is registered as SOCK_STREAM listener or SOCK_DGRAM queue.
    pub fn is_bound(&self, path: &str) -> bool {
        if self.inner.lock().contains_key(path) {
            return true;
        }
        self.dgrams.lock().contains_key(path)
    }

    /// Snapshot all bound paths grouped by kind.
    pub fn snapshot_paths(&self) -> vec::Vec<(u16, String)> {
        let mut out: vec::Vec<(u16, String)> = vec::Vec::new();
        for k in self.inner.lock().keys() {
            out.push((0x0001, k.clone()));
        }
        for k in self.dgrams.lock().keys() {
            out.push((0x0002, k.clone()));
        }
        out
    }

    /// Connect to `path`: allocate a new UnixPair and queue.
    pub fn connect(&self, path: &str) -> Option<Arc<UnixPair>> {
        // DIAG (debug-dbus): log every AF_UNIX connect to a bus socket + whether a
        // listener was found. If mutter (uid 979) can't connect to the system bus
        // (/run/dbus/system_bus_socket), get_session_proxy() returns NULL with no
        // login1 traffic → "Failed to find any matching session".
        #[cfg(feature = "debug-dbus")]
        if path.as_bytes().windows(3).any(|w| w == b"bus") {
            let found = self.lookup_listener(path).is_some();
            klog::write_raw(b"[DBUSCONN t=");
            if let Some(c) = sched::live::current() {
                klog::write_dec_u64(c.tid as u64);
                klog::write_raw(b" ");
                klog::write_raw(c.name.as_bytes());
            }
            klog::write_raw(if found { b" OK " } else { b" REFUSED " });
            klog::write_raw(path.as_bytes());
            klog::write_raw(b"\n");
        }
        let listener = self.lookup_listener(path)?;
        let pair = UnixPair::new();
        #[cfg(feature = "debug-dbus")]
        {
            let nm = sched::live::current().and_then(|c| unsafe { (*c.exe_path.get()).as_ref().map(|s| s.clone()) }).unwrap_or_default();
            klog::write_raw(b"[UXCONNECT comm="); klog::write_raw(nm.as_bytes());
            klog::write_raw(b" pair="); klog::write_hex_u64(alloc::sync::Arc::as_ptr(&pair) as u64);
            klog::write_raw(b" path="); klog::write_raw(path.as_bytes());
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
}
