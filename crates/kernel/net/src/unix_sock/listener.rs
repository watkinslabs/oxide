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
        let listener = self.lookup_listener(path)?;
        let pair = UnixPair::new();
        listener.accept_q.lock().push_back(pair.clone());
        // F170: wake any blocking accept() parked on this listener.
        #[cfg(target_os = "oxide-kernel")]
        listener.accept_waiters.wake_all();
        // Also wake an epoll_wait-blocked server.
        listener.notify_subs();
        Some(pair)
    }
}
