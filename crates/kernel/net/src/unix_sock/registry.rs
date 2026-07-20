//! AF_UNIX path registry for stream listeners and datagram queues.

use alloc::{collections::BTreeMap, string::String, sync::Arc, vec, vec::Vec};

use sync::{Socket as UnixLockClass, Spinlock};

use super::{UnixAddr, UnixAddrKey, UnixConnectError, UnixDgramQueue, UnixListener, UnixPair};
#[cfg(feature = "debug-dbus")]
use sched;

/// Process-global path → listener registry.
pub struct UnixRegistry {
    pub(crate) inner: Spinlock<BTreeMap<UnixAddrKey, Arc<UnixListener>>, UnixLockClass>,
    /// AF_UNIX SOCK_DGRAM path-bound queues (F121).
    pub(crate) dgrams: Spinlock<BTreeMap<UnixAddrKey, (Vec<u8>, Arc<UnixDgramQueue>)>, UnixLockClass>,
}

/// Linux AF_UNIX abstract namespace addresses are keyed by a leading NUL byte. # C: O(1)
pub fn unix_path_is_abstract<P: AsRef<[u8]>>(path: P) -> bool { path.as_ref().first().copied() == Some(0) }

/// Render a registry key the way `/proc/net/unix` reports it. # C: O(N)
pub fn unix_path_display<P: AsRef<[u8]>>(path: P) -> Vec<u8> {
    let path = path.as_ref();
    if unix_path_is_abstract(path) {
        let mut out = Vec::with_capacity(path.len());
        out.push(b'@');
        out.extend_from_slice(&path[1..]);
        out
    } else { path.to_vec() }
}

impl UnixRegistry {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { inner: Spinlock::new(BTreeMap::new()), dgrams: Spinlock::new(BTreeMap::new()) }
    }

    /// Bind a SOCK_DGRAM socket's queue to `path`. Eaddrinuse if already bound. # C: O(log N)
    pub fn dgram_bind_addr(&self, addr: UnixAddr, q: Arc<UnixDgramQueue>) -> Result<(), ()> {
        let mut g = self.dgrams.lock();
        if g.contains_key(&addr.key) { return Err(()); }
        g.insert(addr.key, (addr.display, q));
        Ok(())
    }

    /// Bind a SOCK_DGRAM socket's queue to `path`. Eaddrinuse if already bound. # C: O(log N)
    pub fn dgram_bind(&self, path: String, q: Arc<UnixDgramQueue>) -> Result<(), ()> {
        self.dgram_bind_addr(UnixAddr::from_abstract_or_test_path(path), q)
    }

    /// Look up a SOCK_DGRAM queue by address. # C: O(log N)
    pub fn dgram_lookup_addr(&self, addr: &UnixAddr) -> Option<Arc<UnixDgramQueue>> {
        self.dgrams.lock().get(&addr.key).map(|(_, q)| q.clone())
    }

    /// Look up a SOCK_DGRAM queue by path. # C: O(log N)
    pub fn dgram_lookup(&self, path: &str) -> Option<Arc<UnixDgramQueue>> {
        self.dgram_lookup_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)))
    }

    /// Insert a listener for `path`. `Eaddrinuse` if already bound. # C: O(log N)
    pub fn bind_addr(&self, addr: UnixAddr) -> Result<Arc<UnixListener>, ()> {
        let mut g = self.inner.lock();
        if g.contains_key(&addr.key) { return Err(()); }
        let listener = UnixListener::new(addr.clone());
        g.insert(addr.key, listener.clone());
        Ok(listener)
    }

    /// Insert a listener for `path`. `Eaddrinuse` if already bound. # C: O(log N)
    pub fn bind(&self, path: String) -> Result<Arc<UnixListener>, ()> {
        self.bind_addr(UnixAddr::from_abstract_or_test_path(path))
    }

    /// Release a bound stream-listener path. # C: O(log N)
    pub fn unbind_addr(&self, addr: &UnixAddr) {
        if let Some(listener) = self.inner.lock().remove(&addr.key) { listener.close(); }
    }

    /// Remove a pathname rendezvous while leaving an open listener alive. # C: O(log N)
    pub fn unlink_addr(&self, addr: &UnixAddr) { self.inner.lock().remove(&addr.key); }

    /// Release a bound stream-listener path. # C: O(log N)
    pub fn unbind(&self, path: &str) { self.unbind_addr(&UnixAddr::from_abstract_or_test_path(String::from(path))); }

    /// Release a bound dgram path. # C: O(log N)
    pub fn dgram_unbind_addr(&self, addr: &UnixAddr) { self.dgrams.lock().remove(&addr.key); }

    /// Release a bound dgram path. # C: O(log N)
    pub fn dgram_unbind(&self, path: &str) { self.dgram_unbind_addr(&UnixAddr::from_abstract_or_test_path(String::from(path))); }

    /// Look up a bound stream-listener by AF_UNIX address. # C: O(log N)
    pub fn lookup_listener_addr(&self, addr: &UnixAddr) -> Option<Arc<UnixListener>> {
        self.inner.lock().get(&addr.key).cloned()
    }

    /// Look up a bound stream-listener by AF_UNIX address. # C: O(log N)
    pub fn lookup_listener(&self, addr: &str) -> Option<Arc<UnixListener>> {
        self.lookup_listener_addr(&UnixAddr::from_abstract_or_test_path(String::from(addr)))
    }

    /// True if `path` is registered as SOCK_STREAM listener or SOCK_DGRAM queue. # C: O(log N)
    pub fn is_bound(&self, path: &str) -> bool {
        self.is_bound_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)))
    }

    /// True if `addr` is registered as SOCK_STREAM listener or SOCK_DGRAM queue. # C: O(log N)
    pub fn is_bound_addr(&self, addr: &UnixAddr) -> bool {
        if self.inner.lock().contains_key(&addr.key) { return true; }
        self.dgrams.lock().contains_key(&addr.key)
    }

    /// Snapshot all bound paths grouped by kind. # C: O(N)
    pub fn snapshot_paths(&self) -> vec::Vec<(u16, Vec<u8>)> {
        let mut out: vec::Vec<(u16, Vec<u8>)> = vec::Vec::new();
        for listener in self.inner.lock().values() { out.push((0x0001, listener.path.clone())); }
        for (_, (path, _)) in self.dgrams.lock().iter() { out.push((0x0002, path.clone())); }
        out
    }

    /// Connect to `path`: allocate a new UnixPair and queue. # C: O(log N)
    pub fn connect_addr(&self, addr: &UnixAddr) -> Result<Arc<UnixPair>, UnixConnectError> {
        self.connect_pair_addr(addr, UnixPair::new())
    }

    /// Queue a caller-initialized pair only after credentials/subscriptions are complete. # C: O(log N)
    pub fn connect_pair_addr(&self, addr: &UnixAddr, pair: Arc<UnixPair>) -> Result<Arc<UnixPair>, UnixConnectError> {
        #[cfg(feature = "debug-dbus")]
        if addr.display.windows(3).any(|window| window == b"bus") {
            let found = self.lookup_listener_addr(addr).map(|listener| listener.is_listening()).unwrap_or(false);
            klog::write_raw(b"[DBUSCONN t=");
            if let Some(current) = sched::live::current() {
                klog::write_dec_u64(current.tid as u64);
                klog::write_raw(b" ");
                klog::write_raw(current.name.as_bytes());
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
            let name = sched::live::current().and_then(|current| {
                // SAFETY: current task owns exe_path mutation while this debug-only
                // trace takes a short immutable snapshot in process context.
                unsafe { (*current.exe_path.get()).as_ref().map(|path| path.clone()) }
            }).unwrap_or_default();
            klog::write_raw(b"[UXCONNECT comm="); klog::write_raw(name.as_bytes());
            klog::write_raw(b" pair="); klog::write_hex_u64(Arc::as_ptr(&pair) as u64);
            klog::write_raw(b" path="); klog::write_raw(&addr.display);
            klog::write_raw(b"]\n");
        }
        Ok(pair)
    }

    /// Connect to `path`: allocate a new UnixPair and queue. # C: O(log N)
    pub fn connect(&self, path: &str) -> Result<Arc<UnixPair>, UnixConnectError> {
        self.connect_addr(&UnixAddr::from_abstract_or_test_path(String::from(path)))
    }
}
