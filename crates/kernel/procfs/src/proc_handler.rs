//! Linux `proc_handler` model: the per-leaf binding that
//! ties a `/proc/sys/*` file to its **live kernel variable** (the ctl_table
//! `data`/`extra1`/`extra2`). A read FORMATS the live variable; a write PARSES
//! + range-checks (against `extra1`/`extra2` min/max) + UPDATES the live
//! variable — instead of returning a fixed default string and dropping writes.
//!
//! Implements integer, string, and retained-network-namespace handlers.
//!
//! Backing-variable policy (D22): a leaf whose backing kernel variable EXISTS
//! in-tree binds to it (`StrHook`); a leaf whose backing does NOT exist gets a
//! procfs-OWNED live cell (`IntVar`/`ULongVar` over a `Box::leak`ed atomic) — a
//! real read/write variable, NOT a fake constant.
//!
//! Kept un-`cfg`-gated (like `proc_dointvec`) so the read-format / write-parse /
//! bounds contract is covered by `cargo test -p procfs` on the host.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use network_namespace::NetworkNamespaceRef;
use namespace_identity::NamespaceRef;
use vfs::{KResult, VfsError};

/// One `/proc/sys` leaf's `proc_handler`: format the live value on read, and
/// parse+validate+store it on write. `Err(())` → `EINVAL` (Linux rejects a
/// non-numeric / out-of-range write before it touches the variable).
pub trait ProcHandler: Send + Sync {
    /// Format the CURRENT live value (read path). # C: O(1)
    fn format(&self) -> Vec<u8>;
    /// Parse + validate `src` and UPDATE the live variable (write path).
    /// # C: O(len)
    fn store(&self, src: &[u8]) -> Result<(), ()>;
    /// Preserve a handler-specific VFS error when policy distinguishes EPERM
    /// from malformed-value EINVAL. # C: O(len)
    fn store_vfs(&self, src: &[u8]) -> KResult<()> {
        self.store(src).map_err(|_| VfsError::Einval)
    }
    /// Capture open-time state for handlers whose backing depends on the
    /// opener. `None` keeps using this inode-bound handler. # C: O(1)
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> { None }
    /// Whether the leaf accepts writes (mode 0644 vs read-only 0444).
    /// # C: O(1)
    fn writable(&self) -> bool { true }
    /// Whether the value is a secret, so the file is readable only by its
    /// owner (mode 0600) rather than world-readable. # C: O(1)
    fn owner_only(&self) -> bool { false }
}

/// Per-network-namespace fallible integer binding. `current_ns` runs once at
/// open; the returned handler carries that namespace for its lifetime.
pub struct PerNetIntHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub key: usize,
    pub get: fn(&NetworkNamespaceRef, usize) -> Result<i64, ()>,
    pub set: fn(&NetworkNamespaceRef, usize, i64) -> Result<(), ()>,
    pub bounds: Option<(i64, i64)>,
}
struct BoundPerNetIntHook {
    namespace: NetworkNamespaceRef,
    key: usize,
    get: fn(&NetworkNamespaceRef, usize) -> Result<i64, ()>,
    set: fn(&NetworkNamespaceRef, usize, i64) -> Result<(), ()>,
    bounds: Option<(i64, i64)>,
}
impl ProcHandler for PerNetIntHook {
    fn format(&self) -> Vec<u8> {
        fmt_i64((self.get)(&(self.current_ns)(), self.key)
            .expect("live network namespace sysctl state"))
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_bound_i64(&(self.current_ns)(), self.key, self.set, self.bounds, src)
    }
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> {
        Some(Arc::new(BoundPerNetIntHook {
            namespace: (self.current_ns)(), key: self.key, get: self.get,
            set: self.set, bounds: self.bounds,
        }))
    }
}
impl ProcHandler for BoundPerNetIntHook {
    fn format(&self) -> Vec<u8> {
        fmt_i64((self.get)(&self.namespace, self.key)
            .expect("retained network namespace sysctl state"))
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_bound_i64(&self.namespace, self.key, self.set, self.bounds, src)
    }
}

fn store_bound_i64(namespace: &NetworkNamespaceRef, key: usize,
    set: fn(&NetworkNamespaceRef, usize, i64) -> Result<(), ()>,
    bounds: Option<(i64, i64)>, src: &[u8]) -> Result<(), ()>
{
    let value = parse_single_i64(src)?;
    if let Some((min, max)) = bounds { if value < min || value > max { return Err(()); } }
    set(namespace, key, value)
}

/// A `net/core` leaf whose backing variable is GLOBAL, not per-namespace: the
/// value is shared by every network namespace and only the initial one may
/// write it. A write from any other namespace is refused, which is what a
/// caller in a container observes.
pub struct NetGlobalIntHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub get: fn() -> i64,
    pub set: fn(i64),
    pub bounds: Option<(i64, i64)>,
}

impl NetGlobalIntHook {
    /// # C: O(1)
    fn writer_is_initial(&self) -> bool {
        (self.current_ns)().id() == network_namespace::initial().id()
    }
}

impl ProcHandler for NetGlobalIntHook {
    fn format(&self) -> Vec<u8> { fmt_i64((self.get)()) }
    fn store(&self, src: &[u8]) -> Result<(), ()> { self.store_vfs(src).map_err(|_| ()) }
    fn store_vfs(&self, src: &[u8]) -> KResult<()> {
        if !self.writer_is_initial() { return Err(VfsError::Eacces); }
        let value = parse_single_i64(src).map_err(|_| VfsError::Einval)?;
        if let Some((min, max)) = self.bounds {
            if value < min || value > max { return Err(VfsError::Einval); }
        }
        (self.set)(value);
        Ok(())
    }
}

/// Current-PID-namespace integer binding. Linux's handler resolves
/// `task_active_pid_ns(current)` on each read/write, while a fallible setter
/// preserves its EPERM policy result.
pub struct PerPidIntHook {
    pub current_ns: fn() -> NamespaceRef,
    pub check_write: fn(&NamespaceRef) -> KResult<()>,
    pub get: fn(&NamespaceRef) -> Result<i64, ()>,
    pub set: fn(&NamespaceRef, i64) -> KResult<()>,
    pub bounds: Option<(i64, i64)>,
}
impl ProcHandler for PerPidIntHook {
    fn format(&self) -> Vec<u8> {
        fmt_i64((self.get)(&(self.current_ns)()).expect("live PID namespace sysctl state"))
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        self.store_vfs(src).map_err(|_| ())
    }
    fn store_vfs(&self, src: &[u8]) -> KResult<()> {
        store_pid_i64(&(self.current_ns)(), self.check_write, self.set, self.bounds, src)
    }
}

fn store_pid_i64(namespace: &NamespaceRef,
    check_write: fn(&NamespaceRef) -> KResult<()>,
    set: fn(&NamespaceRef, i64) -> KResult<()>, bounds: Option<(i64, i64)>,
    src: &[u8]) -> KResult<()>
{
    check_write(namespace)?;
    let value = parse_single_i64(src).map_err(|_| VfsError::Einval)?;
    if let Some((min, max)) = bounds {
        if value < min || value > max { return Err(VfsError::Einval); }
    }
    set(namespace, value)
}

/// Per-network-namespace two-u16 vector binding. One-field writes preserve the
/// captured namespace's second field, matching `proc_dointvec` partial writes.
pub struct PerNetU16PairHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub get: fn(&NetworkNamespaceRef) -> Result<(u16, u16), ()>,
    pub set: fn(&NetworkNamespaceRef, u16, u16) -> Result<(), ()>,
}
struct BoundPerNetU16PairHook {
    namespace: NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> Result<(u16, u16), ()>,
    set: fn(&NetworkNamespaceRef, u16, u16) -> Result<(), ()>,
}
impl ProcHandler for PerNetU16PairHook {
    fn format(&self) -> Vec<u8> {
        format_u16_pair((self.get)(&(self.current_ns)())
            .expect("live network namespace port state"))
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_u16_pair(&(self.current_ns)(), self.get, self.set, src)
    }
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> {
        Some(Arc::new(BoundPerNetU16PairHook {
            namespace: (self.current_ns)(), get: self.get, set: self.set,
        }))
    }
}
impl ProcHandler for BoundPerNetU16PairHook {
    fn format(&self) -> Vec<u8> {
        format_u16_pair((self.get)(&self.namespace)
            .expect("retained network namespace port state"))
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_u16_pair(&self.namespace, self.get, self.set, src)
    }
}

/// Per-network-namespace group-window binding. The parse, the reserved-invalid
/// group screen, and the inverted-window reset all belong to the subsystem that
/// owns the window, so this handler never re-decides them.
pub struct PerNetGroupRangeHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub get: fn(&NetworkNamespaceRef) -> Result<(u32, u32), ()>,
    pub set: fn(&NetworkNamespaceRef, u32, u32) -> Result<(), ()>,
}
struct BoundPerNetGroupRangeHook {
    namespace: NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> Result<(u32, u32), ()>,
    set: fn(&NetworkNamespaceRef, u32, u32) -> Result<(), ()>,
}
impl ProcHandler for PerNetGroupRangeHook {
    fn format(&self) -> Vec<u8> {
        net::ping::group::format((self.get)(&(self.current_ns)())
            .expect("live network namespace group window"))
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_group_range(&(self.current_ns)(), self.get, self.set, src)
    }
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> {
        Some(Arc::new(BoundPerNetGroupRangeHook {
            namespace: (self.current_ns)(), get: self.get, set: self.set,
        }))
    }
}
impl ProcHandler for BoundPerNetGroupRangeHook {
    fn format(&self) -> Vec<u8> {
        net::ping::group::format((self.get)(&self.namespace)
            .expect("retained network namespace group window"))
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_group_range(&self.namespace, self.get, self.set, src)
    }
}

fn store_group_range(namespace: &NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> Result<(u32, u32), ()>,
    set: fn(&NetworkNamespaceRef, u32, u32) -> Result<(), ()>, src: &[u8]) -> Result<(), ()>
{
    let live = get(namespace)?;
    let Some((low, high)) = net::ping::group::parse_write(src, live)? else { return Ok(()) };
    match net::ping::group::validate(low, high) {
        net::ping::group::RangeWrite::Accept(low, high) => set(namespace, low, high),
        net::ping::group::RangeWrite::Invalid => Err(()),
    }
}

fn format_u16_pair(pair: (u16, u16)) -> Vec<u8> {
    alloc::format!("{}\t{}\n", pair.0, pair.1).into_bytes()
}

fn store_u16_pair(namespace: &NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> Result<(u16, u16), ()>,
    set: fn(&NetworkNamespaceRef, u16, u16) -> Result<(), ()>, src: &[u8]) -> Result<(), ()>
{
    let text = core::str::from_utf8(src).map_err(|_| ())?;
    let mut fields = text.split_whitespace();
    let first = fields.next().ok_or(())?.parse::<u16>().map_err(|_| ())?;
    let second = match fields.next() {
        Some(value) => value.parse::<u16>().map_err(|_| ())?,
        None => get(namespace)?.1,
    };
    if fields.next().is_some() { return Err(()); }
    set(namespace, first, second)
}

/// Format a signed decimal with a trailing newline (Linux `proc_dointvec`
/// output). # C: O(1)
fn fmt_i64(v: i64) -> Vec<u8> {
    let mut s = alloc::format!("{v}\n").into_bytes();
    s.shrink_to_fit();
    s
}
/// Format an unsigned decimal with a trailing newline. # C: O(1)
fn fmt_u64(v: u64) -> Vec<u8> { alloc::format!("{v}\n").into_bytes() }

/// Parse the SINGLE signed-decimal value a `proc_dointvec` leaf carries
/// (leading/trailing whitespace stripped). Exactly one token, decimal, in
/// `i64` range — else `Err(())`. # C: O(len)
pub fn parse_single_i64(src: &[u8]) -> Result<i64, ()> {
    let s = core::str::from_utf8(src).map_err(|_| ())?.trim();
    if s.is_empty() { return Err(()); }
    s.parse::<i64>().map_err(|_| ())
}

/// Parse the SINGLE unsigned-decimal value a `proc_doulongvec_minmax` leaf
/// carries. # C: O(len)
pub fn parse_single_u64(src: &[u8]) -> Result<u64, ()> {
    let s = core::str::from_utf8(src).map_err(|_| ())?.trim();
    if s.is_empty() { return Err(()); }
    s.parse::<u64>().map_err(|_| ())
}

/// `proc_dointvec` / `proc_dointvec_minmax`: a live `i64` cell with an optional
/// inclusive `[min,max]` window (`extra1`/`extra2`). # C: O(1)
pub struct IntVar {
    pub cell:   &'static AtomicI64,
    pub bounds: Option<(i64, i64)>,
}
impl ProcHandler for IntVar {
    fn format(&self) -> Vec<u8> { fmt_i64(self.cell.load(Ordering::Relaxed)) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        let v = parse_single_i64(src)?;
        if let Some((min, max)) = self.bounds { if v < min || v > max { return Err(()); } }
        self.cell.store(v, Ordering::Relaxed);
        Ok(())
    }
}

/// `proc_dointvec_minmax` bound to a subsystem-owned integer. # C: O(1)
pub struct IntHook {
    pub get: fn() -> i64,
    pub set: fn(i64),
    pub bounds: Option<(i64, i64)>,
}
impl ProcHandler for IntHook {
    fn format(&self) -> Vec<u8> { fmt_i64((self.get)()) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        let v = parse_single_i64(src)?;
        if let Some((min, max)) = self.bounds { if v < min || v > max { return Err(()); } }
        (self.set)(v);
        Ok(())
    }
}

/// Fallible `proc_dointvec_minmax` binding for cross-field validation. # C: O(1)
pub struct CheckedIntHook {
    pub get: fn() -> i64,
    pub set: fn(i64) -> Result<(), ()>,
    pub bounds: Option<(i64, i64)>,
}
impl ProcHandler for CheckedIntHook {
    fn format(&self) -> Vec<u8> { fmt_i64((self.get)()) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        let value = parse_single_i64(src)?;
        if let Some((min, max)) = self.bounds {
            if value < min || value > max { return Err(()); }
        }
        (self.set)(value)
    }
}

/// `proc_dointvec_minmax` whose setter distinguishes a REFUSED write from a
/// malformed one — a knob whose policy answer is EPERM, not EINVAL.
pub struct PermIntHook {
    pub get: fn() -> i64,
    pub set: fn(i64) -> KResult<()>,
    pub bounds: Option<(i64, i64)>,
}
impl ProcHandler for PermIntHook {
    fn format(&self) -> Vec<u8> { fmt_i64((self.get)()) }
    fn store(&self, src: &[u8]) -> Result<(), ()> { self.store_vfs(src).map_err(|_| ()) }
    fn store_vfs(&self, src: &[u8]) -> KResult<()> {
        let value = parse_single_i64(src).map_err(|_| VfsError::Einval)?;
        if let Some((min, max)) = self.bounds {
            if value < min || value > max { return Err(VfsError::Einval); }
        }
        (self.set)(value)
    }
}

/// Two-u16 `proc_dointvec` binding used by `ip_local_port_range`.
pub struct U16PairHook {
    pub get: fn() -> (u16, u16),
    pub set: fn(u16, u16) -> Result<(), ()>,
}
impl ProcHandler for U16PairHook {
    fn format(&self) -> Vec<u8> { format_u16_pair((self.get)()) }

    fn store(&self, src: &[u8]) -> Result<(), ()> {
        let text = core::str::from_utf8(src).map_err(|_| ())?;
        let mut fields = text.split_whitespace();
        let first = fields.next().ok_or(())?.parse::<u16>().map_err(|_| ())?;
        let second = match fields.next() {
            Some(value) => value.parse::<u16>().map_err(|_| ())?,
            None => (self.get)().1,
        };
        if fields.next().is_some() { return Err(()); }
        (self.set)(first, second)
    }
}

/// `proc_doulongvec_minmax`: a live `u64` cell with an optional inclusive
/// `[min,max]` window. # C: O(1)
pub struct ULongVar {
    pub cell:   &'static AtomicU64,
    pub bounds: Option<(u64, u64)>,
}
impl ProcHandler for ULongVar {
    fn format(&self) -> Vec<u8> { fmt_u64(self.cell.load(Ordering::Relaxed)) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        let v = parse_single_u64(src)?;
        if let Some((min, max)) = self.bounds { if v < min || v > max { return Err(()); } }
        self.cell.store(v, Ordering::Relaxed);
        Ok(())
    }
}

/// `proc_dostring` bound to a subsystem accessor pair. `get` returns the value
/// WITHOUT a trailing newline (added on format); `set` receives the raw write
/// payload (the subsystem trims). # C: O(len)
pub struct StrHook { pub get: fn() -> Vec<u8>, pub set: fn(&[u8]) }
impl ProcHandler for StrHook {
    fn format(&self) -> Vec<u8> {
        let mut b = (self.get)();
        if b.last() != Some(&b'\n') { b.push(b'\n'); }
        b
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> { (self.set)(src); Ok(()) }
}

#[cfg(test)]
#[path = "proc_handler_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "proc_handler_netns_tests.rs"]
mod netns_tests;

/// Per-network-namespace three-value socket-buffer window (`tcp_wmem` /
/// `tcp_rmem`). Linux formats the three ints tab-separated and lets a write
/// supply fewer than three, leaving the untouched slots live.
pub struct PerNetBufWindowHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub get: fn(&NetworkNamespaceRef) -> [i64; 3],
    pub set: fn(&NetworkNamespaceRef, [i64; 3]) -> Result<(), ()>,
    pub bounds: (i64, i64),
}
struct BoundPerNetBufWindowHook {
    namespace: NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> [i64; 3],
    set: fn(&NetworkNamespaceRef, [i64; 3]) -> Result<(), ()>,
    bounds: (i64, i64),
}
impl ProcHandler for PerNetBufWindowHook {
    fn format(&self) -> Vec<u8> { format_buf_window((self.get)(&(self.current_ns)())) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_buf_window(&(self.current_ns)(), self.get, self.set, self.bounds, src)
    }
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> {
        Some(Arc::new(BoundPerNetBufWindowHook {
            namespace: (self.current_ns)(), get: self.get, set: self.set, bounds: self.bounds,
        }))
    }
}
impl ProcHandler for BoundPerNetBufWindowHook {
    fn format(&self) -> Vec<u8> { format_buf_window((self.get)(&self.namespace)) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_buf_window(&self.namespace, self.get, self.set, self.bounds, src)
    }
}

fn format_buf_window(window: [i64; 3]) -> Vec<u8> {
    alloc::format!("{}\t{}\t{}\n", window[0], window[1], window[2]).into_bytes()
}

fn store_buf_window(namespace: &NetworkNamespaceRef,
    get: fn(&NetworkNamespaceRef) -> [i64; 3],
    set: fn(&NetworkNamespaceRef, [i64; 3]) -> Result<(), ()>,
    bounds: (i64, i64), src: &[u8]) -> Result<(), ()>
{
    let text = core::str::from_utf8(src).map_err(|_| ())?;
    let mut window = get(namespace);
    let mut fields = text.split_whitespace();
    for slot in window.iter_mut() {
        let Some(field) = fields.next() else { break };
        let value = field.parse::<i64>().map_err(|_| ())?;
        if value < bounds.0 || value > bounds.1 { return Err(()); }
        *slot = value;
    }
    if fields.next().is_some() { return Err(()); }
    set(namespace, window)
}
