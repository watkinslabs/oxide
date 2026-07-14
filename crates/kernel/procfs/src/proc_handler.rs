//! Linux `proc_handler` model (`kernel/sysctl.c`): the per-leaf binding that
//! ties a `/proc/sys/*` file to its **live kernel variable** (the ctl_table
//! `data`/`extra1`/`extra2`). A read FORMATS the live variable; a write PARSES
//! + range-checks (against `extra1`/`extra2` min/max) + UPDATES the live
//! variable — instead of returning a fixed default string and dropping writes.
//!
//! Handler classes implemented here (Linux names in parens):
//!   * [`IntVar`]   — `proc_dointvec` / `proc_dointvec_minmax` over a live
//!                    `&'static AtomicI64` (`data` = an `int`/`long`).
//!   * [`IntHook`]  — `proc_dointvec_minmax` bound to subsystem accessors.
//!   * [`ULongVar`] — `proc_doulongvec_minmax` over a live `&'static AtomicU64`.
//!   * [`BoolVar`]  — `proc_dobool` over a live `&'static AtomicBool`.
//!   * [`BoolHook`] — `proc_dobool` bound to a subsystem accessor pair
//!                    (e.g. `net.ipv4.ip_forward` → `net::forwarding`).
//!   * [`StrHook`]  — `proc_dostring` bound to a subsystem accessor pair
//!                    (e.g. `kernel.hostname` → the UTS hostname slot).
//!
//! Backing-variable policy (D22): a leaf whose backing kernel variable EXISTS
//! in-tree binds to it (`BoolHook`/`StrHook`); a leaf whose backing does NOT
//! exist gets a procfs-OWNED live cell (`IntVar`/`ULongVar`/`BoolVar` over a
//! `Box::leak`ed atomic) — a real read/write variable, NOT a fake constant.
//!
//! Kept un-`cfg`-gated (like `proc_dointvec`) so the read-format / write-parse /
//! bounds contract is covered by `cargo test -p procfs` on the host.

extern crate alloc;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use network_namespace::NetworkNamespaceRef;

/// One `/proc/sys` leaf's `proc_handler`: format the live value on read, and
/// parse+validate+store it on write. `Err(())` → `EINVAL` (Linux rejects a
/// non-numeric / out-of-range write before it touches the variable).
pub trait ProcHandler: Send + Sync {
    /// Format the CURRENT live value (read path). # C: O(1)
    fn format(&self) -> Vec<u8>;
    /// Parse + validate `src` and UPDATE the live variable (write path).
    /// # C: O(len)
    fn store(&self, src: &[u8]) -> Result<(), ()>;
    /// Capture open-time state for handlers whose backing depends on the
    /// opener. `None` keeps using this inode-bound handler. # C: O(1)
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> { None }
    /// Whether the leaf accepts writes (mode 0644 vs read-only 0444).
    /// # C: O(1)
    fn writable(&self) -> bool { true }
}

/// Per-network-namespace fallible integer binding. `current_ns` runs once at
/// open; the returned handler carries that namespace for its lifetime.
pub struct PerNetIntHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub get: fn(u64) -> i64,
    pub set: fn(u64, i64) -> Result<(), ()>,
    pub bounds: Option<(i64, i64)>,
}
struct BoundPerNetIntHook {
    namespace: NetworkNamespaceRef,
    get: fn(u64) -> i64,
    set: fn(u64, i64) -> Result<(), ()>,
    bounds: Option<(i64, i64)>,
}
impl ProcHandler for PerNetIntHook {
    fn format(&self) -> Vec<u8> { fmt_i64((self.get)(namespace_id(&(self.current_ns)()))) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_bound_i64(namespace_id(&(self.current_ns)()), self.set, self.bounds, src)
    }
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> {
        Some(Arc::new(BoundPerNetIntHook {
            namespace: (self.current_ns)(), get: self.get, set: self.set, bounds: self.bounds,
        }))
    }
}
impl ProcHandler for BoundPerNetIntHook {
    fn format(&self) -> Vec<u8> { fmt_i64((self.get)(namespace_id(&self.namespace))) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_bound_i64(namespace_id(&self.namespace), self.set, self.bounds, src)
    }
}

fn store_bound_i64(ns: u64, set: fn(u64, i64) -> Result<(), ()>,
    bounds: Option<(i64, i64)>, src: &[u8]) -> Result<(), ()>
{
    let value = parse_single_i64(src)?;
    if let Some((min, max)) = bounds { if value < min || value > max { return Err(()); } }
    set(ns, value)
}

/// Per-network-namespace two-u16 vector binding. One-field writes preserve the
/// captured namespace's second field, matching `proc_dointvec` partial writes.
pub struct PerNetU16PairHook {
    pub current_ns: fn() -> NetworkNamespaceRef,
    pub get: fn(u64) -> (u16, u16),
    pub set: fn(u64, u16, u16) -> Result<(), ()>,
}
struct BoundPerNetU16PairHook {
    namespace: NetworkNamespaceRef,
    get: fn(u64) -> (u16, u16),
    set: fn(u64, u16, u16) -> Result<(), ()>,
}
impl ProcHandler for PerNetU16PairHook {
    fn format(&self) -> Vec<u8> { format_u16_pair((self.get)(namespace_id(&(self.current_ns)()))) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_u16_pair(namespace_id(&(self.current_ns)()), self.get, self.set, src)
    }
    fn bind(&self) -> Option<Arc<dyn ProcHandler>> {
        Some(Arc::new(BoundPerNetU16PairHook {
            namespace: (self.current_ns)(), get: self.get, set: self.set,
        }))
    }
}
impl ProcHandler for BoundPerNetU16PairHook {
    fn format(&self) -> Vec<u8> { format_u16_pair((self.get)(namespace_id(&self.namespace))) }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        store_u16_pair(namespace_id(&self.namespace), self.get, self.set, src)
    }
}

fn namespace_id(namespace: &NetworkNamespaceRef) -> u64 { namespace.id().as_u64() }

fn format_u16_pair(pair: (u16, u16)) -> Vec<u8> {
    alloc::format!("{}\t{}\n", pair.0, pair.1).into_bytes()
}

fn store_u16_pair(ns: u64, get: fn(u64) -> (u16, u16),
    set: fn(u64, u16, u16) -> Result<(), ()>, src: &[u8]) -> Result<(), ()>
{
    let text = core::str::from_utf8(src).map_err(|_| ())?;
    let mut fields = text.split_whitespace();
    let first = fields.next().ok_or(())?.parse::<u16>().map_err(|_| ())?;
    let second = match fields.next() {
        Some(value) => value.parse::<u16>().map_err(|_| ())?,
        None => get(ns).1,
    };
    if fields.next().is_some() { return Err(()); }
    set(ns, first, second)
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

/// `proc_dobool`: a live `bool` cell (accepts the Linux `0`/`1` values).
/// # C: O(1)
pub struct BoolVar { pub cell: &'static AtomicBool }
impl ProcHandler for BoolVar {
    fn format(&self) -> Vec<u8> {
        if self.cell.load(Ordering::Relaxed) { b"1\n".to_vec() } else { b"0\n".to_vec() }
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> {
        let v = parse_bool(src)?;
        self.cell.store(v, Ordering::Relaxed);
        Ok(())
    }
}

/// `proc_dobool` bound to a subsystem accessor pair (the backing variable lives
/// OUTSIDE procfs — e.g. `net.ipv4.ip_forward`). # C: O(1)
pub struct BoolHook { pub get: fn() -> bool, pub set: fn(bool) }
impl ProcHandler for BoolHook {
    fn format(&self) -> Vec<u8> {
        if (self.get)() { b"1\n".to_vec() } else { b"0\n".to_vec() }
    }
    fn store(&self, src: &[u8]) -> Result<(), ()> { (self.set)(parse_bool(src)?); Ok(()) }
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

/// Parse a Linux boolean sysctl write (`0`/`1`, whitespace-trimmed).
/// # C: O(len)
fn parse_bool(src: &[u8]) -> Result<bool, ()> {
    let s = core::str::from_utf8(src).map_err(|_| ())?.trim();
    match s { "0" => Ok(false), "1" => Ok(true), _ => Err(()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    // proc_dointvec_minmax: read formats the live var; write reflects in it.
    #[test]
    fn intvar_read_write_reflects_live() {
        static CELL: AtomicI64 = AtomicI64::new(60);
        let h = IntVar { cell: &CELL, bounds: Some((0, 200)) };
        assert_eq!(h.format(), b"60\n".to_vec());
        // a write updates the LIVE variable...
        h.store(b"99\n").unwrap();
        assert_eq!(CELL.load(Ordering::Relaxed), 99);
        assert_eq!(h.format(), b"99\n".to_vec());
        // ...and an external mutation of the live var shows up on read.
        CELL.store(7, Ordering::Relaxed);
        assert_eq!(h.format(), b"7\n".to_vec());
    }

    // proc_dointvec_minmax: out-of-range / non-integer write rejected, live var
    // unchanged.
    #[test]
    fn intvar_bounds_rejected() {
        static CELL: AtomicI64 = AtomicI64::new(1);
        let h = IntVar { cell: &CELL, bounds: Some((0, 2)) };
        assert!(h.store(b"3\n").is_err());
        assert!(h.store(b"-1\n").is_err());
        assert!(h.store(b"abc\n").is_err());
        assert!(h.store(b"\n").is_err());
        assert_eq!(CELL.load(Ordering::Relaxed), 1, "rejected write must not mutate live var");
        assert!(h.store(b"2\n").is_ok());
        assert_eq!(CELL.load(Ordering::Relaxed), 2);
    }

    #[test]
    fn intvar_negative_window() {
        static CELL: AtomicI64 = AtomicI64::new(2);
        let h = IntVar { cell: &CELL, bounds: Some((-1, 4)) }; // perf_event_paranoid
        assert!(h.store(b"-1\n").is_ok());
        assert_eq!(CELL.load(Ordering::Relaxed), -1);
        assert!(h.store(b"-2\n").is_err());
    }

    #[test]
    fn intvar_unbounded_accepts_any_int() {
        static CELL: AtomicI64 = AtomicI64::new(0);
        let h = IntVar { cell: &CELL, bounds: None };
        assert!(h.store(b"123456\n").is_ok());
        assert_eq!(CELL.load(Ordering::Relaxed), 123456);
        assert!(h.store(b"notanint").is_err());
    }

    #[test]
    fn inthook_updates_subsystem_owned_value() {
        static CELL: AtomicI64 = AtomicI64::new(4096);
        fn get() -> i64 { CELL.load(Ordering::Relaxed) }
        fn set(v: i64) { CELL.store(v, Ordering::Relaxed); }
        let h = IntHook { get, set, bounds: Some((0, i32::MAX as i64)) };
        assert_eq!(h.format(), b"4096\n".to_vec());
        h.store(b"1024\n").unwrap();
        assert_eq!(CELL.load(Ordering::Relaxed), 1024);
        assert!(h.store(b"-1").is_err());
        assert_eq!(CELL.load(Ordering::Relaxed), 1024);
    }

    #[test]
    fn u16_pair_hook_accepts_partial_vector_and_rejects_excess() {
        static PAIR: AtomicU64 = AtomicU64::new((32_768u64 << 16) | 60_999);
        fn get() -> (u16, u16) {
            let raw = PAIR.load(Ordering::Relaxed);
            ((raw >> 16) as u16, raw as u16)
        }
        fn set(first: u16, second: u16) -> Result<(), ()> {
            if first == 0 || first > second { return Err(()); }
            PAIR.store((first as u64) << 16 | second as u64, Ordering::Relaxed);
            Ok(())
        }
        let h = U16PairHook { get, set };
        assert_eq!(h.format(), b"32768\t60999\n".to_vec());
        h.store(b"40000 40009\n").unwrap();
        assert_eq!(get(), (40_000, 40_009));
        h.store(b"40001").unwrap();
        assert_eq!(get(), (40_001, 40_009));
        assert!(h.store(b"40010 40000").is_err());
        assert!(h.store(b"1 2 3").is_err());
        assert_eq!(get(), (40_001, 40_009));
    }

    #[test]
    fn per_net_handlers_capture_namespace_and_keep_vector_validation_coherent() {
        const fn pack(start: u16, end: u16, floor: u16) -> u64 {
            (start as u64) << 32 | (end as u64) << 16 | floor as u64
        }
        static CURRENT: std::sync::Mutex<Option<NetworkNamespaceRef>> =
            std::sync::Mutex::new(None);
        static STATE: [AtomicU64; 2] = [
            AtomicU64::new(pack(32_768, 60_999, 1_024)),
            AtomicU64::new(pack(40_000, 40_009, 2_048)),
        ];
        fn current() -> NetworkNamespaceRef {
            Arc::clone(CURRENT.lock().unwrap().as_ref().unwrap())
        }
        fn pair(ns: u64) -> (u16, u16) {
            let raw = STATE[ns as usize].load(Ordering::Relaxed);
            ((raw >> 32) as u16, (raw >> 16) as u16)
        }
        fn set_pair(ns: u64, start: u16, end: u16) -> Result<(), ()> {
            let old = STATE[ns as usize].load(Ordering::Relaxed);
            let floor = old as u16;
            if start == 0 || start > end || start < floor { return Err(()); }
            STATE[ns as usize].store(pack(start, end, floor), Ordering::Relaxed);
            Ok(())
        }
        fn floor(ns: u64) -> i64 {
            STATE[ns as usize].load(Ordering::Relaxed) as u16 as i64
        }
        fn set_floor(ns: u64, floor: i64) -> Result<(), ()> {
            let old = STATE[ns as usize].load(Ordering::Relaxed);
            let start = (old >> 32) as u16;
            if floor < 0 || floor > start as i64 { return Err(()); }
            STATE[ns as usize].store((old & !(u16::MAX as u64)) | floor as u64, Ordering::Relaxed);
            Ok(())
        }

        *CURRENT.lock().unwrap() = Some(network_namespace::initial());
        let pair_open = PerNetU16PairHook { current_ns: current, get: pair, set: set_pair }
            .bind().unwrap();
        let floor_open = PerNetIntHook {
            current_ns: current, get: floor, set: set_floor, bounds: Some((0, u16::MAX as i64)),
        }.bind().unwrap();
        let _ = net::net_ns::install_final_drop_pending_notifier();
        *CURRENT.lock().unwrap() = Some(network_namespace::allocate(0).unwrap());

        assert_eq!(pair_open.format(), b"32768\t60999\n".to_vec());
        assert_eq!(floor_open.format(), b"1024\n".to_vec());
        pair_open.store(b"35000").unwrap();
        assert_eq!(pair(0), (35_000, 60_999));
        pair_open.store(b"36000 36009\n").unwrap();
        assert_eq!(pair(0), (36_000, 36_009));
        assert_eq!(pair(1), (40_000, 40_009));
        floor_open.store(b"35000").unwrap();
        assert_eq!(floor(0), 35_000);
        assert_eq!(floor(1), 2_048);
        assert!(pair_open.store(b"34999 36009").is_err());
        assert!(floor_open.store(b"36001").is_err());
        assert_eq!(pair(0), (36_000, 36_009));
        assert_eq!(floor(0), 35_000);
    }

    #[test]
    fn ulongvar_bounds() {
        static CELL: AtomicU64 = AtomicU64::new(4096);
        let h = ULongVar { cell: &CELL, bounds: Some((0, 1 << 30)) };
        assert_eq!(h.format(), b"4096\n".to_vec());
        h.store(b"8192\n").unwrap();
        assert_eq!(CELL.load(Ordering::Relaxed), 8192);
        assert!(h.store(b"99999999999\n").is_err()); // > 2^30
        assert!(h.store(b"-1\n").is_err());          // not unsigned
    }

    #[test]
    fn boolvar_round_trip() {
        static CELL: AtomicBool = AtomicBool::new(false);
        let h = BoolVar { cell: &CELL };
        assert_eq!(h.format(), b"0\n".to_vec());
        h.store(b"1\n").unwrap();
        assert!(CELL.load(Ordering::Relaxed));
        assert_eq!(h.format(), b"1\n".to_vec());
        assert!(h.store(b"2\n").is_err());
    }

    #[test]
    fn boolhook_binds_external() {
        static EXT: AtomicBool = AtomicBool::new(false);
        fn get() -> bool { EXT.load(Ordering::Relaxed) }
        fn set(v: bool) { EXT.store(v, Ordering::Relaxed); }
        let h = BoolHook { get, set };
        assert_eq!(h.format(), b"0\n".to_vec());
        h.store(b"1").unwrap();
        assert!(EXT.load(Ordering::Relaxed));
        assert_eq!(h.format(), b"1\n".to_vec());
    }

    #[test]
    fn strhook_adds_newline() {
        static SLOT: AtomicI64 = AtomicI64::new(0); // marker; real slot below
        let _ = &SLOT;
        fn get() -> Vec<u8> { b"oxide".to_vec() }
        fn set(_s: &[u8]) {}
        let h = StrHook { get, set };
        assert_eq!(h.format(), b"oxide\n".to_vec());
    }
}
