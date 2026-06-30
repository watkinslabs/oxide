//! Linux `proc_handler` model (`kernel/sysctl.c`): the per-leaf binding that
//! ties a `/proc/sys/*` file to its **live kernel variable** (the ctl_table
//! `data`/`extra1`/`extra2`). A read FORMATS the live variable; a write PARSES
//! + range-checks (against `extra1`/`extra2` min/max) + UPDATES the live
//! variable — instead of returning a fixed default string and dropping writes.
//!
//! Handler classes implemented here (Linux names in parens):
//!   * [`IntVar`]   — `proc_dointvec` / `proc_dointvec_minmax` over a live
//!                    `&'static AtomicI64` (`data` = an `int`/`long`).
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
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};

/// One `/proc/sys` leaf's `proc_handler`: format the live value on read, and
/// parse+validate+store it on write. `Err(())` → `EINVAL` (Linux rejects a
/// non-numeric / out-of-range write before it touches the variable).
pub trait ProcHandler: Send + Sync {
    /// Format the CURRENT live value (read path). # C: O(1)
    fn format(&self) -> Vec<u8>;
    /// Parse + validate `src` and UPDATE the live variable (write path).
    /// # C: O(len)
    fn store(&self, src: &[u8]) -> Result<(), ()>;
    /// Whether the leaf accepts writes (mode 0644 vs read-only 0444).
    /// # C: O(1)
    fn writable(&self) -> bool { true }
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
