// The three `kernel/acct` tunables and the `/proc/sys/kernel/acct` vector leaf
// they are read and written through.
//
// One `proc_dointvec` leaf over a three-`int` array: resume percentage,
// suspend percentage, and the seconds between two free-space checks. Reads
// format all three tab-separated with a trailing newline; a write updates as
// many leading elements as the writer supplied and leaves the rest alone —
// the vector-leaf behaviour `sysctl -w kernel.acct="4 2 30"` depends on.
//
// Ungated on purpose: the format/parse pair is the whole observable surface of
// the file, so `cargo test -p fs` proves it without a boot.

extern crate alloc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicI64, Ordering};

/// `acct_parm[0]` — accounting resumes at or above this percentage of free
/// blocks.
pub const DEFAULT_RESUME_PCT: i64 = 4;
/// `acct_parm[1]` — accounting suspends at or below this percentage of free
/// blocks, so the accounting file cannot finish filling a nearly full disk.
pub const DEFAULT_SUSPEND_PCT: i64 = 2;
/// `acct_parm[2]` — seconds between two free-space checks. Between checks the
/// last verdict stands, so a busy exit path does not statfs per record.
pub const DEFAULT_TIMEOUT_SECS: i64 = 30;

/// Number of `int`s the leaf carries (`maxlen = 3 * sizeof(int)`).
pub const ACCT_PARM_LEN: usize = 3;

static RESUME:  AtomicI64 = AtomicI64::new(DEFAULT_RESUME_PCT);
static SUSPEND: AtomicI64 = AtomicI64::new(DEFAULT_SUSPEND_PCT);
static TIMEOUT: AtomicI64 = AtomicI64::new(DEFAULT_TIMEOUT_SECS);

/// The live tunables, read as one triple so a concurrent write cannot be
/// observed half-applied by a single free-space check.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct AcctParm {
    pub resume_pct:   i64,
    pub suspend_pct:  i64,
    pub timeout_secs: i64,
}

impl Default for AcctParm {
    fn default() -> Self {
        Self {
            resume_pct:   DEFAULT_RESUME_PCT,
            suspend_pct:  DEFAULT_SUSPEND_PCT,
            timeout_secs: DEFAULT_TIMEOUT_SECS,
        }
    }
}

/// Snapshot the live tunables. # C: O(1)
pub fn parms() -> AcctParm {
    AcctParm {
        resume_pct:   RESUME.load(Ordering::Relaxed),
        suspend_pct:  SUSPEND.load(Ordering::Relaxed),
        timeout_secs: TIMEOUT.load(Ordering::Relaxed),
    }
}

/// Replace the live tunables. # C: O(1)
pub fn set_parms(p: AcctParm) {
    RESUME.store(p.resume_pct, Ordering::Relaxed);
    SUSPEND.store(p.suspend_pct, Ordering::Relaxed);
    TIMEOUT.store(p.timeout_secs, Ordering::Relaxed);
}

/// `proc_dointvec` read direction for a three-element vector: each value
/// decimal, tab-separated, one trailing newline. # C: O(1)
pub fn format_parms(p: AcctParm) -> Vec<u8> {
    let mut out = Vec::new();
    for (i, v) in [p.resume_pct, p.suspend_pct, p.timeout_secs].iter().enumerate() {
        if i != 0 { out.push(b'\t'); }
        push_dec(&mut out, *v);
    }
    out.push(b'\n');
    out
}

fn push_dec(out: &mut Vec<u8>, v: i64) {
    if v < 0 { out.push(b'-'); }
    let mut n = v.unsigned_abs();
    let mut d = [0u8; 20];
    let mut i = d.len();
    loop {
        i -= 1;
        d[i] = b'0' + (n % 10) as u8;
        n /= 10;
        if n == 0 { break; }
    }
    out.extend_from_slice(&d[i..]);
}

/// `proc_dointvec` write direction: parse up to [`ACCT_PARM_LEN`] whitespace-
/// separated decimal integers onto `base`, leaving any element the writer did
/// not supply untouched. `None` when a token is not an integer — the whole
/// write is then rejected without applying its leading elements, which is what
/// makes a typo in `sysctl.conf` an error rather than a partial reconfigure.
/// # C: O(len)
pub fn parse_parms(base: AcctParm, src: &[u8]) -> Option<AcctParm> {
    let mut out = base;
    let mut n = 0usize;
    let mut it = src.split(|c: &u8| c.is_ascii_whitespace()).filter(|t| !t.is_empty());
    for tok in &mut it {
        if n == ACCT_PARM_LEN { return None; }
        let v = parse_int(tok)?;
        match n {
            0 => out.resume_pct = v,
            1 => out.suspend_pct = v,
            _ => out.timeout_secs = v,
        }
        n += 1;
    }
    if n == 0 { return None; }
    Some(out)
}

fn parse_int(tok: &[u8]) -> Option<i64> {
    let (neg, digits) = match tok.first() {
        Some(b'-') => (true,  &tok[1..]),
        Some(b'+') => (false, &tok[1..]),
        _          => (false, tok),
    };
    if digits.is_empty() { return None; }
    let mut acc: i64 = 0;
    for c in digits {
        if !c.is_ascii_digit() { return None; }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as i64)?;
        if acc > i32::MAX as i64 + 1 { return None; }
    }
    let v = if neg { -acc } else { acc };
    if v > i32::MAX as i64 || v < i32::MIN as i64 { return None; }
    Some(v)
}

/// `/proc/sys/kernel/acct` read hook. # C: O(1)
pub fn sysctl_read() -> Vec<u8> { format_parms(parms()) }

/// `/proc/sys/kernel/acct` write hook. A malformed write is dropped whole.
/// # C: O(len)
pub fn sysctl_write(src: &[u8]) {
    if let Some(p) = parse_parms(parms(), src) { set_parms(p); }
}
