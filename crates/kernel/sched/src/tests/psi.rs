// Hosted PSI unit tests — drive the real `crate::psi` accounting core with
// synthetic clocks (no scheduler, no boot). Covers: file format, live cpu
// accounting + window math, trigger parse/validate, trigger firing predicate,
// honest-zero memory/io, and the task_stall begin/end model.

use alloc::string::String;

use crate::psi::{parse_trigger, Psi, PsiRes, MAX_WINDOW_NS, NS_PER_US, PCT_SCALE, WIN10_NS};
use vfs::POLL_PRI;

const S: u64 = 1_000_000_000; // one second in ns

fn body(p: &mut Psi, res: PsiRes, now: u64) -> String {
    String::from_utf8(p.format(res, now)).unwrap()
}

#[test]
fn format_honest_zero() {
    let mut p = Psi::new();
    let out = body(&mut p, PsiRes::Memory, 42 * S);
    assert_eq!(out, "some avg10=0.00 avg60=0.00 avg300=0.00 total=0\n\
                     full avg10=0.00 avg60=0.00 avg300=0.00 total=0\n");
}

#[test]
fn cpu_some_total_grows_by_active_interval() {
    let mut p = Psi::new();
    p.account_cpu(0, false);          // idle from t=0
    p.account_cpu(1 * S, true);       // [0,1s] idle → no charge; now contended
    p.account_cpu(2 * S, false);      // [1s,2s] contended → +1s SOME
    assert_eq!(p.total_us(PsiRes::Cpu, false, 2 * S), S / NS_PER_US); // 1_000_000 us
    // cpu never accrues FULL.
    assert_eq!(p.total_us(PsiRes::Cpu, true, 2 * S), 0);
}

#[test]
fn window_average_full_pressure_is_100pct() {
    let mut p = Psi::new();
    p.account_cpu(0, true);           // stalled from t=0
    p.maybe_sample(0);                // ring baseline at ts=0, total=0
    // At t=10s the whole avg10 window was stalled → 100.00%.
    assert_eq!(p.window_centi(PsiRes::Cpu, false, WIN10_NS, 10 * S), PCT_SCALE as u32);
}

#[test]
fn window_average_half_pressure_is_50pct() {
    let mut p = Psi::new();
    p.account_cpu(0, false);
    p.maybe_sample(0);                // baseline ts=0 total=0
    p.account_cpu(5 * S, true);       // stalled for the second half only
    // avg10 over [0,10s]: 5s stalled / 10s window = 50.00%.
    assert_eq!(p.window_centi(PsiRes::Cpu, false, WIN10_NS, 10 * S), (PCT_SCALE / 2) as u32);
}

#[test]
fn format_reports_microsecond_total() {
    let mut p = Psi::new();
    p.account_cpu(0, true);
    let out = body(&mut p, PsiRes::Cpu, 3 * S);   // 3s stalled
    assert!(out.contains("total=3000000"), "got {out}");
    assert!(out.starts_with("some "), "got {out}");
}

#[test]
fn trigger_parse_valid() {
    let t = parse_trigger(b"some 150000 1000000\n", true).unwrap();
    assert!(!t.full);
    assert_eq!(t.threshold_ns, 150_000 * NS_PER_US);
    assert_eq!(t.window_ns, 1_000_000 * NS_PER_US);
    let f = parse_trigger(b"full 50000 500000\n", true).unwrap();
    assert!(f.full);
    assert_eq!(f.window_ns, 500_000 * NS_PER_US);
    // Max window (10s) accepted.
    assert!(parse_trigger(b"some 100 10000000\n", true).is_ok());
    assert_eq!(parse_trigger(b"some 100 10000000\n", true).unwrap().window_ns, MAX_WINDOW_NS);
}

#[test]
fn trigger_parse_rejects_bad() {
    assert!(parse_trigger(b"", true).is_err());
    assert!(parse_trigger(b"bad 1 1000000\n", true).is_err());        // bad kind
    assert!(parse_trigger(b"some abc 1000000\n", true).is_err());     // non-digit
    assert!(parse_trigger(b"some 1\n", true).is_err());               // missing window
    // `sscanf` consumed both fields and ignores the rest — Linux accepts this.
    assert!(parse_trigger(b"some 1 1000000 x\n", true).is_ok());
    assert!(parse_trigger(b"some 0 1000000\n", true).is_err());       // zero threshold
    // Linux has NO minimum window; a privileged 400ms window is legal.
    assert!(parse_trigger(b"some 100 400000\n", true).is_ok());
    assert!(parse_trigger(b"some 100 20000000\n", true).is_err());    // window > 10s
    assert!(parse_trigger(b"some 2000000 1000000\n", true).is_err()); // threshold > window
}

#[test]
fn trigger_fires_when_stall_exceeds_threshold() {
    let mut p = Psi::new();
    p.add_trigger(PsiRes::Cpu, b"some 150000 1000000\n", true).unwrap(); // 150ms in 1s
    p.account_cpu(0, true);
    p.maybe_sample(0);
    // Over the 1s window the CPU was fully stalled (1s >> 150ms) → POLLPRI.
    assert_eq!(p.poll_mask(PsiRes::Cpu, 1 * S), POLL_PRI);
}

#[test]
fn trigger_silent_below_threshold() {
    let mut p = Psi::new();
    p.add_trigger(PsiRes::Cpu, b"some 500000 1000000\n", true).unwrap(); // 500ms in 1s
    p.account_cpu(0, false);
    p.maybe_sample(0);
    p.account_cpu(900 * (S / 1000), true); // stalled only the last 100ms of the window
    assert_eq!(p.poll_mask(PsiRes::Cpu, 1 * S), 0);
}

#[test]
fn honest_zero_memory_registers_but_never_fires() {
    let mut p = Psi::new();
    // write() succeeds (this is what fixes systemd's EOPNOTSUPP)…
    assert!(p.add_trigger(PsiRes::Memory, b"some 150000 1000000\n", true).is_ok());
    p.maybe_sample(0);
    // …but with no reclaim events the resource is honestly idle: never fires.
    assert_eq!(p.poll_mask(PsiRes::Memory, 5 * S), 0);
    assert_eq!(p.total_us(PsiRes::Memory, false, 5 * S), 0);
}

#[test]
fn task_stall_some_and_full_accounting() {
    let mut p = Psi::new();
    const NONIDLE: u32 = 4;
    // One task stalls on memory for 2s: SOME accrues, FULL does not (1 of 4).
    p.task_stall(PsiRes::Memory, true, 0, NONIDLE);
    p.task_stall(PsiRes::Memory, false, 2 * S, NONIDLE);
    assert_eq!(p.total_us(PsiRes::Memory, false, 2 * S), 2 * S / NS_PER_US);
    assert_eq!(p.total_us(PsiRes::Memory, true, 2 * S), 0);
}

#[test]
fn task_stall_full_when_all_nonidle_stalled() {
    let mut p = Psi::new();
    const NONIDLE: u32 = 2;
    // Both non-idle tasks stall from t=2s..3s → FULL for that 1s window.
    p.task_stall(PsiRes::Io, true, 2 * S, NONIDLE);  // 1 of 2: some only
    p.task_stall(PsiRes::Io, true, 2 * S, NONIDLE);  // 2 of 2: full begins
    p.task_stall(PsiRes::Io, false, 3 * S, NONIDLE); // charges [2s,3s] some+full
    p.task_stall(PsiRes::Io, false, 3 * S, NONIDLE);
    assert_eq!(p.total_us(PsiRes::Io, true, 3 * S), S / NS_PER_US);   // 1s FULL
    assert_eq!(p.total_us(PsiRes::Io, false, 3 * S), S / NS_PER_US);  // 1s SOME
}
