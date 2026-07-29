// PSI — Pressure Stall Information (Linux `kernel/sched/psi.c`), simplified but
// REAL. Per resource (cpu/memory/io) we accumulate two monotonic stall
// counters in nanoseconds: SOME (>=1 task stalled) and FULL (every non-idle
// task stalled). A state-machine `settle` charges the elapsed interval to
// whichever buckets were active, so totals are exact microsecond stall time.
//
// Rolling avg10/60/300 use a periodic sample ring (Linux resamples on a ~2s
// tick): the window percentage is the growth of the stall total over the real
// span back to the sample nearest `now - window`, i.e.
// `pct = 100 * (total_now - total_window_ago) / span`. The poll/trigger
// interface reuses the same growth-over-window math (`psi_trigger_create`).
//
// LIVE accounting: `cpu` SOME is driven from the timer tick — a CPU whose
// runqueue holds >=2 runnable tasks has a task waiting for the CPU (a genuine
// scheduler-visible stall). `memory`/`io` ride `task_stall(res, begin)`; no
// reclaim/OOM or block-wait path in this kernel emits those events yet, so they
// read an HONEST zero (total=0/avg=0.00) while the hook is wired and correct —
// the instant such an event fires, accounting is exact. See B517 report.

extern crate alloc;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt::Write as _;

use sync::{Spinlock, TaskList as PsiLockClass};
use vfs::{PollSubscribers, POLL_PRI};

/// Number of pressure resources: cpu, memory, io. # C: O(1)
pub const NRES: usize = 3;
/// avg10 window in ns. # C: O(1)
pub const WIN10_NS: u64 = 10_000_000_000;
/// avg60 window in ns. # C: O(1)
pub const WIN60_NS: u64 = 60_000_000_000;
/// avg300 window in ns. # C: O(1)
pub const WIN300_NS: u64 = 300_000_000_000;
/// Trigger window floor (Linux `PSI_TRIG_MIN_WINDOW` 500ms). # C: O(1)
/// Linux `WINDOW_MAX_US` (`kernel/sched/psi.c`) — 10s. Linux has NO minimum.
pub const WINDOW_MAX_US: u32 = 10_000_000;
/// Linux: an unprivileged trigger's window must be a multiple of 2s so the
/// existing averaging aggregation serves it and no RT thread is spawned.
pub const UNPRIVILEGED_WINDOW_US: u32 = 2_000_000;
/// Trigger window ceiling (Linux `PSI_TRIG_MAX_WINDOW` 10s). # C: O(1)
pub const MAX_WINDOW_NS: u64 = 10_000_000_000;
/// Resample cadence: push one ring sample per ~2s (Linux `PSI_FREQ`). # C: O(1)
pub const SAMPLE_INTERVAL_NS: u64 = 2_000_000_000;
/// Ring depth — >=151 samples cover the 300s window at the 2s cadence. # C: O(1)
pub const RING_CAP: usize = 160;
/// Percentage fixed-point scale: value is percent*100 (0..=10000). # C: O(1)
pub const PCT_SCALE: u64 = 10_000;
/// Nanoseconds per microsecond (file `total=` is microseconds). # C: O(1)
pub const NS_PER_US: u64 = 1_000;

/// A pressure resource. Index into the per-resource state array. # C: O(1)
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum PsiRes { Cpu, Memory, Io }

impl PsiRes {
    /// Array index for this resource. # C: O(1)
    pub fn idx(self) -> usize { match self { PsiRes::Cpu => 0, PsiRes::Memory => 1, PsiRes::Io => 2 } }
    /// Resource by its `/proc/pressure/<name>` basename. # C: O(1)
    pub fn from_name(n: &str) -> Option<PsiRes> {
        match n { "cpu" => Some(PsiRes::Cpu), "memory" => Some(PsiRes::Memory), "io" => Some(PsiRes::Io), _ => None }
    }
}

/// One periodic snapshot `(timestamp, some_total, full_total)` in ns, taken on
/// the 2s sample tick; the window averages/triggers read back through it. # C: O(1)
#[derive(Copy, Clone)]
struct Sample { ts: u64, some: u64, full: u64 }

/// A registered pressure trigger (Linux `struct psi_trigger`): fire when the
/// `full`/some stall growth within `window_ns` reaches `threshold_ns`. # C: O(1)
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Trigger { pub full: bool, pub threshold_ns: u64, pub window_ns: u64 }

/// Per-resource accounting + trigger state. # C: O(1)
struct ResInner {
    some_total_ns: u64,
    full_total_ns: u64,
    last_ns: u64,
    some_active: bool,
    full_active: bool,
    stall_count: u32,
    ring: Vec<Sample>,
    last_sample_ns: u64,
    triggers: Vec<Trigger>,
    poll_subs: Option<Arc<PollSubscribers>>,
}

impl ResInner {
    const fn new() -> Self {
        ResInner {
            some_total_ns: 0, full_total_ns: 0, last_ns: 0, some_active: false, full_active: false,
            stall_count: 0, ring: Vec::new(), last_sample_ns: 0, triggers: Vec::new(), poll_subs: None,
        }
    }

    /// Charge `[last_ns, now]` to whichever buckets were active, advance the
    /// clock. Idempotent for `now == last_ns`. Monotonic against clock skew via
    /// `saturating_sub`. # C: O(1)
    fn settle(&mut self, now: u64) {
        let dt = now.saturating_sub(self.last_ns);
        if self.some_active { self.some_total_ns = self.some_total_ns.saturating_add(dt); }
        if self.full_active { self.full_total_ns = self.full_total_ns.saturating_add(dt); }
        self.last_ns = now;
    }

    /// Total ns for the SOME (`full=false`) or FULL (`full=true`) counter. # C: O(1)
    fn total(&self, full: bool) -> u64 { if full { self.full_total_ns } else { self.some_total_ns } }

    /// Ring `(base_total, base_ts)` at the newest sample with `ts <= target`,
    /// else the oldest sample. `None` when the ring is empty. # C: O(N_ring)
    fn base_at(&self, full: bool, target: u64) -> Option<(u64, u64)> {
        if self.ring.is_empty() { return None; }
        let mut chosen = &self.ring[0];
        for s in self.ring.iter() { if s.ts <= target { chosen = s; } }
        Some((if full { chosen.full } else { chosen.some }, chosen.ts))
    }

    /// Growth of the stall total over `[now-window, now]` in ns, measured across
    /// the real available span. `settle` must precede this. # C: O(N_ring)
    fn window_growth(&self, full: bool, window_ns: u64, now: u64) -> (u64, u64) {
        let target = now.saturating_sub(window_ns);
        match self.base_at(full, target) {
            Some((base_total, base_ts)) => {
                let span = now.saturating_sub(base_ts);
                (self.total(full).saturating_sub(base_total), span)
            }
            None => (0, 0),
        }
    }
}

/// System pressure state — one `ResInner` per resource. Held behind a
/// `Spinlock` for the live singleton; hosted tests drive an owned instance
/// directly, so every method is `&mut self` and clock-explicit. # C: O(1)
pub struct Psi { res: [ResInner; NRES] }

impl Psi {
    /// Empty pressure state (all counters zero). # C: O(1)
    pub const fn new() -> Self { Psi { res: [ResInner::new(), ResInner::new(), ResInner::new()] } }

    /// Settle then set the active flags for `res` at `now`. # C: O(1)
    fn set_state(&mut self, res: PsiRes, now: u64, some: bool, full: bool) {
        let r = &mut self.res[res.idx()];
        r.settle(now);
        r.some_active = some;
        r.full_active = full;
    }

    /// LIVE cpu SOME: `some_active` = a runnable task is waiting for a CPU. cpu
    /// has no FULL state (a running task means the CPU is not fully stalled), so
    /// FULL stays zero. # C: O(1)
    pub fn account_cpu(&mut self, now: u64, some_active: bool) { self.set_state(PsiRes::Cpu, now, some_active, false); }

    /// Record a task entering (`begin`) / leaving a `res` stall. SOME once any
    /// task is stalled; FULL once all `nr_nonidle` productive tasks are stalled
    /// (Linux `psi_group_change`). `nr_nonidle == 0` ⇒ no FULL. # C: O(1)
    pub fn task_stall(&mut self, res: PsiRes, begin: bool, now: u64, nr_nonidle: u32) {
        let (some, full) = {
            let r = &mut self.res[res.idx()];
            r.settle(now);
            if begin { r.stall_count = r.stall_count.saturating_add(1); }
            else { r.stall_count = r.stall_count.saturating_sub(1); }
            let some = r.stall_count > 0;
            let full = some && nr_nonidle > 0 && r.stall_count >= nr_nonidle;
            (some, full)
        };
        let r = &mut self.res[res.idx()];
        r.some_active = some;
        r.full_active = full;
    }

    /// Push a ring sample per resource at `now` when >=`SAMPLE_INTERVAL_NS` has
    /// elapsed (or the ring is empty). Trims to `RING_CAP`. Call from the tick.
    /// # C: O(N_ring) amortised
    pub fn maybe_sample(&mut self, now: u64) {
        for i in 0..NRES {
            let due = self.res[i].ring.is_empty() || now.saturating_sub(self.res[i].last_sample_ns) >= SAMPLE_INTERVAL_NS;
            if !due { continue; }
            let r = &mut self.res[i];
            r.settle(now);
            r.ring.push(Sample { ts: now, some: r.some_total_ns, full: r.full_total_ns });
            if r.ring.len() > RING_CAP { r.ring.remove(0); }
            r.last_sample_ns = now;
        }
    }

    /// SOME/FULL cumulative total in MICROSECONDS (the file `total=` field),
    /// settled to `now`. # C: O(1)
    pub fn total_us(&mut self, res: PsiRes, full: bool, now: u64) -> u64 {
        let r = &mut self.res[res.idx()];
        r.settle(now);
        r.total(full) / NS_PER_US
    }

    /// Window average in percent*100 (0..=`PCT_SCALE`), settled to `now`. # C: O(N_ring)
    pub fn window_centi(&mut self, res: PsiRes, full: bool, window_ns: u64, now: u64) -> u32 {
        let r = &mut self.res[res.idx()];
        r.settle(now);
        let (growth, span) = r.window_growth(full, window_ns, now);
        if span == 0 { return 0; }
        let centi = growth.saturating_mul(PCT_SCALE) / span;
        centi.min(PCT_SCALE) as u32
    }

    /// Register a trigger from a `<some|full> <threshold_us> <window_us>` spec
    /// (Linux `psi_trigger_parse`). `Err(())` on malformed input or an
    /// out-of-range window / `threshold > window`. # C: O(1)
    pub fn add_trigger(&mut self, res: PsiRes, spec: &[u8], privileged: bool) -> Result<Trigger, ()> {
        let trig = parse_trigger(spec, privileged)?;
        self.res[res.idx()].triggers.push(trig);
        Ok(trig)
    }

    /// `POLL_PRI` if any registered trigger for `res` is currently firing (its
    /// window stall growth >= threshold), else `0`. # C: O(N_trig * N_ring)
    pub fn poll_mask(&mut self, res: PsiRes, now: u64) -> u32 {
        let fired = {
            let r = &mut self.res[res.idx()];
            r.settle(now);
            let mut hit = false;
            for t in r.triggers.iter() {
                let (growth, _) = r.window_growth(t.full, t.window_ns, now);
                if growth >= t.threshold_ns { hit = true; break; }
            }
            hit
        };
        if fired { POLL_PRI } else { 0 }
    }

    /// Bind the resource's poll-subscriber set (the procfs inode's) so the tick
    /// can wake epoll/poll waiters when a trigger fires. # C: O(1)
    pub fn attach_poll(&mut self, res: PsiRes, subs: Arc<PollSubscribers>) { self.res[res.idx()].poll_subs = Some(subs); }

    /// Render the two-line `/proc/pressure/<res>` body (Linux `psi_show`). Both
    /// `some` and `full` lines are emitted for every resource; the cpu `full`
    /// line is genuinely all-zero. # C: O(N_ring)
    pub fn format(&mut self, res: PsiRes, now: u64) -> Vec<u8> {
        let mut s = String::new();
        for (label, full) in [("some", false), ("full", true)] {
            let a10 = self.window_centi(res, full, WIN10_NS, now);
            let a60 = self.window_centi(res, full, WIN60_NS, now);
            let a300 = self.window_centi(res, full, WIN300_NS, now);
            let total = self.total_us(res, full, now);
            let _ = write!(s, "{} avg10={} avg60={} avg300={} total={}\n",
                label, FmtPct(a10), FmtPct(a60), FmtPct(a300), total);
        }
        s.into_bytes()
    }
}

impl Default for Psi { fn default() -> Self { Self::new() } }

/// Format a percent*100 value as `W.FF` (e.g. `4210` → `42.10`). # C: O(1)
struct FmtPct(u32);
impl core::fmt::Display for FmtPct {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}.{:02}", self.0 / 100, self.0 % 100)
    }
}

/// Parse one ASCII base-10 `u64`; `None` on empty / non-digit / overflow. # C: O(len)
fn parse_u64(b: &[u8]) -> Option<u64> {
    if b.is_empty() { return None; }
    let mut v: u64 = 0;
    for &c in b { if !c.is_ascii_digit() { return None; } v = v.checked_mul(10)?.checked_add((c - b'0') as u64)?; }
    Some(v)
}

/// Parse+validate a trigger spec, Linux `psi_trigger_parse`
/// (`kernel/sched/psi.c`), converting us→ns.
///
/// `privileged` is `CAP_SYS_RESOURCE` on the OPENING cred, which Linux checks
/// because an unprivileged trigger must reuse the 2s averaging aggregation
/// rather than spawn an RT thread.
///
/// Linux's checks, in order, and the three ways this used to differ:
///   * `sscanf(buf, "some %u %u")` / `"full %u %u"`, else EINVAL. sscanf stops
///     at the first non-digit and IGNORES whatever follows — we rejected any
///     trailing token instead, and `psi_write` NUL-terminates by overwriting
///     the last byte (`buf[buf_size - 1] = '\0'`), so the terminator systemd
///     sends landed inside our final token and failed to parse. That is why
///     `write(/proc/pressure/memory, "some 200000 2000000\n", 20)` — which
///     Linux accepts — returned EINVAL to four systemd daemons every boot.
///   * `window_us == 0 || window_us > WINDOW_MAX_US`. There is NO minimum;
///     the 500ms floor here was invented.
///   * `!privileged && window_us % 2000000` → EINVAL. Was missing entirely.
///   * `threshold_us == 0 || threshold_us > window_us`.
/// Widths are Linux's `u32` (`%u`), not u64.
/// # C: O(len)
pub fn parse_trigger(spec: &[u8], privileged: bool) -> Result<Trigger, ()> {
    // `psi_write`: `buf[buf_size - 1] = '\0'` — the final byte is the
    // terminator and is never part of a field.
    let body = match spec.split_last() { Some((_, rest)) => rest, None => return Err(()) };
    let mut it = body.split(|&c| c == b' ' || c == b'\t' || c == b'\n');
    let full = match it.next() { Some(b"some") => false, Some(b"full") => true, _ => return Err(()) };
    // `%u`: leading digits, stopping at the first non-digit (sscanf).
    let threshold_us = parse_u32_prefix(it.next().ok_or(())?).ok_or(())?;
    let window_us = parse_u32_prefix(it.next().ok_or(())?).ok_or(())?;
    // No trailing-token rejection: sscanf consumed two fields and ignores rest.
    if window_us == 0 || window_us > WINDOW_MAX_US { return Err(()); }
    if !privileged && window_us % UNPRIVILEGED_WINDOW_US != 0 { return Err(()); }
    if threshold_us == 0 || threshold_us > window_us { return Err(()); }
    Ok(Trigger { full,
        threshold_ns: (threshold_us as u64) * NS_PER_US,
        window_ns:    (window_us as u64) * NS_PER_US })
}

/// `sscanf("%u")`: decimal digits from the start, stopping at the first
/// non-digit rather than rejecting the token. `None` when no digit leads or
/// the value overflows `u32`. # C: O(len)
fn parse_u32_prefix(tok: &[u8]) -> Option<u32> {
    let mut acc: u32 = 0;
    let mut any = false;
    for &c in tok {
        if !c.is_ascii_digit() { break; }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u32)?;
        any = true;
    }
    if any { Some(acc) } else { None }
}

/// The live system pressure singleton. # C: O(1)
static SYS: Spinlock<Psi, PsiLockClass> = Spinlock::new(Psi::new());

/// Record LIVE cpu SOME pressure at `now`. # C: O(1)
pub fn account_cpu(now: u64, some_active: bool) { SYS.lock().account_cpu(now, some_active); }

/// Record a memory/io stall begin/end against the live singleton. # C: O(1)
pub fn task_stall(res: PsiRes, begin: bool, now: u64, nr_nonidle: u32) { SYS.lock().task_stall(res, begin, now, nr_nonidle); }

/// Register a trigger on the live singleton (procfs write path). # C: O(1)
pub fn add_trigger(res: PsiRes, spec: &[u8], privileged: bool) -> Result<Trigger, ()> { SYS.lock().add_trigger(res, spec, privileged) }

/// Poll readiness for `res` on the live singleton (procfs poll path). # C: O(N)
pub fn poll_mask(res: PsiRes, now: u64) -> u32 { SYS.lock().poll_mask(res, now) }

/// Bind a procfs inode's poll subscribers to the live singleton. # C: O(1)
pub fn attach_poll(res: PsiRes, subs: Arc<PollSubscribers>) { SYS.lock().attach_poll(res, subs); }

/// Render `/proc/pressure/<res>` from the live singleton. # C: O(N_ring)
pub fn format(res: PsiRes, now: u64) -> Vec<u8> { SYS.lock().format(res, now) }

/// `true` if any online CPU's runqueue has >=2 runnable tasks — i.e. at least
/// one task is waiting behind the running one (a cpu SOME stall). Host builds
/// have no runqueues → `false`. # C: O(N_cpu)
fn cpu_contended() -> bool {
    #[cfg(target_os = "oxide-kernel")]
    {
        /// A runqueue with >=2 runnable has one running + >=1 waiting. # C: O(1)
        const WAITER_THRESHOLD: u32 = 2;
        let n = cpu::smp::online_count();
        for c in 0..n {
            // SAFETY: `global_for` reads CPU `c`'s installed runqueue slot; every
            // CPU in `0..online_count()` has completed `install_global` by the
            // time the timer tick runs, and `nr_running` is a lock-free atomic.
            if let Some(rq) = unsafe { crate::live::runqueue::global_for(c) } {
                if rq.nr_running.load(core::sync::atomic::Ordering::Acquire) >= WAITER_THRESHOLD { return true; }
            }
        }
        false
    }
    #[cfg(not(target_os = "oxide-kernel"))]
    { false }
}

/// Timer-tick PSI update: charge cpu SOME, resample the ring on the 2s cadence,
/// and wake poll/epoll waiters whose trigger just crossed. Called BSP-only from
/// `tick_poll_combined`. # C: O(N_cpu + N_ring + N_trig)
pub fn tick(now_ns: u64) {
    let some = cpu_contended();
    let mut wake: [Option<Arc<PollSubscribers>>; NRES] = [None, None, None];
    {
        let mut g = SYS.lock();
        g.account_cpu(now_ns, some);
        g.maybe_sample(now_ns);
        for i in 0..NRES {
            let res = [PsiRes::Cpu, PsiRes::Memory, PsiRes::Io][i];
            if g.poll_mask(res, now_ns) != 0 { wake[i] = g.res[i].poll_subs.clone(); }
        }
    }
    for w in wake.into_iter().flatten() { w.notify_mask(POLL_PRI); }
}

#[cfg(test)]
#[path = "tests/psi.rs"]
mod psi_tests;

#[cfg(test)]
mod trigger_parse_tests {
    use super::*;

    /// THE regression: the exact 20-byte write four systemd daemons make to
    /// /proc/pressure/memory at startup. Linux accepts it; we returned EINVAL
    /// every boot because the trailing terminator landed inside the last field.
    #[test]
    fn systemds_own_trigger_is_accepted() {
        let t = parse_trigger(b"some 200000 2000000\n", false).expect("Linux accepts this");
        assert!(!t.full);
        assert_eq!(t.threshold_ns, 200_000 * NS_PER_US);
        assert_eq!(t.window_ns, 2_000_000 * NS_PER_US);
        // `psi_write` NUL-terminates by overwriting the last byte, so a NUL
        // terminator must parse identically to a newline.
        assert_eq!(parse_trigger(b"some 200000 2000000\0", false), Ok(t));
    }

    /// `sscanf` stops at the first non-digit and ignores everything after the
    /// two fields it consumed. Rejecting a trailing token was our own rule.
    #[test]
    fn trailing_content_is_ignored_like_sscanf() {
        assert!(parse_trigger(b"full 1000000 2000000 garbage\n", false).is_ok());
        assert!(parse_trigger(b"some 200000 2000000extra\n", false).is_ok());
    }

    /// Linux has NO minimum window — only `window_us == 0 || > WINDOW_MAX_US`.
    /// A privileged caller may use a sub-second window; we rejected it outright.
    #[test]
    fn there_is_no_minimum_window() {
        assert!(parse_trigger(b"some 50000 100000\n", true).is_ok(), "100ms window, privileged");
        assert!(parse_trigger(b"some 1 0\n", true).is_err(), "zero window");
        let over = alloc::format!("some 1 {}\n", WINDOW_MAX_US as u64 + 1);
        assert!(parse_trigger(over.as_bytes(), true).is_err(), "beyond WINDOW_MAX_US");
        let at_max = alloc::format!("some 1 {}\n", WINDOW_MAX_US);
        assert!(parse_trigger(at_max.as_bytes(), true).is_ok(), "exactly WINDOW_MAX_US");
    }

    /// `!privileged && window_us % 2000000` -> EINVAL. Was missing entirely, so
    /// an unprivileged caller could register an RT-thread-grade trigger.
    #[test]
    fn an_unprivileged_window_must_be_a_multiple_of_two_seconds() {
        assert!(parse_trigger(b"some 100000 1000000\n", false).is_err(), "1s, unprivileged");
        assert!(parse_trigger(b"some 100000 1000000\n", true).is_ok(),  "1s, privileged");
        assert!(parse_trigger(b"some 100000 4000000\n", false).is_ok(), "4s is a multiple of 2s");
    }

    #[test]
    fn threshold_must_be_nonzero_and_within_the_window() {
        assert!(parse_trigger(b"some 0 2000000\n", false).is_err());
        assert!(parse_trigger(b"some 2000001 2000000\n", false).is_err());
        assert!(parse_trigger(b"some 2000000 2000000\n", false).is_ok(), "equal is allowed");
    }

    #[test]
    fn the_kind_field_must_be_some_or_full() {
        assert!(parse_trigger(b"bogus 1 2000000\n", false).is_err());
        assert!(parse_trigger(b"\n", false).is_err());
        assert!(parse_trigger(b"", false).is_err());
        assert!(parse_trigger(b"full 100000 2000000\n", false).unwrap().full);
    }
}
