// Unhandled-fatal-signal reporting: the kernel-log line a task's death by an
// unhandled synchronous fault owes the operator.
//
// `debug/exception-trace` -> `show_unhandled_signals`, printed by the ARCH
// fault path just before the signal is forced. Default 1 on x86_64, 0 on
// aarch64, per the reference's per-arch initialiser.
//
// Decision logic lives here, ungated, so it is reachable from `cargo test`;
// the emit half is a thin klog writer and the ARCH fault path is its one
// caller.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

/// Reference `DEFAULT_RATELIMIT_INTERVAL` (5 s) in nanoseconds.
pub const RATELIMIT_INTERVAL_NS: u64 = 5_000_000_000;
/// Reference `DEFAULT_RATELIMIT_BURST`.
pub const RATELIMIT_BURST: u32 = 10;

/// `sa_handler == SIG_DFL`.
pub const SIG_DFL: u64 = 0;
/// `sa_handler == SIG_IGN`.
pub const SIG_IGN: u64 = 1;

/// `show_unhandled_signals`. The reference initialises this per arch: 1 on
/// x86_64, 0 on aarch64. Keeping the arch split means a report that appears on
/// one arch and not the other is the documented default, not a porting bug.
static SHOW_UNHANDLED: AtomicBool = AtomicBool::new(cfg!(target_arch = "x86_64"));

/// Read `debug/exception-trace`. # C: O(1)
pub fn show_unhandled_signals() -> bool { SHOW_UNHANDLED.load(Ordering::Relaxed) }
/// Write `debug/exception-trace`. # C: O(1)
pub fn set_show_unhandled_signals(on: bool) { SHOW_UNHANDLED.store(on, Ordering::Relaxed) }

/// Reference `unhandled_signal(tsk, sig)`: would this signal reach its default
/// action without any userspace or tracer say in the matter?
///
/// Order is load-bearing. PID 1 reports unconditionally — its death is the
/// operator's problem whatever it had installed. A real handler means the
/// program asked to see the fault (JIT guard pages, GC write barriers), so
/// nothing is printed. A task already carrying a pending SIGKILL is on its way
/// out and its new signals are dropped, so there is nothing to report. A
/// traced task's signal belongs to its tracer, which may well suppress it.
/// # C: O(1)
pub fn unhandled_signal(handler: u64, is_global_init: bool, fatal_pending: bool, ptraced: bool) -> bool {
    if is_global_init { return true; }
    if handler != SIG_IGN && handler != SIG_DFL { return false; }
    if fatal_pending { return false; }
    !ptraced
}

/// Reference `struct ratelimit_state` over a fixed interval and burst: allow
/// up to `RATELIMIT_BURST` messages per `RATELIMIT_INTERVAL_NS`, then go quiet
/// until the interval rolls over.
pub struct RateLimit {
    begin: AtomicU64,
    printed: AtomicU32,
}

impl RateLimit {
    /// A limiter that has not yet opened an interval. # C: O(1)
    pub const fn new() -> Self { Self { begin: AtomicU64::new(0), printed: AtomicU32::new(0) } }

    /// Charge one message against the limiter at `now_ns`; `true` means print.
    ///
    /// The first call opens the interval. A call past `begin + interval` opens
    /// a fresh one, which is what keeps a slow drip of faults visible forever
    /// rather than silencing the log after the first ten.
    /// # C: O(1)
    pub fn allow(&self, now_ns: u64) -> bool {
        let begin = self.begin.load(Ordering::Relaxed);
        if begin == 0 || now_ns.wrapping_sub(begin) >= RATELIMIT_INTERVAL_NS {
            self.begin.store(now_ns, Ordering::Relaxed);
            self.printed.store(1, Ordering::Relaxed);
            return true;
        }
        let n = self.printed.fetch_add(1, Ordering::Relaxed);
        n < RATELIMIT_BURST
    }
}

impl Default for RateLimit {
    fn default() -> Self { Self::new() }
}

/// The one limiter the fault report is charged against.
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
static FAULT_RS: RateLimit = RateLimit::new();

/// Reference `show_signal_msg()`: one line naming the task that a synchronous
/// user-mode fault is about to kill, and where it died.
///
/// Called by the ARCH fault path BEFORE the signal is queued, because the
/// screen it applies (`unhandled_signal`) reads the disposition that forcing
/// the signal is about to overwrite with `SIG_DFL`. Reading it afterwards
/// would report every fault, including the ones a JIT or GC installed a
/// handler for and resolves in userspace.
/// # C: O(1)
/// # Ctx: fault, task context
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
pub fn report_user_fault(sig: u32, addr: u64, ip: u64, sp: u64, err: u64, vma: Option<VmaAddr>) {
    if !show_unhandled_signals() { return; }
    let Some(cur) = crate::live::current() else { return };
    let handler = cur.sigactions_ref().get(sig).handler;
    let is_init = cur.vtgid.load(Ordering::Relaxed) == 1;
    let fatal_pending = cur.sigpending.load(Ordering::Acquire) & crate::Signum::Sigkill.bit() != 0;
    let ptraced = cur.traced_by.load(Ordering::Acquire) != 0;
    if !unhandled_signal(handler, is_init, fatal_pending, ptraced) { return; }
    if !FAULT_RS.allow(crate::deadline::clock::now_ns()) { return; }

    let comm = cur.comm_bytes();
    klog::write_raw(crate::Task::comm_trim(&comm).as_bytes());
    klog::write_raw(b"[");
    klog::write_dec_u64(cur.vtgid.load(Ordering::Relaxed) as u64);
    klog::write_raw(b"]: ");
    klog::write_raw(fault_kind(sig));
    klog::write_raw(b" at ");   klog::write_hex_u64(addr);
    klog::write_raw(b" ip ");   klog::write_hex_u64(ip);
    klog::write_raw(b" sp ");   klog::write_hex_u64(sp);
    klog::write_raw(b" error "); klog::write_hex_u64(err);
    klog::write_raw(b" tid ");  klog::write_dec_u64(cur.tid as u64);
    cur.with_exe_path(|path| if let Some(path) = path {
        klog::write_raw(b" in ");
        klog::write_raw(path.as_bytes());
    });
    if let Some(v) = vma {
        // The reference's `print_vma_addr` tail: which mapping the faulting
        // instruction sits in, and its offset within the backing file. Without
        // it a bare `ip` names nothing — every mapping is randomised per run,
        // and the process whose `/proc/<pid>/maps` would decode it is dead by
        // the time anyone reads the log. `ino 0` means an anonymous mapping.
        klog::write_raw(b" vma ");   klog::write_hex_u64(v.start);
        klog::write_raw(b"+");       klog::write_hex_u64(v.len);
        klog::write_raw(b" ino ");   klog::write_dec_u64(v.ino);
        klog::write_raw(b" off ");   klog::write_hex_u64(v.file_off);
    }
    klog::write_raw(b"\n");
}

/// Where the faulting instruction sits: the mapping that covers it, the
/// backing inode (0 when anonymous) and the instruction's offset within that
/// file. Assembled by the ARCH fault path, which is the layer holding the mm.
#[derive(Clone, Copy)]
pub struct VmaAddr {
    /// First address of the mapping covering the faulting instruction.
    pub start: u64,
    /// Length of that mapping in bytes.
    pub len: u64,
    /// Backing inode number, 0 for an anonymous mapping.
    pub ino: u64,
    /// Offset of the faulting instruction within the backing file.
    pub file_off: u64,
}

/// The reference names the SIGSEGV case `segfault`; every other fault signal
/// is reported by the generic `unhandled exception` wording rather than being
/// dropped, so a SIGBUS or SIGILL death is not silent.
/// # C: O(1)
#[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
fn fault_kind(sig: u32) -> &'static [u8] {
    match sig {
        s if s == crate::Signum::Sigsegv.as_u8() as u32 => b"segfault",
        s if s == crate::Signum::Sigbus.as_u8()   as u32 => b"bus error",
        s if s == crate::Signum::Sigill.as_u8()   as u32 => b"illegal instruction",
        s if s == crate::Signum::Sigfpe.as_u8()   as u32 => b"fp exception",
        s if s == crate::Signum::Sigtrap.as_u8()  as u32 => b"trap",
        _ => b"unhandled exception",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_caught_signal_is_never_reported() {
        assert!(!unhandled_signal(0x4001_0000, false, false, false));
    }

    #[test]
    fn default_and_ignored_dispositions_are_both_reported() {
        assert!(unhandled_signal(SIG_DFL, false, false, false));
        assert!(unhandled_signal(SIG_IGN, false, false, false));
    }

    #[test]
    fn pid_one_is_reported_even_with_a_handler_installed() {
        assert!(unhandled_signal(0x4001_0000, true, false, false));
    }

    #[test]
    fn a_task_already_carrying_sigkill_is_not_reported() {
        assert!(!unhandled_signal(SIG_DFL, false, true, false));
    }

    #[test]
    fn a_traced_task_leaves_the_decision_to_its_tracer() {
        assert!(!unhandled_signal(SIG_DFL, false, false, true));
    }

    #[test]
    fn pid_one_outranks_both_the_dying_and_the_traced_screen() {
        assert!(unhandled_signal(SIG_DFL, true, true, true));
    }

    #[test]
    fn the_burst_is_ten_messages_then_silence_within_one_interval() {
        let rl = RateLimit::new();
        // Interval opens at t=1 and that first message counts against the burst.
        assert!(rl.allow(1));
        for i in 1..RATELIMIT_BURST as u64 { assert!(rl.allow(1 + i), "message {i} inside burst"); }
        assert!(!rl.allow(1 + RATELIMIT_BURST as u64));
        assert!(!rl.allow(RATELIMIT_INTERVAL_NS - 1));
    }

    #[test]
    fn the_interval_rolling_over_re_opens_the_burst() {
        let rl = RateLimit::new();
        for _ in 0..RATELIMIT_BURST + 5 { rl.allow(1); }
        assert!(!rl.allow(1));
        assert!(rl.allow(1 + RATELIMIT_INTERVAL_NS));
    }

    #[test]
    fn a_zero_timestamp_still_opens_an_interval() {
        let rl = RateLimit::new();
        assert!(rl.allow(0));
    }

    // The knob is process-global, so a test that WRITES it races every other
    // test in the binary. Its default is asserted read-only here; the write
    // path is covered where it is reachable from userspace, by the procfs
    // sysctl tests.

    #[test]
    fn exception_trace_defaults_on_for_x86_64_and_off_for_aarch64() {
        assert_eq!(show_unhandled_signals(), cfg!(target_arch = "x86_64"));
    }
}
