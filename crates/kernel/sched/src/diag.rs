// Liveness diagnostics: on-demand task-state dump (serial sysrq) +
// a no-progress liveness watchdog. Per `05` pre-mortem fix
// ("liveness watchdog (no-progress-N-sec)") and `27`'s `kernel.sysrq`
// surface.
//
// Purpose: when the boot wedges before `login:` appears, the machine
// otherwise emits *nothing* — we cannot tell a CPU-bound spin (soft
// lockup) from a lost-wakeup park (everything Sleeping, nothing wakes
// it) from a page-fault loop. This module makes both observable:
//
//   * `dump_tasks()` — sysrq `show-state`-style table of every live
//     task: vpid/tid, name, R/S/T/Z, on_rq, cpu, last syscall + count,
//     CPU time, and time-since-last-switched-in. Emits zero bytes
//     until triggered, so it respects the gated-klog rule (`04 R06`).
//   * `watchdog_tick()` — called from the BSP timer tick. Fires a
//     one-shot lockup banner + dump if a *Runnable* task holds the CPU
//     with no context switch for longer than the stall threshold. A
//     genuinely idle machine (current == idle, or current Sleeping)
//     never trips it — that is healthy "waiting for input", not a hang.
//   * `sysrq_rx()` — UART RX filter: a magic prefix byte arms sysrq,
//     the next byte selects a command. Lets a human (or the qemu MCP)
//     pull a dump on demand even when the watchdog sees a "healthy"
//     idle wedge.
//
// All emit paths use `klog::write_raw`/`write_dec_u64`/`write_hex_u64`,
// which are allocation-free and safe from IRQ / panic context.

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

use crate::{Task, TaskState};

/// Per-CPU heartbeat + cross-CPU hard-lockup detector (sees a frozen
/// CPU from a different CPU, which the BSP-tick watchdog cannot).
pub mod percpu;
/// NMI/FIQ backtrace: poke a (possibly IRQ-masked) CPU into dumping its
/// own register state.
pub mod nmi;

/// Borrow the running task. Kernel-only (`live` is gated to the kernel
/// target); on the hosted test target there is no live runqueue, so it
/// is `None` — the pure watchdog/formatting logic is exercised through
/// `WatchdogState::step` and the formatting helpers directly.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
fn current_task() -> Option<&'static Task> {
    crate::live::current()
}
#[cfg(not(target_os = "oxide-kernel"))]
fn current_task() -> Option<&'static Task> {
    None
}

/// Monotonic count of real context switches (prev != next), bumped by
/// the scheduler at both switch sites. Never reset (unlike the stats
/// `VOLUNTARY`/`IRQ_SW` counters, which `swap(0)` on read) so the
/// watchdog can use it as a forward-progress beat.
static SWITCHES: AtomicU64 = AtomicU64::new(0);

/// Note a real context switch. Called from `schedule()` /
/// `schedule_from_irq()` only when `prev != next`.
/// # C: O(1)
pub fn note_switch() {
    SWITCHES.fetch_add(1, Ordering::Relaxed);
}

/// Live switch count.
/// # C: O(1)
pub fn switches() -> u64 {
    SWITCHES.load(Ordering::Relaxed)
}

// ---- recent-syscall ring (why did a task exit?) ----
//
// A global lock-free ring of the last RING_N (tid, nr, ret) tuples,
// recorded at syscall-return. Dumped on INIT-DEATH so a PID-1 exit shows
// the syscall(s) that preceded it — e.g. an `execve = -ENOENT` right
// before `exit_group(127)` pins a flaky exec/loader failure that the
// single last_syscall field (which only shows the exit itself) can't.
// Recording is always-on + klog-free (1 fetch_add + 3 relaxed stores);
// only the dump rides `debug-watchdog`.

const RING_N: usize = 512;
static RING_TID: [AtomicU32; RING_N] = [const { AtomicU32::new(0) }; RING_N];
static RING_NR: [AtomicU32; RING_N] = [const { AtomicU32::new(u32::MAX) }; RING_N];
static RING_RET: [core::sync::atomic::AtomicI64; RING_N] =
    [const { core::sync::atomic::AtomicI64::new(0) }; RING_N];
static RING_POS: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

/// Record a completed syscall `(current tid, nr, ret)` into the ring.
/// Called at syscall-return. No-op off the kernel target.
/// # C: O(1)
pub fn record_syscall(nr: u32, ret: i64) {
    let tid = match current_task() {
        Some(t) => t.tid,
        None => return,
    };
    let i = RING_POS.fetch_add(1, Ordering::Relaxed) % RING_N;
    RING_TID[i].store(tid, Ordering::Relaxed);
    RING_NR[i].store(nr, Ordering::Relaxed);
    RING_RET[i].store(ret, Ordering::Relaxed);
}

/// Dump the most recent ring entries for `tid` (newest first). Used by
/// the INIT-DEATH report to show what PID 1 did right before it exited.
/// # C: O(RING_N)
#[cfg(feature = "debug-watchdog")]
fn dump_recent_for(tid: u32) {
    klog::write_raw(b"  recent syscalls (newest first):\n");
    let pos = RING_POS.load(Ordering::Relaxed);
    let mut shown = 0u32;
    let mut k = 0usize;
    while k < RING_N && shown < 40 {
        // newest is at (pos-1); walk backwards.
        let i = (pos + RING_N - 1 - k) % RING_N;
        k += 1;
        if RING_NR[i].load(Ordering::Relaxed) == u32::MAX {
            continue;
        }
        if RING_TID[i].load(Ordering::Relaxed) != tid {
            continue;
        }
        klog::write_raw(b"    ");
        emit_syscall(RING_NR[i].load(Ordering::Relaxed));
        klog::write_raw(b" = ");
        let r = RING_RET[i].load(Ordering::Relaxed);
        if r < 0 {
            klog::write_raw(b"-");
            klog::write_dec_u64((-r) as u64);
        } else {
            klog::write_dec_u64(r as u64);
        }
        klog::write_raw(b"\n");
        shown += 1;
    }
    if shown == 0 {
        klog::write_raw(b"    <none recorded>\n");
    }
}

/// Dump the current task's recent syscalls when it exits non-zero — pins the
/// failing syscall behind a service's `status=1/FAILURE` (e.g. systemd-udevd /
/// systemd-journald failing init). No-op for clean (code 0) exits. Rides
/// `debug-watchdog`.
/// # C: O(RING_N)
#[cfg(feature = "debug-watchdog")]
pub fn dump_exit_recent(name: &str, code: u64) {
    if code == 0 { return; }
    klog::write_raw(b"[EXIT] name=");
    klog::write_raw(name.as_bytes());
    if let Some(t) = current_task() {
        // SAFETY: running task on this CPU; single-mutator read of the exe_path
        // slot per `13§5`. Identifies WHICH binary exited (name is the static
        // "fork-child" — exe_path is the execve'd path, e.g. systemd-journald).
        if let Some(p) = unsafe { &*t.exe_path.get() } {
            klog::write_raw(b" exe=");
            klog::write_raw(p.as_bytes());
        }
    }
    klog::write_raw(b" code=");
    klog::write_dec_u64(code);
    klog::write_raw(b"\n");
    if let Some(t) = current_task() { dump_recent_for(t.tid); }
}
/// Off-watchdog no-op.
/// # C: O(1)
#[cfg(not(feature = "debug-watchdog"))]
pub fn dump_exit_recent(_name: &str, _code: u64) {}

impl Task {
    /// Record entry into syscall `nr` (x86_64 table key). Always-on
    /// (two relaxed atomics) so the sysrq/watchdog dump can show where
    /// a stalled task last entered the kernel even in a non-debug build.
    /// # C: O(1)
    pub fn note_syscall(&self, nr: u32) {
        self.last_syscall_nr.store(nr, Ordering::Relaxed);
        self.nsyscalls.fetch_add(1, Ordering::Relaxed);
    }
}

// ---- watchdog ----

/// Stall threshold: a Runnable task holding the CPU with no context
/// switch for this long is reported as a soft lockup. 10 s is long
/// enough that normal long syscalls / heavy boot work don't
/// false-positive, short enough to catch a wedge well before a human
/// gives up on `login:`.
const STALL_NS: u64 = 10_000_000_000;

/// Per-tick observation fed to the watchdog decision function.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Beat {
    /// tid of the task on-CPU (0 if idle/none).
    pub tid: u32,
    /// true iff that task is Runnable and not the idle class — i.e.
    /// actually trying to run, not parked on a wait queue.
    pub runnable: bool,
    /// live monotonic switch count.
    pub switches: u64,
    /// current monotonic time (ns).
    pub now_ns: u64,
}

/// Pure watchdog state machine — no I/O, no atomics — so the stall
/// decision is fully host-testable. The kernel wrapper
/// (`watchdog_tick`) snapshots this behind a spinlock-free atomic set
/// and prints when `step` returns `Some(stall_secs)`.
#[derive(Copy, Clone, Debug)]
pub struct WatchdogState {
    window_tid: u32,
    window_switches: u64,
    window_start_ns: u64,
    fired: bool,
    armed: bool,
}

impl WatchdogState {
    /// # C: O(1)
    pub const fn new() -> Self {
        Self { window_tid: 0, window_switches: 0, window_start_ns: 0, fired: false, armed: false }
    }

    /// Advance one tick. Returns `Some(stall_seconds)` exactly once per
    /// distinct stall (the tick that first crosses `STALL_NS`); `None`
    /// otherwise. A tid change, a switch, or a non-runnable/idle CPU
    /// resets the window and re-arms the detector.
    /// # C: O(1)
    pub fn step(&mut self, b: Beat) -> Option<u64> {
        // CPU idle / task parked → healthy wait. Disarm.
        if !b.runnable {
            self.armed = false;
            self.fired = false;
            return None;
        }
        // Open a fresh window on any forward progress, OR on the
        // transition back into a runnable state from idle/park.
        if !self.armed || b.tid != self.window_tid || b.switches != self.window_switches {
            self.window_tid = b.tid;
            self.window_switches = b.switches;
            self.window_start_ns = b.now_ns;
            self.fired = false;
            self.armed = true;
            return None;
        }
        // Same runnable task, no switch since the window opened.
        let elapsed = b.now_ns.wrapping_sub(self.window_start_ns);
        if elapsed < STALL_NS || self.fired {
            return None;
        }
        self.fired = true;
        Some(elapsed / 1_000_000_000)
    }
}

// Kernel-side watchdog: single-CPU v1, one global state set guarded by
// the fact that `watchdog_tick` is only ever called from the BSP timer
// ISR (serialised). Stored as raw atomics to stay lock-free.
static WD_TID: AtomicU32 = AtomicU32::new(0);
static WD_SWITCHES: AtomicU64 = AtomicU64::new(0);
static WD_START_NS: AtomicU64 = AtomicU64::new(0);
static WD_FIRED: AtomicBool = AtomicBool::new(false);
static WD_ARMED: AtomicBool = AtomicBool::new(false);

/// Liveness watchdog, called once per BSP timer tick with the current
/// monotonic time. On the first tick a forward-progress stall crosses
/// `STALL_NS`, prints a lockup banner + full task dump (per `05`).
/// # C: O(1) on the common path; O(N_tasks) only when firing.
pub fn watchdog_tick(now_ns: u64) {
    let cur = current_task();
    let runnable = match cur {
        Some(t) => t.state() == TaskState::Runnable
            && !matches!(t.sched_class(), crate::SchedClass::Idle),
        None => false,
    };
    let beat = Beat {
        tid: cur.map(|t| t.tid).unwrap_or(0),
        runnable,
        switches: SWITCHES.load(Ordering::Relaxed),
        now_ns,
    };

    let mut st = WatchdogState {
        window_tid: WD_TID.load(Ordering::Relaxed),
        window_switches: WD_SWITCHES.load(Ordering::Relaxed),
        window_start_ns: WD_START_NS.load(Ordering::Relaxed),
        fired: WD_FIRED.load(Ordering::Relaxed),
        armed: WD_ARMED.load(Ordering::Relaxed),
    };
    let fired = st.step(beat);
    WD_TID.store(st.window_tid, Ordering::Relaxed);
    WD_SWITCHES.store(st.window_switches, Ordering::Relaxed);
    WD_START_NS.store(st.window_start_ns, Ordering::Relaxed);
    WD_FIRED.store(st.fired, Ordering::Relaxed);
    WD_ARMED.store(st.armed, Ordering::Relaxed);

    if let Some(_secs) = fired {
        #[cfg(feature = "debug-watchdog")]
        report_lockup(_secs, beat.tid, cur);
    }

    // No-progress detector: catches a PARKED wedge (everything Sleeping,
    // a lost wakeup — the soft-lockup detector above disarms on !runnable
    // and never sees it). If the global switch count hasn't advanced for
    // NOPROG_NS, dump every task's state once so a parked deadlock is not
    // silent. Re-arms when switches advance again.
    let sw = beat.switches;
    let last_sw = WD_NOPROG_SW.load(Ordering::Relaxed);
    if sw != last_sw {
        WD_NOPROG_SW.store(sw, Ordering::Relaxed);
        WD_NOPROG_NS.store(now_ns, Ordering::Relaxed);
        WD_NOPROG_FIRED.store(false, Ordering::Relaxed);
    } else {
        let since = now_ns.wrapping_sub(WD_NOPROG_NS.load(Ordering::Relaxed));
        if since >= NOPROG_NS && !WD_NOPROG_FIRED.swap(true, Ordering::Relaxed) {
            #[cfg(feature = "debug-watchdog")]
            {
                klog::write_raw(b"\n[WATCHDOG] no-progress: 0 context switches for ");
                klog::write_dec_u64(since / 1_000_000_000);
                klog::write_raw(b"s (parked wedge?) task dump:\n");
                dump_tasks();
            }
        }
    }
}

/// No-progress threshold for the parked-wedge detector. Longer than the
/// soft-lockup STALL_NS since a healthy boot can legitimately have brief
/// all-parked windows (e.g. waiting on a disk read); 15 s with zero
/// context switches during boot is a genuine deadlock.
const NOPROG_NS: u64 = 40_000_000_000;
static WD_NOPROG_SW: AtomicU64 = AtomicU64::new(0);
static WD_NOPROG_NS: AtomicU64 = AtomicU64::new(0);
static WD_NOPROG_FIRED: AtomicBool = AtomicBool::new(false);

/// Emit the soft-lockup banner + task dump. Gated: the watchdog *logic*
/// (counters, state machine) is always-on and silent; only this report
/// path emits, and only when a stall actually fires (`04` R06).
/// # C: O(N_tasks)
#[cfg(feature = "debug-watchdog")]
fn report_lockup(secs: u64, tid: u32, cur: Option<&Task>) {
    klog::write_raw(b"\n[WATCHDOG] soft lockup: no reschedule for ");
    klog::write_dec_u64(secs);
    klog::write_raw(b"s on tid=");
    klog::write_dec_u64(tid as u64);
    if let Some(t) = cur {
        klog::write_raw(b" (");
        klog::write_raw(t.name.as_bytes());
        klog::write_raw(b") last_syscall=");
        emit_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
    }
    klog::write_raw(b"\n");
    dump_tasks();
}

/// Print a sysrq `show-state`-style table of every live task. Emits
/// nothing unless built with `debug-watchdog` (`04` R06); the call
/// site stays always-present so wiring compiles unconditionally.
/// # C: O(N_tasks)
pub fn dump_tasks() {
    #[cfg(feature = "debug-watchdog")]
    dump_tasks_emit();
}

/// Best-effort table emit: a contended registry lock reports "registry
/// busy" rather than blocking — the point is to diagnose a wedge
/// without adding a new way to wedge.
/// # C: O(N_tasks)
#[cfg(feature = "debug-watchdog")]
fn dump_tasks_emit() {
    klog::write_raw(b"[sysrq] task dump  switches=");
    klog::write_dec_u64(SWITCHES.load(Ordering::Relaxed));
    if let Some(t) = current_task() {
        klog::write_raw(b" current=tid:");
        klog::write_dec_u64(t.tid as u64);
    }
    klog::write_raw(b"\n  PID   TID name             ST onrq cpu  last-sysc  nsysc      cputime_ms\n");

    let tasks = match crate::registry::try_snapshot() {
        Some(v) => v,
        None => {
            klog::write_raw(b"  <registry busy - lock held; cannot snapshot>\n");
            return;
        }
    };
    for t in tasks.iter() {
        let vpid = t.vtgid.load(Ordering::Relaxed);
        col_dec(if vpid != 0 { vpid as u64 } else { t.tid as u64 }, 5);
        klog::write_raw(b" ");
        col_dec(t.tid as u64, 6);
        klog::write_raw(b" ");
        col_str(t.name, 16);
        klog::write_raw(b" ");
        klog::write_raw(&[t.state().linux_char()]);
        klog::write_raw(b"  ");
        klog::write_raw(if t.on_rq.load(Ordering::Relaxed) { b"y  " } else { b"n  " });
        let cpu = t.cpu.load(Ordering::Relaxed);
        if cpu == u16::MAX { klog::write_raw(b"  -"); } else { col_dec(cpu as u64, 3); }
        klog::write_raw(b"  ");
        col_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
        klog::write_raw(b" ");
        col_dec(t.nsyscalls.load(Ordering::Relaxed), 10);
        klog::write_raw(b" ");
        col_dec(t.sum_exec_runtime_ns.load(Ordering::Relaxed) / 1_000_000, 10);
        // tgid/vtid/parent_tid expose thread-group structure: rows sharing a
        // `tgid` are sibling threads of one process. Lets the wedge dump prove
        // multi-threaded vs single-threaded (and which thread holds a lock).
        klog::write_raw(b" tgid=");  col_dec(t.tgid.load(Ordering::Relaxed) as u64, 6);
        klog::write_raw(b" vtid=");  col_dec(t.vtid.load(Ordering::Relaxed) as u64, 6);
        klog::write_raw(b" ptid="); col_dec(t.parent_tid.load(Ordering::Relaxed) as u64, 6);
        // Futex wait address (0 = not parked in a futex). On a wedge this shows
        // which lock each blocked task waits on — a holder for that address
        // among the runnable/other rows pinpoints the deadlock.
        let fux = t.futex_uaddr.load(Ordering::Relaxed);
        if fux != 0 { klog::write_raw(b" fux="); klog::write_hex_u64(fux); }
        // exe= identifies the binary behind the static "fork-child" name — on a
        // futex wedge this names WHICH program deadlocked on the inherited lock.
        // SAFETY: dump runs with scheduling effectively quiesced (watchdog/sysrq
        // context); single-mutator read of the exe_path slot per `13§5`.
        if let Some(p) = unsafe { &*t.exe_path.get() } {
            klog::write_raw(b" exe="); klog::write_raw(p.as_bytes());
        }
        klog::write_raw(b"\n");
    }
}

/// Announce that PID 1 (init) has exited. This is fatal: with no init
/// there is nothing left to run, so the box idles forever and presents
/// as a silent hang (the flaky-login failure mode — systemd exits ~25%
/// of SMP=2 boots right after keymap load instead of spawning getty).
/// Linux panics here ("Attempted to kill init!"); we at minimum make it
/// loud + dump the final task table so the cause is never again silent.
/// # C: O(N_tasks)
pub fn note_init_exit(code: i32) {
    #[cfg(feature = "debug-watchdog")]
    {
        klog::write_raw(b"\n[INIT-DEATH] PID 1 (init) exited code=");
        klog::write_dec_u64(code as u64);
        klog::write_raw(b" - no init, system will hang (Linux would panic)\n");
        // The syscalls PID 1 made right before exiting — an `execve =
        // -<errno>` here pins a flaky exec/loader failure (code 127).
        if let Some(t) = current_task() {
            dump_recent_for(t.tid);
        }
        dump_tasks();
    }
    #[cfg(not(feature = "debug-watchdog"))]
    let _ = code;
}

// ---- serial sysrq ----

/// Magic prefix byte that arms sysrq. NUL is never produced by a
/// terminal keyboard and is stripped by line disciplines, so using it
/// as the arming byte avoids colliding with shell input. The qemu MCP
/// `qemu_send_serial` can emit it directly.
const SYSRQ_ARM: u8 = 0x00;

static SYSRQ_ARMED: AtomicBool = AtomicBool::new(false);

/// UART RX filter. Returns `true` if the byte was consumed as a sysrq
/// sequence (caller must NOT forward it to the tty), `false` otherwise.
///
/// Sequence: `<NUL> <cmd>` where `<cmd>` is:
///   `t` — dump tasks
///   `w` — dump watchdog/current summary
/// An unknown `<cmd>` after the arm byte is swallowed (and a help line
/// printed) so a stray NUL never injects garbage into the shell.
/// # C: O(1); O(N_tasks) on `t`.
pub fn sysrq_rx(b: u8) -> bool {
    if SYSRQ_ARMED.swap(false, Ordering::Relaxed) {
        #[cfg(feature = "debug-watchdog")]
        sysrq_cmd(b);
        return true;
    }
    if b == SYSRQ_ARM {
        SYSRQ_ARMED.store(true, Ordering::Relaxed);
        return true;
    }
    false
}

/// Execute a sysrq command byte. Gated with the rest of the emit path.
/// # C: O(N_tasks) on `t`.
#[cfg(feature = "debug-watchdog")]
fn sysrq_cmd(b: u8) {
    match b {
        b't' => dump_tasks(),
        b'w' => {
            klog::write_raw(b"[sysrq] switches=");
            klog::write_dec_u64(SWITCHES.load(Ordering::Relaxed));
            if let Some(t) = current_task() {
                klog::write_raw(b" current=tid:");
                klog::write_dec_u64(t.tid as u64);
                klog::write_raw(b" state=");
                klog::write_raw(&[t.state().linux_char()]);
                klog::write_raw(b" last_syscall=");
                emit_syscall(t.last_syscall_nr.load(Ordering::Relaxed));
            }
            klog::write_raw(b"\n");
        }
        b'c' => percpu::dump_cpus(),
        b'b' => nmi::backtrace_all(),
        _ => klog::write_raw(b"[sysrq] keys: t=tasks w=watchdog c=per-cpu b=backtrace-all\n"),
    }
}

// ---- formatting helpers (allocation-free, fixed-width columns) ----
// Pure helpers (no klog) are also compiled under `test` so the hosted
// suite can exercise them; the klog-emitting column writers ride the
// `debug-watchdog` feature with the rest of the emit path.

/// Short name for the syscalls that matter to a login/getty/shell
/// stall; decimal nr otherwise. Names use the x86_64 table key (the
/// dispatch normalises arm64 to it).
#[cfg(any(feature = "debug-watchdog", test))]
fn syscall_name(nr: u32) -> Option<&'static str> {
    use syscall::nrs::*;
    Some(match nr as u64 {
        NR_READ => "read",
        NR_WRITE => "write",
        NR_POLL => "poll",
        NR_PPOLL => "ppoll",
        NR_SELECT => "select",
        NR_PSELECT6 => "pselect6",
        NR_IOCTL => "ioctl",
        NR_PAUSE => "pause",
        NR_NANOSLEEP => "nanosleep",
        NR_CLOCK_NANOSLEEP => "clk_nanosl",
        NR_RT_SIGTIMEDWAIT => "sigtimedwt",
        NR_FUTEX => "futex",
        NR_EPOLL_WAIT => "epoll_wait",
        NR_EPOLL_PWAIT => "epoll_pwt",
        NR_WAIT4 => "wait4",
        NR_WAITID => "waitid",
        NR_ACCEPT => "accept",
        NR_ACCEPT4 => "accept4",
        NR_EXECVE => "execve",
        NR_CLONE => "clone",
        NR_FORK => "fork",
        _ => return None,
    })
}

#[cfg(feature = "debug-watchdog")]
fn emit_syscall(nr: u32) {
    if nr == u32::MAX {
        klog::write_raw(b"none");
    } else if let Some(n) = syscall_name(nr) {
        klog::write_raw(n.as_bytes());
    } else {
        klog::write_raw(b"nr#");
        klog::write_dec_u64(nr as u64);
    }
}

/// Emit the last-syscall column padded to 10 chars.
#[cfg(feature = "debug-watchdog")]
fn col_syscall(nr: u32) {
    let mut buf = [b' '; 10];
    let written = if nr == u32::MAX {
        copy_into(&mut buf, b"none")
    } else if let Some(n) = syscall_name(nr) {
        copy_into(&mut buf, n.as_bytes())
    } else {
        // "nr#NNN"
        let mut tmp = [0u8; 10];
        let p = fmt_dec(nr as u64, &mut tmp);
        let mut w = copy_into(&mut buf, b"nr#");
        let mut i = 0;
        while w < buf.len() && i < (tmp.len() - p) {
            buf[w] = tmp[p + i];
            w += 1;
            i += 1;
        }
        w
    };
    let _ = written;
    klog::write_raw(&buf);
}

/// Right-justify `v` in a `width`-byte field and emit it.
#[cfg(feature = "debug-watchdog")]
fn col_dec(v: u64, width: usize) {
    let mut tmp = [0u8; 20];
    let start = fmt_dec(v, &mut tmp);
    let ndigits = tmp.len() - start;
    let mut i = ndigits;
    while i < width {
        klog::write_raw(b" ");
        i += 1;
    }
    klog::write_raw(&tmp[start..]);
}

/// Left-justify `s` (truncated) in a `width`-byte field and emit it.
#[cfg(feature = "debug-watchdog")]
fn col_str(s: &str, width: usize) {
    let b = s.as_bytes();
    let n = if b.len() > width { width } else { b.len() };
    klog::write_raw(&b[..n]);
    let mut i = n;
    while i < width {
        klog::write_raw(b" ");
        i += 1;
    }
}

/// Format `v` decimal into the *tail* of `buf`; return the start index.
#[cfg(any(feature = "debug-watchdog", test))]
fn fmt_dec(mut v: u64, buf: &mut [u8]) -> usize {
    let mut i = buf.len();
    if v == 0 {
        i -= 1;
        buf[i] = b'0';
        return i;
    }
    while v > 0 && i > 0 {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
    }
    i
}

/// Copy `src` into `dst` from index 0; return bytes written.
#[cfg(any(feature = "debug-watchdog", test))]
fn copy_into(dst: &mut [u8], src: &[u8]) -> usize {
    let n = if src.len() > dst.len() { dst.len() } else { src.len() };
    dst[..n].copy_from_slice(&src[..n]);
    n
}

#[cfg(test)]
mod tests;
