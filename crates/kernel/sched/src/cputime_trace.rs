// [CPUT] process-CPU-clock accounting trace.
//
// Built for B1455, where `wait_diff`'s `cputime|sibling_burn_completes` read
// `cpu=0` with `burn=1`: a sibling thread burned CPU for seconds and
// `CLOCK_PROCESS_CPUTIME_ID` never moved. The static chain checked out, so the
// break had to be dynamic, and these five events separate every candidate in
// ONE boot:
//
//   `join` grp=X vs `tick` grp=Y   -> the sibling is charged into another group
//   `tick` grp right, ns rising, but `arm`/`disarm` sampling a flat `now`
//                                  -> the sample reads what the charge doesn't
//   `clone` flags without IF       -> the thread can never be interrupted
//   `irq` absent while `ticks=` is flat across a window
//                                  -> no timer interrupt reached the CPU
//
// The last one is what fired: `ticks=` was identical either side of a 5 s
// window, i.e. the accounting tick had been postponed out of existence. Keep
// the probe — the same four questions come back on any accounting regression.
//
// Feature-gated — a default build compiles the empty arms and emits nothing.

use core::sync::atomic::{AtomicU64, Ordering};

/// Ticks between `[CPUT tick]` lines. A tick trace at full rate floods the
/// UART faster than it drains and skews the very accounting under test.
#[cfg(feature = "debug-cputime")]
const TICK_TRACE_STRIDE: u64 = 16;

#[cfg(feature = "debug-cputime")]
static TICK_SEQ: AtomicU64 = AtomicU64::new(0);

/// Every timer interrupt this CPU has taken, counted before any filter. Printed
/// on the non-tick events so a window with no `[CPUT irq]` line can be told
/// apart from a window whose lines were lost.
#[cfg(feature = "debug-cputime")]
static TICKS: AtomicU64 = AtomicU64::new(0);

/// # C: O(1)
#[cfg(feature = "debug-cputime")]
fn emit_ticks() {
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(TICKS.load(Ordering::Relaxed));
}

/// Every timer tick, before any early return — separates "the timer vector
/// never fired" from "it fired and the charge was skipped". # C: O(1) # Ctx: IRQ
#[cfg(feature = "debug-cputime")]
pub fn tick_entry(now_ns: u64, prev_ns: u64, has_current: bool) {
    if TICKS.fetch_add(1, Ordering::Relaxed) % TICK_TRACE_STRIDE != 0 { return; }
    klog::write_raw(b"[CPUT irq now=");
    klog::write_dec_u64(now_ns);
    klog::write_raw(b" prev=");
    klog::write_dec_u64(prev_ns);
    klog::write_raw(b" cur=");
    klog::write_dec_u64(has_current as u64);
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(feature = "debug-cputime"))]
pub fn tick_entry(_now_ns: u64, _prev_ns: u64, _has_current: bool) {}

/// One accounting tick: who was charged, into which `ThreadGroup`, and the
/// running totals the process clock samples. # C: O(1) # Ctx: IRQ
#[cfg(feature = "debug-cputime")]
pub fn tick(task: &crate::Task, from_user: bool, delta_ns: u64) {
    if TICK_SEQ.fetch_add(1, Ordering::Relaxed) % TICK_TRACE_STRIDE != 0 { return; }
    let (user, system) = task.thread_group.cpu_sample();
    klog::write_raw(b"[CPUT tick tid=");
    klog::write_dec_u64(task.tid as u64);
    klog::write_raw(b" tgid=");
    klog::write_dec_u64(task.tgid.load(Ordering::Relaxed) as u64);
    klog::write_raw(b" grp=");
    klog::write_hex_u64(alloc::sync::Arc::as_ptr(&task.thread_group) as u64);
    klog::write_raw(b" fu=");
    klog::write_dec_u64(from_user as u64);
    klog::write_raw(b" d=");
    klog::write_dec_u64(delta_ns);
    klog::write_raw(b" u=");
    klog::write_dec_u64(user);
    klog::write_raw(b" s=");
    klog::write_dec_u64(system);
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(feature = "debug-cputime"))]
pub fn tick(_task: &crate::Task, _from_user: bool, _delta_ns: u64) {}

/// A task joining an existing thread group — names the `Arc` the sibling will
/// be charged into, so a mismatch with `tick` is visible. # C: O(1)
#[cfg(feature = "debug-cputime")]
pub fn join(tid: u32, group: &alloc::sync::Arc<crate::thread_group::ThreadGroup>) {
    klog::write_raw(b"[CPUT join tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" grp=");
    klog::write_hex_u64(alloc::sync::Arc::as_ptr(group) as u64);
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(feature = "debug-cputime"))]
pub fn join(_tid: u32, _group: &alloc::sync::Arc<crate::thread_group::ThreadGroup>) {}

/// The user-mode resume state a `clone(2)` child is built with. RFLAGS is the
/// one that decides whether the timer tick can ever preempt it. # C: O(1)
#[cfg(feature = "debug-cputime")]
pub fn clone_frame(tid: u32, ip: u64, sp: u64, flags: u64) {
    klog::write_raw(b"[CPUT clone tid=");
    klog::write_dec_u64(tid as u64);
    klog::write_raw(b" ip=");
    klog::write_hex_u64(ip);
    klog::write_raw(b" sp=");
    klog::write_hex_u64(sp);
    klog::write_raw(b" flags=");
    klog::write_hex_u64(flags);
    emit_ticks();
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(feature = "debug-cputime"))]
pub fn clone_frame(_tid: u32, _ip: u64, _sp: u64, _flags: u64) {}

/// A CPU-clock sleep arming, waking, or disarming: the sampled `now` against
/// the projected expiry, off the same clock the sleep waits on. # C: O(1)
#[cfg(feature = "debug-cputime")]
pub fn sleep(what: &'static [u8], task: &crate::Task, now_ns: u64, deadline_ns: u64) {
    klog::write_raw(b"[CPUT ");
    klog::write_raw(what);
    klog::write_raw(b" tid=");
    klog::write_dec_u64(task.tid as u64);
    klog::write_raw(b" tgid=");
    klog::write_dec_u64(task.tgid.load(Ordering::Relaxed) as u64);
    klog::write_raw(b" grp=");
    klog::write_hex_u64(alloc::sync::Arc::as_ptr(&task.thread_group) as u64);
    klog::write_raw(b" now=");
    klog::write_dec_u64(now_ns);
    klog::write_raw(b" dl=");
    klog::write_dec_u64(deadline_ns);
    emit_ticks();
    klog::write_raw(b"]\n");
}

/// # C: O(1)
#[cfg(not(feature = "debug-cputime"))]
pub fn sleep(_what: &'static [u8], _task: &crate::Task, _now_ns: u64, _deadline_ns: u64) {}
