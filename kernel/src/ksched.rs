// Cooperative round-robin scheduler smoke per `13§3`.
//
// Holds N+1 saved `Context` slots (N kthreads + 1 boot frame), a
// boxed kernel stack per kthread, and a current-index cursor. A
// kthread calls `yield_now()` → saves into its own slot, advances
// the cursor (skipping any kthread that has marked itself `done`),
// loads the next slot. After every kthread's iteration budget is
// exhausted, `yield_now()` picks the boot slot, returning control
// to the smoke driver.
//
// Pre-runqueue: keeps logic kernel-side until `crates/sched`'s
// Task gets `kernel_stack` + `context` per spec `13§5`. This
// proves N-way fairness + stack discipline; gated under
// `debug-sched` (hence elided in production).

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicUsize, Ordering};
use hal::Context;

#[cfg(target_arch = "x86_64")]
type ArchCtx = hal_x86_64::ContextX86_64;
#[cfg(target_arch = "aarch64")]
type ArchCtx = hal_aarch64::ContextAArch64;

const STACK_BYTES: usize = 16 * 1024;

struct KThread {
    ctx:    ArchCtx,
    _stack: Box<[u8]>,
    done:   AtomicBool,
    yields: AtomicU32,
    /// Timer ticks observed while this kthread was current.
    ticks:  AtomicU32,
}

/// Tiny single-CPU cooperative round-robin. Idx 0 is the boot frame;
/// idx 1..=N are kthreads. `cur` tracks who is *currently running*.
pub struct KSched {
    boot:    ArchCtx,
    kts:     Vec<KThread>,
    cur:     AtomicUsize,    // 0 = boot, 1..=N = kthread index
}

/// Global scheduler cell; pre-init / single-CPU only.
struct SchedCell(UnsafeCell<Option<KSched>>);
// SAFETY: Initialized once from kernel_main; mutated only via the
// single-CPU pre-init path; kthreads run on the same CPU so no
// concurrent writers exist for the lifetime of the smoke.
unsafe impl Sync for SchedCell {}
static SCHED: SchedCell = SchedCell(UnsafeCell::new(None));

/// Reborrow as a uniquely-owned reference. SAFETY: caller is the
/// boot path or a kthread running under `SCHED` exclusively
/// (single-CPU pre-init); no concurrent borrows exist.
unsafe fn sched_mut<'a>() -> &'a mut KSched {
    // SAFETY: SCHED.0 is single-init in `smoke_rr()`; kthreads run on the same CPU; no concurrent writers.
    unsafe { (*SCHED.0.get()).as_mut().unwrap() }
}

extern "C" fn rr_kthread_entry(arg: usize) -> ! {
    let me = arg; // 1-based kthread index
    klog::write_raw(b"[INFO]  ksched: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" enter\n");
    let budget = 3;
    for _ in 0..budget {
        // SAFETY: scheduler is initialized; we're running on its `cur` slot.
        unsafe { yield_now(); }
    }
    // SAFETY: scheduler is single-init and we're its current task.
    unsafe { sched_mut().kts[me - 1].done.store(true, Ordering::Release); }
    klog::write_raw(b"[INFO]  ksched: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" done\n");
    // SAFETY: yield until scheduler picks the boot slot; safe per fn contract.
    unsafe { yield_now(); }
    loop { core::hint::spin_loop(); }
}

/// Save current ctx into its slot, pick next, switch. If every
/// kthread has marked itself `done`, picks the boot slot.
///
/// # SAFETY: SCHED is initialized; runs single-CPU pre-init.
/// # C: O(N)
unsafe fn yield_now() {
    // SAFETY: scheduler is initialized by `smoke_rr()` and runs single-CPU.
    let s = unsafe { sched_mut() };
    let prev = s.cur.load(Ordering::Relaxed);
    let n = s.kts.len();
    // Pick next: scan from prev+1 round-robin; skip done kthreads.
    // If none alive, return to boot (idx 0).
    let mut next = 0usize;
    for off in 1..=n {
        let cand = ((prev + off - 1) % n) + 1; // 1..=n
        if !s.kts[cand - 1].done.load(Ordering::Acquire) {
            next = cand;
            break;
        }
    }
    if next == prev { return; }
    s.cur.store(next, Ordering::Release);
    if prev != 0 {
        s.kts[prev - 1].yields.fetch_add(1, Ordering::Relaxed);
    }
    let prev_ctx: *mut ArchCtx = if prev == 0 {
        &mut s.boot as *mut _
    } else {
        &mut s.kts[prev - 1].ctx as *mut _
    };
    let next_ctx: *const ArchCtx = if next == 0 {
        &s.boot as *const _
    } else {
        &s.kts[next - 1].ctx as *const _
    };
    // SAFETY: both ctx pointers come from a single-init `KSched`; next_ctx is either freshly built via `new_kernel` or saved by a prior switch; runs single-CPU pre-init.
    unsafe { ArchCtx::switch(prev_ctx, next_ctx); }
}

/// Spawn `n` round-robin kthreads, run until all exit, return.
///
/// # SAFETY: caller is the boot path; allocator up; single-CPU,
/// IRQs off. The static `SCHED` is initialized once per boot.
/// # C: O(n) plus per-kthread budget yields
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn smoke_rr(n: usize) {
    let mut kts: Vec<KThread> = Vec::with_capacity(n);
    for _ in 0..n {
        // SAFETY: zeroed ArchCtx is overwritten by `new_kernel` below; all-zero is a valid Default-equivalent for ContextX86_64/AArch64.
        let ctx: ArchCtx = unsafe { core::mem::zeroed() };
        let stack: Box<[u8]> = alloc::vec![0u8; STACK_BYTES].into_boxed_slice();
        kts.push(KThread {
            ctx,
            _stack: stack,
            done: AtomicBool::new(false),
            yields: AtomicU32::new(0),
            ticks: AtomicU32::new(0),
        });
    }
    // SAFETY: SCHED.0 is single-init from the boot path; not yet read.
    unsafe {
        // SAFETY: boot ctx is overwritten by the SAVE half of the first switch from boot.
        let boot = core::mem::zeroed();
        *SCHED.0.get() = Some(KSched { boot, kts, cur: AtomicUsize::new(0) });
    }
    // SAFETY: scheduler now exists; build each kthread's context pointing back to its own stack.
    let s = unsafe { sched_mut() };
    for i in 0..n {
        // SAFETY: stack is owned by the kthread for the lifetime of the scheduler.
        let top = unsafe { s.kts[i]._stack.as_mut_ptr().add(STACK_BYTES) };
        s.kts[i].ctx = ArchCtx::new_kernel(top, rr_kthread_entry, i + 1);
    }

    klog::write_raw(b"[INFO]  ksched: starting RR with ");
    klog::write_dec_u64(n as u64);
    klog::write_raw(b" kthreads\n");
    // Boot enters as cur=0; pick first kthread; switch.
    s.cur.store(1, Ordering::Release);
    // SAFETY: kthread 1's context is freshly built via `new_kernel`; preempt disabled.
    unsafe { ArchCtx::switch(&mut s.boot as *mut _, &s.kts[0].ctx as *const _); }

    // Back from RR. Sum yields per kthread.
    let mut total = 0u32;
    for i in 0..s.kts.len() {
        total += s.kts[i].yields.load(Ordering::Relaxed);
    }
    klog::write_raw(b"[INFO]  ksched: RR done, total yields=");
    klog::write_dec_u64(total as u64);
    klog::write_raw(b"\n");
    // Drop scheduler; reclaim stacks.
    // SAFETY: all kthreads have exited; no one else holds SCHED.
    unsafe { *SCHED.0.get() = None; }
}

/// Per-kthread tick budget for the preempt smoke. After this many
/// timer ticks while it's current, the kthread is marked `done`
/// and skipped on subsequent `tick_yield()` picks.
const TICK_BUDGET: u32 = 3;

/// IRQ-context yield. Bumps current's tick counter; if past budget,
/// marks it `done`. Then RR-picks the next not-`done` kthread (or
/// boot if all done) and switches.
///
/// # SAFETY: called only from the IRQ dispatcher tail with `SCHED`
/// initialized; single-CPU pre-init.
/// # C: O(N)
/// # Ctx: IRQ
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn tick_yield() {
    // SAFETY: SCHED was initialized by `smoke_preempt`; we're on
    // the same single-CPU runtime; no concurrent writers.
    let s = unsafe {
        let p = SCHED.0.get();
        match (*p).as_mut() { Some(s) => s, None => return }
    };
    let prev = s.cur.load(Ordering::Relaxed);
    let n = s.kts.len();
    if prev != 0 {
        // Just bump; the kthread itself marks `done` once it
        // observes its own ticks >= TICK_BUDGET. Doing the
        // mark-done here would prevent the kthread from running
        // its exit/log path one final time.
        s.kts[prev - 1].ticks.fetch_add(1, Ordering::Relaxed);
    }
    let mut next = 0usize;
    for off in 1..=n {
        let cand = ((prev + off - 1) % n) + 1;
        if !s.kts[cand - 1].done.load(Ordering::Acquire) {
            next = cand;
            break;
        }
    }
    if next == prev { return; }
    s.cur.store(next, Ordering::Release);
    let prev_ctx: *mut ArchCtx = if prev == 0 {
        &mut s.boot as *mut _
    } else {
        &mut s.kts[prev - 1].ctx as *mut _
    };
    let next_ctx: *const ArchCtx = if next == 0 {
        &s.boot as *const _
    } else {
        &s.kts[next - 1].ctx as *const _
    };
    // SAFETY: both ctx pointers are inside the single-init `KSched`; next_ctx is either freshly built via `new_kernel_with_irq_frame` (unrun kthread) or saved by a prior IRQ-driven switch (preempted kthread); IRQ frame remains on each task's kernel stack.
    unsafe { ArchCtx::switch(prev_ctx, next_ctx); }
}

/// IRQ-context picker per `14§R07`. Bumps `cur`'s tick counter,
/// scans for the next not-`done` kthread (round-robin, falling back
/// to boot if none alive), updates `s.cur`, and stages the
/// `(prev, next)` Context pointers in
/// `oxide_preempt_{cur,next}_ctx` so the IRQ asm tail performs the
/// `oxide_context_switch` and `iretq`s into the new task's stored
/// IRQ frame. No-op if the picked-next equals the prev (cur stays).
///
/// # SAFETY: caller is the IRQ dispatcher (lapic/gic) running with
/// IRQs masked (interrupt-gate / vector-table entry); single-CPU
/// pre-init; `SCHED` may or may not be installed.
/// # C: O(N) scan over kthreads
/// # Ctx: IRQ
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn tick_pick_next_for_irq_exit() {
    // SAFETY: caller asserts IRQ context with IRQs masked, single-
    // CPU pre-init; the only writers to SCHED are the boot path
    // (install/teardown) and ourselves under the same constraints.
    let s = unsafe {
        let p = SCHED.0.get();
        match (*p).as_mut() { Some(s) => s, None => return }
    };
    let prev = s.cur.load(Ordering::Relaxed);
    let n = s.kts.len();
    if prev != 0 && prev <= n {
        s.kts[prev - 1].ticks.fetch_add(1, Ordering::Relaxed);
    }
    let mut next = 0usize;
    for off in 1..=n {
        let cand = ((prev + off - 1) % n) + 1;
        if !s.kts[cand - 1].done.load(Ordering::Acquire) {
            next = cand;
            break;
        }
    }
    if next == prev { return; }
    s.cur.store(next, Ordering::Release);
    let prev_ctx: *mut u8 = if prev == 0 {
        &mut s.boot as *mut _ as *mut u8
    } else {
        &mut s.kts[prev - 1].ctx as *mut _ as *mut u8
    };
    let next_ctx: *mut u8 = if next == 0 {
        &s.boot as *const _ as *mut u8
    } else {
        &s.kts[next - 1].ctx as *const _ as *mut u8
    };
    crate::preempt::oxide_preempt_cur_ctx.store(prev_ctx, Ordering::Release);
    crate::preempt::oxide_preempt_next_ctx.store(next_ctx, Ordering::Release);
}

/// Body shared by per-arch preempt smokes. Builds N kthreads
/// running `hlt`/`wfi` loops, registers them in `SCHED`, and
/// returns the address of `KSched.boot` so the caller can perform
/// the cooperative boot→kthread1 switch after enabling IRQs.
///
/// # SAFETY: caller is the boot path; allocator up; single-CPU
/// pre-init; `SCHED` not currently in use.
/// # C: O(n)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn preempt_install(n: usize) {
    let mut kts: Vec<KThread> = Vec::with_capacity(n);
    for _ in 0..n {
        // SAFETY: zeroed ArchCtx is overwritten by `new_kernel` below.
        let ctx: ArchCtx = unsafe { core::mem::zeroed() };
        let stack: Box<[u8]> = alloc::vec![0u8; STACK_BYTES].into_boxed_slice();
        kts.push(KThread {
            ctx,
            _stack: stack,
            done: AtomicBool::new(false),
            yields: AtomicU32::new(0),
            ticks: AtomicU32::new(0),
        });
    }
    // SAFETY: SCHED is single-init from the boot path; not yet read.
    unsafe {
        let boot = core::mem::zeroed();
        *SCHED.0.get() = Some(KSched { boot, kts, cur: AtomicUsize::new(0) });
    }
    // SAFETY: scheduler was just initialized in the block above; single-CPU pre-init; no other holder.
    let s = unsafe { sched_mut() };
    for i in 0..n {
        // SAFETY: stack owned by kthread for the lifetime of SCHED.
        let top = unsafe { s.kts[i]._stack.as_mut_ptr().add(STACK_BYTES) };
        // `new_kernel_with_irq_frame` per `14§R07`: scaffolds the
        // kthread's kernel stack with a synthetic IRQ frame so the
        // IRQ-exit picker can `Context::switch` into a fresh task
        // and `iretq`/`eret` from the same epilogue.
        s.kts[i].ctx = ArchCtx::new_kernel_with_irq_frame(top, preempt_kthread_entry, i + 1);
    }
}

/// Switch to the first kthread (the boot→kthread1 cooperative
/// edge). Returns when all kthreads are done and the scheduler has
/// switched back to boot via `tick_yield`.
///
/// # SAFETY: `preempt_install` ran; IRQs unmasked by caller; timer
/// ISR will drive `tick_yield` until all kthreads exit.
/// # C: O(1) at the boot edge; total run time = O(n × budget)
/// # Ctx: pre-init, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn preempt_run() {
    // SAFETY: SCHED was initialized by `preempt_install`.
    let s = unsafe { sched_mut() };
    s.cur.store(1, Ordering::Release);
    // SAFETY: kthread 1's context is freshly built via `new_kernel`; the cooperative switch saves boot's callee-saves into `s.boot` so a later tick_yield can return here.
    unsafe { ArchCtx::switch(&mut s.boot as *mut _, &s.kts[0].ctx as *const _); }
}

/// Tear down the preempt scheduler after `preempt_run` returns.
/// # SAFETY: caller has masked IRQs and disarmed the timer.
/// # C: O(n)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn preempt_teardown() -> (u32, u32) {
    // SAFETY: SCHED is initialized; caller asserts no kthread is current.
    let (yields, ticks) = unsafe {
        let s = sched_mut();
        let mut y = 0u32;
        let mut t = 0u32;
        for kt in &s.kts {
            y += kt.yields.load(Ordering::Relaxed);
            t += kt.ticks.load(Ordering::Relaxed);
        }
        (y, t)
    };
    // SAFETY: no kthread is current; caller asserts single-CPU.
    unsafe { *SCHED.0.get() = None; }
    (yields, ticks)
}

/// Per-arch preempt smoke: install N kthreads, arm the periodic
/// timer, unmask IRQs, run until all kthreads exit, disarm.
/// Logs `preempt: ...` lines and a final `total ticks=` summary.
///
/// # SAFETY: caller has fully brought up LAPIC (x86) / GIC (arm)
/// + kernel device mapper; allocator up; single-CPU pre-init.
/// # C: O(n) plus per-kthread `TICK_BUDGET` ticks
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub unsafe fn smoke_preempt_x86(n: usize, period: u32) {
    klog::write_raw(b"[INFO]  preempt: install n=");
    klog::write_dec_u64(n as u64);
    klog::write_raw(b"\n");
    // SAFETY: SCHED unused; allocator up; pre-init.
    unsafe { preempt_install(n); }
    // Reset reschedule flag.
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: LAPIC was enabled by smoke_device_map_x86; legal at CPL=0.
    let armed = unsafe { crate::lapic::timer_periodic(period) };
    if !armed {
        klog::kerror!("preempt: lapic timer not armed");
        // SAFETY: scheduler is initialized but no kthread is current.
        let _ = unsafe { preempt_teardown() };
        return;
    }
    // SAFETY: STI legal at CPL=0; pairs with the CLI on return path.
    unsafe { core::arch::asm!("sti", options(nomem, nostack)); }
    // SAFETY: kthread 1 was freshly built via new_kernel; preempt_run cooperatively switches; the timer ISR drives subsequent rotations.
    unsafe { preempt_run(); }
    // SAFETY: CLI restores IF=0; matches the boot-path discipline.
    unsafe { core::arch::asm!("cli", options(nomem, nostack)); }
    // SAFETY: LAPIC was enabled by smoke_device_map_x86; timer_disarm just writes 0 to the Initial Count reg, which halts the periodic timer cleanly.
    unsafe { crate::lapic::timer_disarm(); }
    // SAFETY: preempt_run returned via tick_yield→boot; no kthread is current.
    let (yields, ticks) = unsafe { preempt_teardown() };
    klog::write_raw(b"[INFO]  preempt: done yields=");
    klog::write_dec_u64(yields as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(ticks as u64);
    klog::write_raw(b"\n");
}

/// ARM variant of `smoke_preempt_x86`. Enables INTID 27 (CNTV PPI),
/// arms the virtual generic-timer in periodic-ish mode, opens
/// DAIF.I, runs, masks again, disarms.
///
/// # SAFETY: caller has fully brought up GIC + the kernel device
/// mapper; allocator up; single-CPU pre-init.
/// # C: O(n) plus per-kthread `TICK_BUDGET` ticks
/// # Ctx: pre-init, IRQ-off (entry), single-CPU
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
pub unsafe fn smoke_preempt_arm(n: usize, period: u32) {
    klog::write_raw(b"[INFO]  preempt: install n=");
    klog::write_dec_u64(n as u64);
    klog::write_raw(b"\n");
    // SAFETY: SCHED unused; allocator up; pre-init.
    unsafe { preempt_install(n); }
    crate::preempt::NEED_RESCHED.store(false, Ordering::Release);
    // SAFETY: GIC mapped + enabled; INTID 27 is the QEMU-virt CNTV PPI.
    unsafe { crate::gic::enable_intid(27); }
    // SAFETY: timer sysregs are unprivileged at EL1; INTID 27 enabled.
    unsafe { crate::arm_timer::timer_periodic(period); }
    // SAFETY: opening DAIF.I lets the GIC deliver the CNTV line via VBAR_EL1[0x280] → oxide_arm_irq_dispatch.
    unsafe { core::arch::asm!("msr daifclr, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: kthread 1 was freshly built; preempt_run cooperatively switches in.
    unsafe { preempt_run(); }
    // SAFETY: re-mask after preempt_run returns to boot.
    unsafe { core::arch::asm!("msr daifset, #2", options(nomem, nostack, preserves_flags)); }
    // SAFETY: disable CNTV (CTL=0) to halt the line.
    unsafe {
        let off: u64 = 0;
        core::arch::asm!("msr cntv_ctl_el0, {c}", c = in(reg) off, options(nomem, nostack, preserves_flags));
    }
    // SAFETY: preempt_run returned via tick_yield→boot; no kthread is current; IRQs masked above.
    let (yields, ticks) = unsafe { preempt_teardown() };
    klog::write_raw(b"[INFO]  preempt: done yields=");
    klog::write_dec_u64(yields as u64);
    klog::write_raw(b" ticks=");
    klog::write_dec_u64(ticks as u64);
    klog::write_raw(b"\n");
}

extern "C" fn preempt_kthread_entry(arg: usize) -> ! {
    let me = arg;
    klog::write_raw(b"[INFO]  preempt: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" enter\n");
    // Real IRQ-exit preemption per `14§R07`: the timer-tick picker
    // increments our ticks + transparently switches us out at the
    // IRQ tail when another kthread should run. We just hlt/wfi
    // until our budget exhausts; no NEED_RESCHED polling needed.
    loop {
        // SAFETY: SCHED is single-init; observe own ticks + done.
        let (ticks, done) = unsafe {
            let s = sched_mut();
            (s.kts[me - 1].ticks.load(Ordering::Acquire),
             s.kts[me - 1].done.load(Ordering::Acquire))
        };
        if done { break; }
        if ticks >= TICK_BUDGET {
            // Self-mark done so subsequent picks skip this kthread.
            // SAFETY: SCHED initialized; we are the current task.
            unsafe { sched_mut().kts[me - 1].done.store(true, Ordering::Release); }
            break;
        }
        #[cfg(target_arch = "x86_64")]
        // SAFETY: `hlt` parks the core until next IRQ; legal at CPL=0.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)); }
        #[cfg(target_arch = "aarch64")]
        // SAFETY: `wfi` parks the core until any wake event; unprivileged at EL1.
        unsafe { core::arch::asm!("wfi", options(nomem, nostack, preserves_flags)); }
    }
    klog::write_raw(b"[INFO]  preempt: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" done\n");
    // Voluntary yield to give boot (or the next not-done kthread)
    // control. tick_yield runs synchronously (Context::switch);
    // doesn't go through the IRQ epilogue.
    // SAFETY: tick_yield called from a normal call site (not IRQ context); SCHED initialized; we are the current task.
    unsafe { tick_yield(); }
    loop { core::hint::spin_loop(); }
}
