// Softirq primitive per docs/45 (DRAFT). Linux-equivalent bottom-half
// runner: ISR / process context calls `raise(slot)` to mark a deferred
// handler pending; `run_pending()` is invoked from the timer-ISR tail
// (after EOI, with IRQs unmasked) and walks the bitmask, calling each
// installed handler. Slots are statically numbered (`Slot::*`) so the
// dispatch is a fixed-size table — no allocation, no dyn, no lock.
//
// Per-CPU model (Linux `irq_stat[]` + per-CPU ksoftirqd)
//   - PENDING / IN_PROGRESS are per-CPU arrays. `raise` sets the bit on the
//     CURRENT CPU; `run_pending` drains ONLY this CPU's mask. There is no
//     global queue and no single-CPU bottleneck — every CPU raises + drains
//     its own work from its own timer/MSI tail and its own ksoftirqd.
//   - IN_PROGRESS[cpu] guards re-entry on that CPU: a nested timer ISR that
//     calls run_pending observes its own CPU's guard set and returns; the
//     outer runner drains the new bits on its next iteration. Other CPUs
//     drain concurrently against their own entries.
//   - run_pending applies Linux's `__do_softirq` restart gate
//     (MAX_SOFTIRQ_RESTART / MAX_SOFTIRQ_TIME / need_resched); leftover work
//     defers to this CPU's ksoftirqd via the `wakeup_softirqd` hook.
//
// Limits
//   - 32 slots (one u32 of pending bits). Bump to u64 + 64 handlers
//     if we exhaust them.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#[cfg(test)]
extern crate std;

use core::sync::atomic::{AtomicPtr, AtomicU32, Ordering};

mod account;
mod hibernate_diag;
pub use account::{HandlerAccounting, Unaccounted};
pub use hibernate_diag::{hibernate_irq_restore, hibernate_witness, HibernateWitness};
use hibernate_diag::witness_stage as hibernate_witness_stage;

/// Softirq slot identifiers. Add new entries at the bottom; never
/// reorder existing variants — handlers index by `as u32`.
#[repr(u32)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Slot {
    /// fbcon: drain Console.fb → virtio-gpu transfer + flush. Raised
    /// by `fbcon::kernel::klog_sink` after Console.put.
    FbconFlush = 0,
    /// virtio-input: drain device used-ring + translate events to
    /// VT input. Raised by the virtio-input device IRQ.
    InputDrain = 1,
    /// virtio-net: drain RX queue used-ring + dispatch frames into
    /// the net stack. Raised by the MSI dispatcher on every virtio
    /// MSI fire (shared vector — handler bails if RX queue is empty).
    NetRx = 2,
    /// virtio-vsock: drain RX queue used-ring + dispatch packets into
    /// AF_VSOCK. Raised by the MSI dispatcher; the handler is installed
    /// by the virtio-vsock driver probe.
    VsockRx = 3,
    /// virtio-snd: drain EVENTQ used-ring entries. Raised by the
    /// virtio-snd queue-1 MSI callback.
    SndEvent = 4,
    /// Network namespace final-owner drop: wake the process-context reaper.
    NetNsReap = 5,
    /// Block-device completion bottom half. Virtio and other interrupt-driven
    /// block drivers raise this from their completion IRQ; drivers consume
    /// used-ring entries and wake request owners from process-safe context.
    BlockIo = 6,
    /// Bridge STP tick: age the forwarding database, run the port state
    /// machine, emit BPDUs. Raised by the timer tick; the work itself takes
    /// bridge/interface locks, allocates, and transmits, none of which may
    /// happen in a hard-IRQ handler (`06§3.1`). Linux runs the equivalent from
    /// a `timer_list`, i.e. TIMER_SOFTIRQ.
    BridgeStp = 7,
    /// Tasklet drain (Linux `TASKLET_SOFTIRQ`). Raised by `tasklet::schedule`;
    /// the handler runs every pending tasklet body in softirq context.
    Tasklet = 8,
    /// perf software-event sampling opportunities charged from inside the
    /// runqueue-locked region (`sched::perf_sw::charge_deferred`), plus the
    /// `PERF_RECORD_SWITCH` pair. Linux defers the same work with an
    /// `irq_work`; the sampler takes the perf registry and one ring lock, so
    /// it may not run under `rq->lock` — and it may not run in the switch tail
    /// either, since that charges every blocking path with the sampler's stack.
    PerfDeferred = 9,
    /// xHCI USB keyboard and mouse report completions.
    UsbInput = 10,
    /// HDA codec unsolicited jack responses. The codec readback and sound
    /// control notification run from process context, not the IRQ tail.
    HdaJack = 11,
}

const N_SLOTS: usize = 32;
/// Linux's fixed `/proc/stat` and `/proc/softirqs` class order.  Internal
/// work slots remain independently numbered; this is only their externally
/// observable execution-accounting class.
#[repr(usize)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum StatClass { Hi = 0, Timer = 1, NetTx = 2, NetRx = 3, Block = 4, IrqPoll = 5, Tasklet = 6, Sched = 7, Hrtimer = 8, Rcu = 9 }

pub const N_STAT_CLASSES: usize = 10;

impl Slot {
    /// Linux softirq accounting class for this internal deferred-work slot.
    /// # C: O(1)
    pub const fn stat_class(self) -> StatClass {
        match self {
            Self::NetRx => StatClass::NetRx,
            Self::BlockIo => StatClass::Block,
            Self::BridgeStp => StatClass::Timer,
            Self::PerfDeferred => StatClass::Sched,
            Self::Tasklet | Self::FbconFlush | Self::InputDrain | Self::VsockRx
            | Self::SndEvent | Self::NetNsReap | Self::UsbInput | Self::HdaJack => StatClass::Tasklet,
        }
    }
}

fn stat_class_for_index(idx: usize) -> Option<StatClass> {
    match idx {
        x if x == Slot::FbconFlush as usize => Some(Slot::FbconFlush.stat_class()),
        x if x == Slot::InputDrain as usize => Some(Slot::InputDrain.stat_class()),
        x if x == Slot::NetRx as usize => Some(Slot::NetRx.stat_class()),
        x if x == Slot::VsockRx as usize => Some(Slot::VsockRx.stat_class()),
        x if x == Slot::SndEvent as usize => Some(Slot::SndEvent.stat_class()),
        x if x == Slot::NetNsReap as usize => Some(Slot::NetNsReap.stat_class()),
        x if x == Slot::BlockIo as usize => Some(Slot::BlockIo.stat_class()),
        x if x == Slot::BridgeStp as usize => Some(Slot::BridgeStp.stat_class()),
        x if x == Slot::Tasklet as usize => Some(Slot::Tasklet.stat_class()),
        x if x == Slot::PerfDeferred as usize => Some(Slot::PerfDeferred.stat_class()),
        x if x == Slot::UsbInput as usize => Some(Slot::UsbInput.stat_class()),
        x if x == Slot::HdaJack as usize => Some(Slot::HdaJack.stat_class()),
        _ => None,
    }
}

/// Per-CPU handler-dispatch counts, classified in the Linux-visible softirq
/// layout.  The increment sits beside the actual function call, so a raised
/// but deferred bit never masquerades as completed work.
static STAT_CALLS: [[core::sync::atomic::AtomicU64; MAX_CPUS]; N_STAT_CLASSES] =
    [const { [const { core::sync::atomic::AtomicU64::new(0) }; MAX_CPUS] }; N_STAT_CLASSES];

/// Number of completed handlers in `class` on `cpu`. # C: O(1)
pub fn stat_count(class: StatClass, cpu: usize) -> u64 {
    if cpu >= MAX_CPUS { return 0; }
    STAT_CALLS[class as usize][cpu].load(Ordering::Relaxed)
}

/// Sum `class` across the supplied online CPU count. # C: O(N_cpu)
pub fn stat_total(class: StatClass, ncpu: usize) -> u64 {
    let n = ncpu.min(MAX_CPUS);
    (0..n).map(|cpu| stat_count(class, cpu)).sum()
}
const PROCESS_ONLY: u32 = (1u32 << (Slot::NetNsReap as u32)) | (1u32 << (Slot::HdaJack as u32));
/// Per-CPU array width (Linux `irq_stat[NR_CPUS]`).
const MAX_CPUS: usize = cpu::MAX_CPUS;

/// Per-CPU pending bitmasks — Linux `irq_stat[cpu].__softirq_pending`. Bit
/// `Slot::* as u32` set on CPU N ⇒ that CPU must run the handler. Each CPU
/// raises and drains ONLY its own entry; there is no global queue. The handler
/// table (`HANDLERS`) stays global — Linux `softirq_vec[]` is shared; only the
/// pending mask + drain state are per-CPU.
static PENDING: [AtomicU32; MAX_CPUS] = [const { AtomicU32::new(0) }; MAX_CPUS];
/// Migration-safe publication for process-only work raised outside a pinned
/// CPU context. Any ksoftirqd may claim these idempotent slot bits.
static PROCESS_PENDING: AtomicU32 = AtomicU32::new(0);

/// Current logical CPU id (kernel) / 0 (host tests). Same arch glue as
/// `sched::diag::percpu::this_cpu_id`. Clamped to `MAX_CPUS` so a bogus id
/// can never index out of bounds.
/// Canonical per-CPU index for softirq-owned state. Subsystems that keep their
/// own per-CPU array alongside the pending mask (the net RX backlog) index it
/// with this so a slot's queue and its pending bit can never disagree about
/// which CPU they belong to. # C: O(1)
#[inline]
pub fn this_cpu() -> usize { this_cpu_id() }

#[inline]
fn this_cpu_id() -> usize {
    #[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
    let id = { use hal::CpuOps; hal_x86_64::X86CpuOps::current_cpu() as usize };
    #[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
    let id = { use hal::CpuOps; hal_aarch64::ArmCpuOps::current_cpu() as usize };
    #[cfg(not(target_os = "oxide-kernel"))]
    let id = 0usize;
    if id >= MAX_CPUS { 0 } else { id }
}

/// Handler table. Slot N's handler in `HANDLERS[N]`; null = unset.
/// Stored as `*mut ()` for AtomicPtr; cast through `fn()` on load.
static HANDLERS: [AtomicPtr<()>; N_SLOTS] = [
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
    AtomicPtr::new(core::ptr::null_mut()), AtomicPtr::new(core::ptr::null_mut()),
];

// Re-entry is guarded by the per-CPU `preempt_count` softirq field (Linux
// `in_interrupt()`), checked by the caller `sched::bh::do_softirq` — there is
// no separate flag. `run_pending` below is the pure `__do_softirq` core; it
// runs only inside that bh-accounted bracket.

/// Linux `MAX_SOFTIRQ_RESTART`: restart-pass cap before
/// the drain defers, so a self-re-raising slot (virtio-net `NetRx` re-armed
/// by every RX MSI under a packet flood) can't monopolize the CPU and starve
/// the percpu heartbeat.
const MAX_SOFTIRQ_RESTART: u32 = 10;
/// Linux `MAX_SOFTIRQ_TIME` (`2*HZ/1000` jiffies): the wall-clock ceiling on
/// one drain. Expressed in ticks since oxide's jiffies hook returns ticks.
const MAX_SOFTIRQ_TIME: u64 = 2;

/// Boot-installed scheduler/time hooks. `softirq` is a leaf crate (no `sched`
/// dep — that would cycle); the arch/sched layer installs these at boot, the
/// same pattern as `sched::diag::nmi::set_poke_hook`. Null before install =
/// safe defaults (no resched pending, jiffies 0, no-op wakeup), so the
/// restart loop degrades to the `MAX_SOFTIRQ_RESTART` cap alone pre-boot.
static RESCHED_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static JIFFIES_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static WAKEUP_HOOK:  AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
static PROCESS_KICK_HOOK: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());

/// Install the `need_resched()` peek (non-consuming). # C: O(1)
pub fn set_resched_hook(f: fn() -> bool) { RESCHED_HOOK.store(f as *mut (), Ordering::Release); }
/// Install the jiffies/tick reader. # C: O(1)
pub fn set_jiffies_hook(f: fn() -> u64) { JIFFIES_HOOK.store(f as *mut (), Ordering::Release); }
/// Install `wakeup_softirqd` — the deferral target run when the restart gate
/// trips with work still pending. # C: O(1)
pub fn set_wakeup_hook(f: fn()) { WAKEUP_HOOK.store(f as *mut (), Ordering::Release); }
/// Install the lock-free IRQ kick used when process-only work is published.
/// # C: O(1)
pub fn set_process_kick_hook(f: fn()) {
    PROCESS_KICK_HOOK.store(f as *mut (), Ordering::Release);
}

/// Peek `need_resched` via the installed hook. False (don't yield) if unset.
fn need_resched() -> bool {
    let p = RESCHED_HOOK.load(Ordering::Acquire);
    if p.is_null() { return false; }
    // SAFETY: p stored from a `fn() -> bool` by set_resched_hook; reverse-transmute to that exact ABI before call.
    let f: fn() -> bool = unsafe { core::mem::transmute(p) };
    f()
}
/// Read jiffies/ticks via the installed hook. 0 if unset (time gate inert).
fn jiffies() -> u64 {
    let p = JIFFIES_HOOK.load(Ordering::Acquire);
    if p.is_null() { return 0; }
    // SAFETY: p stored from a `fn() -> u64` by set_jiffies_hook; reverse-transmute to that exact ABI before call.
    let f: fn() -> u64 = unsafe { core::mem::transmute(p) };
    f()
}
/// Fire the deferral hook (Linux `wakeup_softirqd`). No-op if unset.
fn wakeup_softirqd() {
    let p = WAKEUP_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p stored from a `fn()` by set_wakeup_hook; reverse-transmute to that exact ABI before call.
    let f: fn() = unsafe { core::mem::transmute(p) };
    f();
}

fn kick_process_drainer() {
    let p = PROCESS_KICK_HOOK.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p was installed from a `fn()` and remains immutable after boot.
    let f: fn() = unsafe { core::mem::transmute(p) };
    f();
}

/// Diagnostic counters.
pub static RAISES: AtomicU32 = AtomicU32::new(0);
pub static RUNS: AtomicU32 = AtomicU32::new(0);
pub static HANDLER_CALLS: AtomicU32 = AtomicU32::new(0);
/// Times a drain tripped the restart gate and deferred still-pending bits.
pub static DEFERRALS: AtomicU32 = AtomicU32::new(0);

/// Install a handler. Caller passes a `fn()` so we don't need
/// `dyn` (per `07§5` no-dyn-in-kernel rule). One handler per slot;
/// later calls overwrite. Returns the previous handler pointer
/// (as `*mut ()`) so callers can chain if they want.
/// # C: O(1) — atomic store.
pub fn set_handler(slot: Slot, f: fn()) -> *mut () {
    let raw = f as *mut ();
    HANDLERS[slot as usize].swap(raw, Ordering::Release)
}

/// Remove a handler and clear any still-pending work for that slot on every
/// CPU. Drivers call this from remove after stopping publication of new work.
/// # C: O(NR_CPUS)
pub fn clear_handler(slot: Slot) -> *mut () {
    clear_pending(slot);
    HANDLERS[slot as usize].swap(core::ptr::null_mut(), Ordering::AcqRel)
}

/// Clear a slot's pending publication on every CPU without removing its
/// handler.  The subsystem that owns the slot may use this only after it has
/// closed every producer and synchronized with the handler's state.  This is
/// the softirq half of Linux's suspend/remove pattern: stop queueing deferred
/// work, flush its shared state, then cancel a stale per-CPU wake publication.
/// # C: O(NR_CPUS)
pub fn clear_pending(slot: Slot) {
    let bit = 1u32 << (slot as u32);
    for pending in PENDING.iter() {
        pending.fetch_and(!bit, Ordering::AcqRel);
    }
    PROCESS_PENDING.fetch_and(!bit, Ordering::AcqRel);
}

/// Raise `slot` on THIS CPU — Linux `__raise_softirq_irqoff` / `or_softirq_
/// pending`. The bit lands on the running CPU's mask; that CPU drains it from
/// its own timer/MSI tail or its ksoftirqd. Must run with the CPU pinned (ISR
/// context or IRQs/preempt off) so `this_cpu` is stable, exactly as Linux
/// requires of `raise_softirq_irqoff`.
/// # C: O(1) — atomic fetch_or.
pub fn raise(slot: Slot) {
    PENDING[this_cpu()].fetch_or(1u32 << (slot as u32), Ordering::Release);
    RAISES.fetch_add(1, Ordering::Relaxed);
}

/// Raise a process-only slot without requiring CPU pinning. # C: O(1)
/// # Ctx: any; lock-free, allocation-free, IRQ-safe
pub fn raise_process(slot: Slot) {
    let bit = 1u32 << (slot as u32);
    debug_assert!((bit & PROCESS_ONLY) != 0, "raise_process requires process-only slot");
    let old = PROCESS_PENDING.fetch_or(bit, Ordering::AcqRel);
    RAISES.fetch_add(1, Ordering::Relaxed);
    if old & bit == 0 { kick_process_drainer(); }
}

/// True iff this CPU or the migration-safe process drainer has work. # C: O(1)
///
/// Scheduler drainers use this combined predicate. CPU-hotplug admission must
/// use [`local_pending`], because globally claimable process work does not pin
/// any particular CPU online.
/// # C: O(1)
pub fn pending() -> bool {
    local_pending() || PROCESS_PENDING.load(Ordering::Acquire) != 0
}

/// Whether this CPU's own pending mask requires it to remain online. # C: O(1)
pub fn local_pending() -> bool { PENDING[this_cpu()].load(Ordering::Acquire) != 0 }

/// This CPU's exact pending mask for CPU-hotplug admission diagnostics. # C: O(1)
pub fn local_pending_bits() -> u32 { PENDING[this_cpu()].load(Ordering::Acquire) }

/// `__do_softirq` core: drain THIS CPU's pending mask with Linux's restart
/// gate. NOT a public entry point — call `sched::bh::do_softirq` (or
/// `local_bh_enable`), which brackets this in softirq accounting and supplies
/// the `in_interrupt()` re-entry guard.
///
/// # Ctx
/// Runs with IRQs enabled (handlers wait on device IRQ acks) and
/// `in_serving_softirq` set by the caller.
///
/// # SAFETY
/// Caller must run inside `sched::bh`'s softirq-accounted bracket (so re-entry
/// is excluded and `this_cpu` is stable) with IRQs locally enabled.
///
/// # C: O(N_handlers_with_work) per drain pass; bounded by the restart gate.
unsafe fn run_pending_mode<A: HandlerAccounting>(process_context: bool) {
    hibernate_witness_stage(1, 0, 0, usize::MAX);
    // This CPU's slot. Stable for the drain: callers (`sched::bh::do_softirq`)
    // run with `in_serving_softirq` set, so preemption/migration is off and
    // `this_cpu` can't change under us. Re-entry is already excluded by the
    // caller's `in_interrupt()` guard — no flag here.
    let c = this_cpu();
    hibernate_witness_stage(2, 0, 0, usize::MAX);
    RUNS.fetch_add(1, Ordering::Relaxed);
    // Linux `__do_softirq` restart gate, on THIS CPU's pending mask. A handler
    // that re-raises its own bit (NetRx re-armed by each RX MSI under a packet
    // flood) would otherwise spin this loop forever: the CPU never returns to
    // the timer-ISR tail, the percpu heartbeat goes unstamped, and the
    // hard-lockup watchdog fires. Mirror the kernel exactly — after running the
    // pending set, restart only while `time_before(jiffies, end) &&
    // !need_resched() && --max_restart`; otherwise `wakeup_softirqd()` and
    // return, leaving still-pending bits set for this CPU's ksoftirqd to finish.
    let end = jiffies().wrapping_add(MAX_SOFTIRQ_TIME);
    hibernate_witness_stage(3, 0, 0, usize::MAX);
    let mut max_restart = MAX_SOFTIRQ_RESTART;
    loop {
        // `set_softirq_pending(0)` — claim this CPU's set, run each handler.
        let local_bits = PENDING[c].swap(0, Ordering::AcqRel);
        let process_bits = if process_context {
            PROCESS_PENDING.swap(0, Ordering::AcqRel)
        } else {
            PROCESS_PENDING.load(Ordering::Acquire)
        };
        hibernate_witness_stage(4, local_bits, process_bits, usize::MAX);
        if local_bits == 0 && process_bits == 0 {
            break;
        }
        let local_deferred = if process_context { 0 } else { local_bits & PROCESS_ONLY };
        let process_deferred = !process_context && process_bits != 0;
        if local_deferred != 0 {
            PENDING[c].fetch_or(local_deferred, Ordering::Release);
        }
        if local_deferred != 0 || process_deferred {
            wakeup_softirqd();
        }
        let mut b = if process_context {
            local_bits | process_bits
        } else {
            local_bits & !local_deferred
        };
        while b != 0 {
            let idx = b.trailing_zeros() as usize;
            b &= !(1u32 << idx);
            let raw = HANDLERS[idx].load(Ordering::Acquire);
            if !raw.is_null() {
                hibernate_witness_stage(5, local_bits, process_bits, idx);
                HANDLER_CALLS.fetch_add(1, Ordering::Relaxed);
                if let Some(class) = stat_class_for_index(idx) {
                    STAT_CALLS[class as usize][c].fetch_add(1, Ordering::Relaxed);
                }
                // SAFETY: raw was stored via set_handler which casts a non-null `fn()` through `*mut ()`; reverse-cast restores the original ABI-compatible fn pointer; handlers are responsible for their own safety contracts.
                let f: fn() = unsafe { core::mem::transmute::<*mut (), fn()>(raw) };
                let snapshot = A::before();
                hibernate_witness_stage(6, local_bits, process_bits, idx);
                hibernate_witness_stage(7, local_bits, process_bits, idx);
                f();
                hibernate_witness_stage(8, local_bits, process_bits, idx);
                hibernate_witness_stage(9, local_bits, process_bits, idx);
                A::after(snapshot);
            }
        }
        // Process-only work must leave IRQ-tail immediately for ksoftirqd.
        if local_deferred != 0 || process_deferred { break; }
        // Re-raised on this CPU during the pass? Apply the three-way gate.
        if PENDING[c].load(Ordering::Acquire) == 0
            && PROCESS_PENDING.load(Ordering::Acquire) == 0
        {
            break;
        }
        // `time_before(jiffies, end)` — wrapping-safe signed compare.
        let within_time = (jiffies().wrapping_sub(end) as i64) < 0;
        if within_time && !need_resched() {
            max_restart -= 1;
            if max_restart != 0 {
                continue;
            }
        }
        // Gate tripped with work pending → hand off to THIS CPU's ksoftirqd
        // (Linux `wakeup_softirqd`). The still-pending bits remain set.
        wakeup_softirqd();
        DEFERRALS.fetch_add(1, Ordering::Relaxed);
        break;
    }
}

/// Drain IRQ-tail-safe handlers, deferring process-only slots to ksoftirqd.
/// # SAFETY: caller holds the softirq accounting bracket. # C: O(pending work)
pub unsafe fn run_pending() {
    // SAFETY: caller provides the accounting contract for this IRQ-tail mode.
    unsafe { run_pending_mode::<Unaccounted>(false); }
}

/// Drain all handlers from ksoftirqd process context. # C: O(pending work)
/// # SAFETY: caller holds the softirq accounting bracket in process context.
pub unsafe fn run_pending_process() {
    // SAFETY: caller provides process context and the accounting contract.
    unsafe { run_pending_mode::<Unaccounted>(true); }
}

/// Drain IRQ-tail-safe handlers with caller-owned per-handler accounting.
/// # SAFETY: caller holds the softirq accounting bracket. # C: O(pending work)
pub unsafe fn run_pending_accounted<A: HandlerAccounting>() {
    // SAFETY: caller provides the accounting contract for this IRQ-tail mode.
    unsafe { run_pending_mode::<A>(false); }
}

/// Drain all handlers in process context with caller-owned accounting.
/// # SAFETY: caller holds the softirq accounting bracket. # C: O(pending work)
pub unsafe fn run_pending_process_accounted<A: HandlerAccounting>() {
    // SAFETY: caller provides process context and the accounting contract.
    unsafe { run_pending_mode::<A>(true); }
}

#[cfg(test)]
mod tests;
