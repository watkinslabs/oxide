// AArch64 transport for the shared cross-CPU call queue.
//
// The queue and completion rules are architecture-independent (`cpu::call_fn`).
// This file owns only the GIC SGI delivery and target-side dispatch. Arm64
// bypasses `TlbFlush` because broadcast TLBI already supplies that operation.

use cpu::call_fn::{drop_unreachable, escalation_due, escalation_gap, targets_for, CallQueues};
use hal::smp_call::CallKind;
use hal::{CpuOps, TimerOps};

static QUEUES: CallQueues = CallQueues::new();

const STUCK_WARN_NS: u64 = 5_000_000_000;
const STUCK_WARN_SPINS: u64 = 500_000_000;

#[inline]
fn this_cpu() -> usize { (hal_aarch64::ArmCpuOps::current_cpu() as usize).min(cpu::MAX_CPUS - 1) }

fn exec(kind: u32, arg: u64) {
    match CallKind::from_u32(kind) {
        // Broadcast TLBI is already complete when the initiating CPU returns.
        Some(CallKind::TlbFlush) | Some(CallKind::LdtReload) => {}
        Some(CallKind::MembarrierGlobalMb) => sched::membarrier::service_global(),
        Some(CallKind::MembarrierPrivateMb) => sched::membarrier::service_private_mb(arg),
        Some(CallKind::MembarrierPrivateSyncCore) => sched::membarrier::service_private_sync_core(arg),
        Some(CallKind::MembarrierPrivateRseq) => sched::membarrier::service_private_rseq(arg),
        Some(CallKind::Stop) => loop {
            // SAFETY: terminal machine-stop handler; masking IRQs then WFI
            // keeps this CPU from executing pages the caller may replace.
            unsafe { core::arch::asm!("msr daifset, #2", "wfi", options(nomem, nostack, preserves_flags)); }
        },
        None => {}
    }
}

/// Drain every call queued for this CPU.
/// # C: O(queued entries)
pub fn service() { QUEUES.drain(this_cpu(), exec); }

/// Send the call-function SGI to one logical CPU.
/// # SAFETY: GIC CPU interfaces and the call-function SGI are enabled.
unsafe fn send_ipi(logical_cpu: u32) -> bool {
    // SAFETY: the logical CPU maps to its GIC affinity-0 in this topology.
    unsafe { crate::gic::send_call_function_ipi(logical_cpu); }
    true
}

fn call_function_many(mask: &[u64], kind: u32, arg: u64, wait: bool) {
    if kind == CallKind::TlbFlush.as_u32() || cpu::smp::online_count() <= 1 { return; }
    let me = this_cpu();
    let targets = targets_for(cpu::CpuMask::from_words(mask), cpu::smp::online_cpumask(), me);
    if targets.is_empty() { return; }
    let mut pending = targets;
    let mut c = 0usize;
    while c < cpu::MAX_CPUS {
        if targets.contains(c) {
            QUEUES.lock_slot(me, c, || {
                service();
                sync::spin_relax::relax();
            });
            let need_ipi = QUEUES.push(me, c, kind, arg);
            // SAFETY: the target is online and its GIC call SGI is enabled.
            if need_ipi && !unsafe { send_ipi(c as u32) } { pending = drop_unreachable(pending, c as u32); }
        }
        c += 1;
    }
    if wait { wait_for(me, pending); }
}

fn wait_for(me: usize, pending: cpu::CpuMask) {
    let t0 = now_ns();
    let mut fired = 0u32;
    let mut next_warn = t0.wrapping_add(STUCK_WARN_NS);
    let mut spins = 0u64;
    let mut next_spin_warn = STUCK_WARN_SPINS;
    loop {
        let mut left = cpu::CpuMask::empty();
        let mut c = 0usize;
        while c < cpu::MAX_CPUS {
            if pending.contains(c) && !QUEUES.is_complete(me, c) { let _ = left.insert(c); }
            c += 1;
        }
        if left.is_empty() { return; }
        service();
        sync::spin_relax::relax();
        spins = spins.wrapping_add(1);
        let now = now_ns();
        if escalation_due(now, next_warn, spins, next_spin_warn) {
            report_stuck(left, now.wrapping_sub(t0), spins);
            fired = fired.saturating_add(1);
            next_warn = now.wrapping_add(escalation_gap(STUCK_WARN_NS, fired));
            next_spin_warn = spins.wrapping_add(escalation_gap(STUCK_WARN_SPINS, fired));
        }
    }
}

#[inline]
fn now_ns() -> u64 { hal_aarch64::ArmTimerOps::monotonic_ns().0 }

fn report_stuck(left: cpu::CpuMask, waited_ns: u64, spins: u64) {
    klog::write_raw(b"[SMPCALL-STUCK] waited_ms=");
    klog::write_dec_u64(waited_ns / 1_000_000);
    klog::write_raw(b" spins=");
    klog::write_dec_u64(spins);
    klog::write_raw(b" pending=");
    klog::write_hex_u64(left.low_word());
    klog::write_raw(b"\n");
    let mut c = 0usize;
    while c < cpu::MAX_CPUS {
        if left.contains(c) {
            // SAFETY: re-delivery is idempotent while the entry remains queued.
            unsafe { let _ = send_ipi(c as u32); }
        }
        c += 1;
    }
}

/// Install the AArch64 generic cross-CPU call transport.
/// # SAFETY: boot path calls this once after every online GIC interface enables SGI 1.
/// # C: O(1)
pub unsafe fn install() {
    // SAFETY: this boot-lifetime function owns the arm call transport.
    unsafe { hal::smp_call::set_call_hook(call_function_many); }
    // SAFETY: `service` takes no lock, does not sleep, and is reentrant.
    unsafe { sync::set_spin_relax_hook(service); }
}
