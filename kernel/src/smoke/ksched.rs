// Cooperative round-robin smoke per `13§3`. Drives the real
// `Runqueue` (P2-13b) without arming any timer IRQ — each
// kthread voluntary-yields a fixed budget, the picker rotates
// among runnable peers, and after every kthread marks itself
// Zombie the picker returns to idle (boot anchor) so the smoke
// driver returns. This is the cooperative companion to
// `preempt_smoke` (which exercises the IRQ-exit picker).


use alloc::sync::Arc;
use alloc::vec::Vec;
use sched::Task;

use sched::live as ksched;

/// Voluntary-yields per kthread.
const RR_BUDGET: u32 = 3;

/// Spawn `n` cooperative kthreads, schedule into them, return
/// when all have yielded `RR_BUDGET` times and self-Zombied.
///
/// # SAFETY: caller is the boot path; allocator up; single-CPU,
/// IRQs masked. No prior runqueue installed (or already torn down).
/// # C: O(n × RR_BUDGET) yields plus per-yield O(log N) CFS pick
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn smoke_rr(n: usize) {
    klog::write_raw(b"[INFO]  ksched: starting RR with ");
    klog::write_dec_u64(n as u64);
    klog::write_raw(b" kthreads\n");
    // SAFETY: boot path; allocator up; single-CPU pre-init; no other runqueue installed at this point per smoke ordering.
    unsafe { ksched::install_default_runqueue(); }

    let mut kts: Vec<Arc<Task>> = Vec::with_capacity(n);
    for i in 1..=n as u32 {
        // SAFETY: runqueue installed; allocator up.
        let r = unsafe { ksched::spawn_kernel_thread(i, "rr", rr_kthread_entry, i as usize) };
        match r {
            Ok(t)  => kts.push(t),
            Err(_) => klog::kerror!("ksched: spawn failed"),
        }
    }

    // First voluntary `schedule()` from boot saves boot's regs into
    // idle.arch_ctx and switches into the first CFS-picked kthread.
    // Returns when every kthread is Zombie and the picker returns
    // idle. No IRQs are armed for this smoke — every rotation is
    // a voluntary `tick_yield()` from inside `rr_kthread_entry`.
    // SAFETY: process ctx; single-CPU; runqueue installed; IRQs masked.
    unsafe { ksched::schedule(); }

    // SAFETY: schedule() returned via boot-anchor restore; no kthread is current.
    let stats = unsafe { ksched::schedule::uninstall_global_with_stats() }
        .unwrap_or(ksched::RunStats::default());
    drop(kts);
    klog::write_raw(b"[INFO]  ksched: RR done, total yields=");
    klog::write_dec_u64(stats.voluntary_switches as u64);
    klog::write_raw(b"\n");
}

extern "C" fn rr_kthread_entry(arg: usize) -> ! {
    let me = arg;
    klog::write_raw(b"[INFO]  ksched: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" enter\n");
    for _ in 0..RR_BUDGET {
        // SAFETY: process ctx; per `tick_yield()` contract.
        unsafe { ksched::tick_yield(); }
    }
    klog::write_raw(b"[INFO]  ksched: kthread ");
    klog::write_dec_u64(me as u64);
    klog::write_raw(b" done\n");
    if let Some(cur) = ksched::current() {
        ksched::mark_done(cur);
    }
    // SAFETY: per `tick_yield()`; self-Zombied so won't be re-enqueued.
    unsafe { ksched::tick_yield(); }
    loop { core::hint::spin_loop(); }
}
