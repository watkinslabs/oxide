// Kernel scheduler integration per `13§6` / `13§7` / `13§8`.
//
// This module is the kernel-side glue between `crates/sched`'s
// hosted-testable runqueue logic (`RunqueueInner`, `Task`, RT/CFS
// classes) and the live HAL `Context` switch + per-arch IRQ-exit
// preempt machinery. Layout follows the spec:
//
//   `Runqueue` (here)        — outer per-CPU struct, atomics +
//                              `Spinlock<RunqueueInner>` per `13§6`.
//   `RunqueueInner` (sched)  — RT bitmap + CFS RB-tree + idle.
//   `Task` (sched)           — `13§5` task descriptor; in this PR
//                              gains `Box<[u8]>` stack ownership +
//                              real `arch_ctx` init via
//                              `Context::new_kernel_with_irq_frame`.
//
// Submodules:
//   `runqueue` — kernel `Runqueue` outer struct + global static.
//   `spawn`    — `spawn_kernel_thread`: alloc stack, build ctx,
//                 `Arc<Task>`, enqueue.
//   `schedule` — `schedule()` voluntary path (`13§8`),
//                `schedule_from_irq()` IRQ-exit path (`14§R07`),
//                `tick()` periodic timer hook, `current()`.
//
// Replaces the `kernel/src/ksched.rs` Vec-shim per the P2-13b
// branch in state.md.


pub mod balance;
pub mod registry;
pub mod runqueue;
pub mod schedule;
pub mod spawn;
pub mod wait_list;
pub mod zombies;

pub use runqueue::{global, Runqueue};
pub use schedule::{
    current, mark_done, schedule, schedule_from_irq, tick_yield,
    install_default_runqueue, runqueue_active, RunStats,
};
pub use spawn::{next_tid, spawn_kernel_thread, spawn_user_thread, spawn_user_thread_for_fork, spawn_user_thread_with_vpid};
pub use wait_list::WaitList;
pub use zombies::{enqueue_zombie, park_for_wait4, park_zombie, reap_one, signal_child_exit};

pub mod preempt;

/// Hook for "send resched IPI to CPU N". Kernel installs this at boot
/// from `kernel/src/lapic.rs` (x86) or `kernel/src/gic.rs` (arm).
/// `balance::reschedule_cpu` calls through here instead of hard-
/// linking to lapic — keeps the sched crate arch-glue-free.
pub type SendReschedIpiFn = unsafe fn(u32) -> bool;
static SEND_IPI_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1) — atomic store.
pub fn set_send_resched_ipi_hook(f: SendReschedIpiFn) {
    SEND_IPI_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// # C: O(1) — atomic load + indirect call.
pub unsafe fn send_resched_ipi(cpu: u32) -> bool {
    let p = SEND_IPI_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return false; }
    // SAFETY: caller holds ABI contract; hook installed at boot from kernel.
    unsafe {
        let f: SendReschedIpiFn = core::mem::transmute(p);
        f(cpu)
    }
}
