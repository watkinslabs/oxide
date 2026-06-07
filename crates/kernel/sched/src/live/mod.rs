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
pub mod sigpend;
pub mod tick_deadline;

pub use runqueue::{global, Runqueue};
pub use schedule::{
    current, current_mount_ns, current_chroot_root, mark_done, schedule, schedule_from_irq, tick_yield,
    install_default_runqueue, runqueue_active, RunStats,
};
pub use spawn::{next_tid, spawn_kernel_thread, spawn_user_thread, spawn_user_thread_for_fork, spawn_user_thread_with_vpid};
pub mod timer_driver;
pub use timer_driver::spawn_timer_driver;
pub use wait_list::WaitList;
pub use sigpend::{
    deliverable_signals, deliverable_signals_self, send_signal_self,
    wake_if_sleeping, freeze_task, unfreeze_task, Signum,
};
pub use tick_deadline::tick_wake_expired;
pub use zombies::{enqueue_zombie, has_zombies, park_for_wait4, park_zombie, peek_one, reap_one, reparent_children, signal_child_exit, unpark_self_from_wait4};

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

pub mod stop;

/// Global epoll wait list. `sys_epoll_wait` parks here when its
/// scan finds zero ready entries and `timeout != 0`; any fd-state-
/// change site (socket send, pipe write, etc.) calls
/// `notify_epoll_waiters()` after committing to wake every parked
/// caller. Each wakes, rescans its interest set, and either
/// returns events to user space or re-parks.
///
/// Lives in `sched` (not `fs::epoll`) so that the net/IPC layers
/// — which don't depend on `fs` — can still trigger the wakeup
/// without circular crate edges.
///
/// Single global vs per-EpollInode: v1 simplification. Spurious
/// wakeups are correct (level-triggered semantics) and cheap when
/// N_epolls is small (a boot has <5). Per-fd targeted
/// wakeups are a follow-up once the Inode trait grows a poll-wait
/// hook without dragging sched into vfs.
pub static EPOLL_GLOBAL_WAIT: WaitList = WaitList::new();

/// B57: wait queue for tasks blocked in `select`/`poll`/`ppoll`/
/// `pselect`. The Linux way: those syscalls register here, sleep
/// (zero CPU), and a data-ready site wakes them — instead of the old
/// busy-yield re-poll loop. Mirrors `EPOLL_GLOBAL_WAIT`. Level-
/// triggered: woken pollers re-scan and re-park if still not ready.
/// A bounded re-scan deadline in the syscall caps worst-case latency
/// for any fd type whose ready-site doesn't (yet) call
/// `notify_poll_waiters`, so a missing wake degrades to latency, not
/// a hang.
pub static POLL_WAIT: WaitList = WaitList::new();

/// Wake every task parked in `select`/`poll`. Call from any fd-state-
/// change site after committing a transition that flips a poll bit
/// (tty RX byte queued, pipe write, socket recv, …). Spurious calls
/// are safe. # C: O(N_pollers)
pub fn notify_poll_waiters() {
    POLL_WAIT.wake_all();
}

/// Wake every task parked in `sys_epoll_wait`. Call from any fd-
/// state-change site after committing the transition that would
/// flip a poll bit (POLL_IN became readable, POLL_HUP set, ...).
/// Spurious calls are safe — woken epollers re-scan and re-park
/// if still empty.
///
/// F181: dispatch wakes via the per-EpollInode waitlist hook
/// installed at boot (set_epoll_broadcast_hook). Falls back to
/// the global wait list when the hook is unset (early boot, no
/// fs crate active). InetSocket events should prefer the F181
/// targeted path (per-fd subscribers) and only fall through here
/// for inode types that haven't been migrated to subscriber lists.
/// # C: O(N_epoll_instances) typical
pub fn notify_epoll_waiters() {
    let p = EPOLL_BROADCAST_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() {
        EPOLL_GLOBAL_WAIT.wake_all();
        return;
    }
    // SAFETY: hook installed via set_epoll_broadcast_hook with
    // the documented `fn()` signature; Acquire-paired with the
    // Release store in the setter.
    let f: fn() = unsafe { core::mem::transmute(p) };
    f();
}

/// F181: broadcast wake hook installed by `fs::epoll` at boot.
/// Lives here so non-fs callers (net, ipc) can drive
/// notify_epoll_waiters() without the circular dep (fs depends on
/// vfs+sched; net depends on sched but not fs).
static EPOLL_BROADCAST_HOOK: core::sync::atomic::AtomicPtr<()>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1)
pub fn set_epoll_broadcast_hook(f: fn()) {
    EPOLL_BROADCAST_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}
