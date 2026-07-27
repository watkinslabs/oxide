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
//   `schedule` — the one `schedule()` switch primitive (`13§8`) +
//                `finish_task_switch` handoff; IRQ-exit routes through
//                it via `oxide_irq_resched_on_exit` (`14§R07`).
//
// Replaces the `kernel/src/ksched.rs` Vec-shim per the P2-13b
// branch in state.md.


pub mod balance;
pub mod chroot_refs;
pub mod registry;
pub mod runqueue;
pub mod schedule;
pub mod spawn;
pub mod sched_fork;
pub mod ttwu;
pub mod delayed_work;
pub mod tasklet;
pub mod threaded_irq;
pub mod timer_list;
pub mod kthread;
pub mod mutex;
pub mod workqueue;
pub mod wait_list;
pub mod zombies;
pub mod sigpend;
pub mod sb_freeze;
pub mod quota_wait;
pub mod inode_wait;
pub mod migration_wait;
pub mod tick_deadline;
pub mod vfs_context;
#[cfg(feature = "debug-wakelat")]
pub mod wakelat;

pub use chroot_refs::chroot_fs_refs;
pub use ttwu::{try_to_wake_up, ttwu_deferred, select_task_rq, resched_curr, relocate_for_affinity};

pub use runqueue::{global, Runqueue};
pub use schedule::{
    current, current_mount_ns, current_chroot_root, mark_done, schedule,
    oxide_finish_task_switch, park_yield, sched_yield, tick_yield,
    install_default_runqueue, runqueue_active, RunStats,
    install_sched_switch_hook, SchedSwitchFn,
};
pub use spawn::{next_tid, publish_new_task, spawn_kernel_thread, spawn_user_thread,
    spawn_user_thread_for_fork, spawn_user_thread_with_vpid, wake_new_task, SpawnError};
pub mod timer_driver;
pub use timer_driver::spawn_timer_driver;
pub mod ksoftirqd;
pub use ksoftirqd::spawn_ksoftirqd;
pub use wait_list::WaitList;
pub use mutex::{Mutex, MutexGuard};
pub use kthread::{should_stop as kthread_should_stop, stop as kthread_stop};
pub use workqueue::{queue_work, queue_work_on, WorkFn};
pub use delayed_work::queue_delayed_work_on;
pub use tasklet::TaskletFn;
pub use timer_list::TimerFn;
pub use threaded_irq::{request as request_threaded_irq, free as free_threaded_irq};
pub use sigpend::{
    deliverable_signals, deliverable_signals_self, send_signal_self, signal_wake_up,
    wake_if_sleeping, vfork_done, freeze_task, unfreeze_task, zap_other_threads, Signum,
};
pub use tick_deadline::tick_wake_expired;
pub use vfs_context::{current_vfs_lookup_context, VfsLookupContext};
pub use zombies::{enqueue_zombie, has_wait_zombies, has_zombies, park_for_wait4, peek_one, reap_one, reap_orphans, reparent_children, signal_child_exit, terminate_current_with_signal, unpark_self_from_wait4};

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

// poll/select/ppoll no longer use a global wait queue. Per the Linux
// `->poll` model each call registers a per-call `PollWaiter` (in
// syscalls::poll::poll_common) on EACH polled fd's own `PollSubscribers`
// (the inode's `poll_subscribers()`); the fd's readiness transition
// `notify()`s only its subscribers. The old global `POLL_WAIT` +
// `notify_poll_waiters` (wake every poller on any fd) is gone.

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

/// Lightweight sibling of `notify_epoll_waiters`: bump ONLY the global epoll
/// generation (no waitlist wake). The next `epoll_wait` safety-net rescan then
/// re-evaluates level-ready fds that EPOLLET already marked `et_seen` — needed
/// when a fd becomes ready AFTER its exit-time notify already advanced/consumed
/// the gen. The concrete case: a child's SIGCHLD + gen bump fire in
/// `signal_child_exit` BEFORE the zombie is enqueued into `ZOMBIES` (that
/// happens later in the context-switch tail via `enqueue_zombie`), so the
/// parent's signalfd/pidfd only reports `has_zombies` readiness on a fresh gen
/// edge — which never comes, stalling the reap ~45s until an unrelated event.
/// Safe to call from the switch tail where a full wake is not: a single atomic
/// `fetch_add` behind the hook. # C: O(1)
pub fn bump_epoll_gen() {
    let p = EPOLL_GEN_BUMP_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook installed via set_epoll_gen_bump_hook with the documented
    // `fn()` signature; Acquire-paired with the Release store in the setter.
    let f: fn() = unsafe { core::mem::transmute(p) };
    f();
}

static EPOLL_GEN_BUMP_HOOK: core::sync::atomic::AtomicPtr<()>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1)
pub fn set_epoll_gen_bump_hook(f: fn()) {
    EPOLL_GEN_BUMP_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Robust-futex exit walk (`ipc::live::futex::exit_robust_list`), installed at
/// boot by kmain. Lives here as a hook because the walk body is in `ipc`, and
/// `ipc` already depends on `sched` — a direct `sched -> ipc` dep would cycle.
/// The scheduler-owned fatal-exit path drives it through `run_robust_exit` so a
/// thread killed by a fatal fault while holding a robust mutex still marks it
/// FUTEX_OWNER_DIED and wakes a waiter (Linux
/// `do_exit -> exit_robust_list`; the syscall exit path calls the body directly
/// from `060_exit.rs`). `(head_uaddr, owner_tid)`.
pub type RobustExitFn = fn(u64, u32);
static ROBUST_EXIT_HOOK: core::sync::atomic::AtomicPtr<()>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1)
pub fn set_robust_exit_hook(f: RobustExitFn) {
    ROBUST_EXIT_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Run the installed robust-futex exit walk for a dying task. No-op if unset
/// (early boot before kmain wires the hook). MUST be called while the dying
/// task's mm is still mapped (the walk reads user memory under the active AS).
/// # C: O(list_len) via the installed walk
pub fn run_robust_exit(head_uaddr: u64, owner_tid: u32) {
    let p = ROBUST_EXIT_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook installed via set_robust_exit_hook with the documented RobustExitFn signature; Acquire load pairs with the Release store in the setter; ptr is a valid 'static fn address.
    let f: RobustExitFn = unsafe { core::mem::transmute(p) };
    f(head_uaddr, owner_tid);
}

/// SysV `SEM_UNDO` exit walk (`ipc::sysv::sem::exit_sem`), installed at boot by
/// kmain. Same hook shape and same reason as `RobustExitFn`: the body lives in
/// `ipc`, which already depends on `sched`. A process dying while holding a
/// semaphore it acquired with `SEM_UNDO` must have that adjustment applied
/// (Linux `do_exit -> exit_sem`), or every peer waiting on the semaphore blocks
/// forever. Argument is the dying task's thread-group id.
pub type SysvSemExitFn = fn(u32);
static SYSVSEM_EXIT_HOOK: core::sync::atomic::AtomicPtr<()>
    = core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1)
pub fn set_sysvsem_exit_hook(f: SysvSemExitFn) {
    SYSVSEM_EXIT_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Run the installed `SEM_UNDO` exit walk for a dying process. No-op if unset
/// (early boot before kmain wires the hook). Touches no user memory, so it has
/// no ordering requirement against the mm teardown.
/// # C: O(N_undo × nsems) via the installed walk
pub fn run_sysvsem_exit(tgid: u32) {
    let p = SYSVSEM_EXIT_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook installed via set_sysvsem_exit_hook with the documented SysvSemExitFn signature; Acquire load pairs with the Release store in the setter; ptr is a valid 'static fn address.
    let f: SysvSemExitFn = unsafe { core::mem::transmute(p) };
    f(tgid);
}
