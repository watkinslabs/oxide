// B1409: final `InetSocket` release must never take RTNL from softirq/
// hard-IRQ context. RTNL is about to become a sleeping mutex (B1408), and
// Linux never runs socket teardown from BH in the first place: `sock_put()`
// -> `sk_free()` -> `__sk_destruct` always runs from process context or an
// RCU callback, never the RX softirq.
//
// `sock::packet::deliver()` (the AF_PACKET fan-out) runs inline in the
// NetRx softirq (`drv-virtio-net rx_drain_softirq`, `softirq::Slot::NetRx`)
// holding temporary `Arc<InetSocket>` clones obtained via `Weak::upgrade()`.
// If the owning fd closes while a frame is in flight, that temporary
// clone's drop can be the LAST `Arc<InetSocket>` reference, running
// `InetSocket::Drop` -> `release_file()` on the softirq stack.
//
// `release_file()` (`sock_drop.rs`) detects the context with
// `sched::preempt::in_interrupt()` — the canonical HARDIRQ|SOFTIRQ
// predicate this kernel already uses for `in_atomic()`/lockdep — and, when
// unsafe to run inline, hands the two RTNL-taking pieces here instead of
// running them:
//   - `SocketMcast::release`: `mcast` is already `Arc<SocketMcast>`
//     (shared across derived sockets), so deferring it is a cheap
//     `Arc::clone` — no extraction needed.
//   - `PacketMemberships`: owned by value inside `InetSocket`, so its rows
//     are taken out (a plain spinlock op, no RTNL) by
//     `PacketMemberships::take_pending` before the socket can be freed.
//
// A DEDICATED kthread + queue, not the shared `sched::live::workqueue`:
// that ring is FIXED CAPACITY per CPU and drops on overflow BY DESIGN
// (`queue_work` callers are expected to tolerate or retry a lost item).
// Losing a deferred socket release would leak multicast group membership /
// packet-filter registrations forever — never acceptable — so this path
// gets its own never-drops queue, the same shape as the `netns_reaper`
// final-drop queue (`net_ns/teardown.rs`) and the `kworker` missed-wakeup
// backstop (`sched::live::workqueue`).

extern crate alloc;
use alloc::collections::VecDeque;
use alloc::sync::Arc;
use sync::{Spinlock, Socket as LockClass};

use crate::mcast_filter::SocketMcast;
use crate::sock::PendingPacketRelease;
use crate::stack::NetStack;

/// One socket's extracted RTNL-taking teardown, captured while the socket
/// was still alive. Both pieces are optional: a socket with no multicast
/// groups and no packet memberships never gets queued at all
/// (`defer` skips it).
struct Pending {
    mcast: Option<Arc<SocketMcast>>,
    packet: Option<PendingPacketRelease>,
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
type DeferIrq = hal_x86_64::X86IrqGate;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
type DeferIrq = hal_aarch64::ArmIrqGate;
#[cfg(not(target_os = "oxide-kernel"))]
type DeferIrq = sync::NoopIrq;

static PENDING: Spinlock<VecDeque<Pending>, LockClass> = Spinlock::new(VecDeque::new());
// `sched::live` (the kthread/WaitList runtime) is only compiled for a real
// kernel target or `sched`'s OWN unit tests (`#[cfg(any(target_os =
// "oxide-kernel", test))]` in `sched/src/lib.rs`) — `net`'s hosted tests
// build `sched` as a plain (non-test) dependency, so `sched::live` does not
// exist there. Hosted tests exercise `defer`/`drain_all` directly and never
// need the wake side; only the kernel target spawns the reaper kthread.
#[cfg(target_os = "oxide-kernel")]
static WAIT: sched::live::WaitList = sched::live::WaitList::new();

/// Queue one socket's RTNL-taking teardown for the dedicated reaper
/// kthread. A no-op when both pieces are empty — the common case (most
/// sockets never join a multicast group or register a packet membership).
/// Safe from ANY context including hard-IRQ: no RTNL, no sleep, bounded
/// work (irqsave push + wake). # C: O(1)
/// # Ctx: any, including softirq/hard-IRQ
pub(crate) fn defer(mcast: Option<Arc<SocketMcast>>, packet: Option<PendingPacketRelease>) {
    if mcast.is_none() && packet.is_none() { return; }
    PENDING.lock_irqsave::<DeferIrq>().push_back(Pending { mcast, packet });
    #[cfg(target_os = "oxide-kernel")]
    WAIT.wake_one();
}

/// Drain everything queued right now, finishing each socket's RTNL-taking
/// release in process context. Returns the number of sockets finished —
/// hosted tests use this to prove nothing is silently lost.
/// # C: O(N queued)
/// # Ctx: process context only (may take RTNL / sleep)
pub(crate) fn drain_all(stack: &NetStack) -> usize {
    let mut done = 0;
    loop {
        let next = PENDING.lock_irqsave::<DeferIrq>().pop_front();
        let Some(item) = next else { return done };
        if let Some(mcast) = item.mcast { mcast.release(stack); }
        if let Some(packet) = item.packet { crate::sock::finish_pending_packet_release(packet); }
        done += 1;
    }
}

/// Sockets queued right now, awaiting the reaper. Diagnostics + tests.
/// # C: O(1)
pub(crate) fn pending_len() -> usize { PENDING.lock_irqsave::<DeferIrq>().len() }

/// Missed-wakeup backstop, same idiom as `ksoftirqd`/`kworker`: a `defer`
/// landing between the emptiness check and the park would otherwise wait
/// for the next producer.
const BACKSTOP_NS: u64 = 100_000_000;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_x86_64::X86TimerOps::monotonic_ns().0 }
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))]
fn now_ns() -> u64 { use hal::TimerOps; hal_aarch64::ArmTimerOps::monotonic_ns().0 }

/// Linux `sk_free`'s process-context finisher, run from a dedicated kthread
/// rather than an RCU callback (this kernel has no RCU-callback execution
/// context yet): drain queued releases, yield between bursts, park until
/// `defer` wakes us. # C: O(queued work) per wake
#[cfg(target_os = "oxide-kernel")]
extern "C" fn sock_rtnl_reaper(_arg: usize) -> ! {
    loop {
        if pending_len() != 0 {
            drain_all(crate::global_stack());
            // cond_resched(): draining a burst must stay preemptible.
            // SAFETY: running kthread, no lock held; schedule re-enqueues
            // this still-Runnable task.
            unsafe { sched::live::schedule(); }
            continue;
        }
        // SAFETY: running kthread on this CPU, no lock held across the
        // park; schedule() yields immediately per the WaitList contract.
        unsafe {
            WAIT.park_with_deadline(now_ns() + BACKSTOP_NS);
            sched::live::schedule();
        }
    }
}

/// Spawn the dedicated process-context reaper for deferred RTNL-taking
/// socket teardown. Boot, once, after runqueue install (same site as
/// `spawn_ksoftirqd`/`spawn_namespace_reaper`). # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn spawn_sock_rtnl_reaper() -> Result<(), sched::live::SpawnError> {
    let tid = sched::live::next_tid();
    // SAFETY: boot path after install_default_runqueue + AP bring-up; entry
    // is a 'static extern "C" fn pointer; arg is unused.
    let task = unsafe {
        sched::live::spawn_kernel_thread(tid, "sock-rtnl-reap", sock_rtnl_reaper, 0)
    }?;
    drop(task);
    Ok(())
}

#[cfg(test)]
#[path = "sock_rtnl_defer_tests.rs"]
mod tests;
