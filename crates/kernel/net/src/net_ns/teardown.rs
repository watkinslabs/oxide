extern crate alloc;

use core::sync::atomic::{AtomicBool, Ordering};

use super::NET_NS;
use crate::NetStack;

static FINAL_DROP_PENDING: AtomicBool = AtomicBool::new(false);
#[cfg(target_os = "oxide-kernel")]
static REAPER_READY: AtomicBool = AtomicBool::new(false);

fn signal_final_drop_pending() {
    FINAL_DROP_PENDING.store(true, Ordering::Release);
    #[cfg(target_os = "oxide-kernel")]
    softirq::raise_process(softirq::Slot::NetNsReap);
}

/// Install the lockless final-owner-drop signal used by namespace allocation.
/// # C: O(1)
/// # Ctx: process initialization
/// # Sleeps: no
pub fn install_final_drop_pending_notifier() -> Result<(), network_namespace::InstallError> {
    network_namespace::install_final_drop_callback(signal_final_drop_pending)
}

/// Consume the final-owner-drop pending signal. # C: O(1)
/// # Ctx: process
/// # Sleeps: no
pub fn take_final_drop_pending() -> bool {
    FINAL_DROP_PENDING.swap(false, Ordering::AcqRel)
}

#[cfg(target_os = "oxide-kernel")]
pub(super) fn reaper_ready() -> bool { REAPER_READY.load(Ordering::Acquire) }

/// Destroy all network state owned by one non-init namespace. # C: O(N)
pub(super) fn destroy_namespace_into(stack: &NetStack, ns: u64) -> bool {
    if ns == 0 { return false; }
    let mut removed = false;
    for (iface, _) in stack.ifaces.snapshot_devs_in_ns(ns) {
        removed |= stack.teardown_iface_in(ns, iface);
    }
    removed |= stack.ipv4_reasm.remove_namespace(ns) != 0;
    removed |= stack.ipv6_reasm.remove_namespace(ns) != 0;
    removed |= stack.routes.remove_namespace(ns);
    removed |= stack.routes6.remove_namespace(ns);
    removed |= crate::policy_rule::remove_namespace(ns) != 0;
    removed |= stack.remove_inet_namespace(ns);
    removed |= NET_NS.lock().remove(&ns).is_some();
    removed
}

fn drain_final_drops_into(stack: &NetStack) -> usize {
    let mut destroyed = 0;
    while take_final_drop_pending() {
        for id in network_namespace::take_dead_namespace_ids() {
            destroyed += usize::from(destroy_namespace_into(stack, id.as_u64()));
            let _finished = network_namespace::finish_teardown(id);
        }
    }
    destroyed
}

#[cfg(target_os = "oxide-kernel")]
static REAPER_WAIT: sched::live::WaitList = sched::live::WaitList::new();

#[cfg(target_os = "oxide-kernel")]
fn wake_namespace_reaper() { REAPER_WAIT.wake_all(); }

#[cfg(target_os = "oxide-kernel")]
extern "C" fn namespace_reaper(_arg: usize) -> ! {
    loop {
        let _ = drain_final_drops_into(crate::global_stack());
        // SAFETY: this dedicated kthread holds no subsystem lock while parking;
        // the post-arm pending check closes publication before sleep.
        unsafe { REAPER_WAIT.park(); }
        if FINAL_DROP_PENDING.load(Ordering::Acquire) {
            REAPER_WAIT.cancel_current_park();
            continue;
        }
        // SAFETY: the current reaper task was armed above and holds no lock.
        unsafe { sched::live::schedule(); }
    }
}

/// Start the process-context namespace teardown worker. # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn spawn_namespace_reaper() -> Result<(), sched::live::SpawnError> {
    let tid = sched::live::next_tid();
    // SAFETY: boot has installed the runqueue; entry and argument are static.
    let task = unsafe {
        sched::live::spawn_kernel_thread(tid, "netns_reaper", namespace_reaper, 0)
    }?;
    softirq::set_handler(softirq::Slot::NetNsReap, wake_namespace_reaper);
    REAPER_READY.store(true, Ordering::Release);
    drop(task);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pending_drop_drains_dead_namespace_once() {
        let stack = NetStack::new();
        install_final_drop_pending_notifier().unwrap();
        let owner = network_namespace::allocate(7).unwrap();
        let ns = owner.id().as_u64();
        super::super::materialize_loopback_into(&stack, &owner);
        drop(owner);
        assert!(drain_final_drops_into(&stack) >= 1);
        assert_eq!(drain_final_drops_into(&stack), 0);
        assert!(stack.ifaces.snapshot_devs_in_ns(ns).is_empty());
    }
}
