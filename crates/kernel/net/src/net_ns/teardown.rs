extern crate alloc;

use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use super::NET_NS;
use super::reaper_protocol::PendingSignal;
use crate::NetStack;

static FINAL_DROP_PENDING: PendingSignal<AtomicU64> = PendingSignal::new();
#[cfg(target_os = "oxide-kernel")]
static REAPER_READY: AtomicBool = AtomicBool::new(false);

fn signal_final_drop_pending() {
    FINAL_DROP_PENDING.publish();
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
    FINAL_DROP_PENDING.harvest()
}

#[cfg(target_os = "oxide-kernel")]
pub(super) fn reaper_ready() -> bool { REAPER_READY.load(Ordering::Acquire) }

/// Destroy all network state owned by one non-init namespace. # C: O(N)
#[cfg(test)]
pub(crate) fn destroy_namespace_into(stack: &NetStack, ns: u64) -> bool {
    destroy_namespace_owned(stack, crate::control_event::NamespaceOwner::Hosted(ns))
}

fn destroy_namespace_owned(stack: &NetStack,
                           namespace: crate::control_event::NamespaceOwner) -> bool {
    let ns = namespace.id();
    if ns == 0 { return false; }
    let mut removed = false;
    let published = {
        let rtnl = stack.rtnl_lock();
        removed |= stack.ifaces.abort_pending_in_ns(&rtnl, ns) != 0;
        stack.ifaces.snapshot_devs_in_ns(ns)
    };
    for (iface, _) in published {
        removed |= stack.teardown_iface_owned(namespace.clone(), iface);
    }
    removed |= stack.ipv4_reasm.remove_namespace(ns) != 0;
    removed |= stack.ipv6_reasm.remove_namespace(ns) != 0;
    let route_ticket = {
        let rtnl = stack.rtnl_lock();
        let records = stack.routes.snapshot_records_in(ns);
        removed |= stack.routes.remove_namespace_rtnl(&rtnl, ns);
        let routes6 = stack.routes6.take_namespace_rtnl(&rtnl, ns);
        removed |= !routes6.is_empty();
        removed |= crate::policy_rule::remove_namespace_rtnl(&rtnl, ns) != 0;
        let mut ticket = None;
        for records in crate::RouteTable::alias_groups(records) {
            ticket = Some(crate::control_event::stage(&rtnl,
                crate::control_event::ControlEvent::Route(crate::control_event::RouteEvent {
                    kind: crate::control_event::EventKind::Delete,
                    namespace: namespace.clone(), owners: alloc::vec::Vec::new(),
                    leases: alloc::vec::Vec::new(), records,
                })));
        }
        if !routes6.is_empty() {
            ticket = Some(crate::control_event::stage(&rtnl,
                crate::control_event::ControlEvent::Route6(crate::control_event::Route6Event {
                    kind: crate::control_event::EventKind::Delete,
                    namespace: namespace.clone(), owners: alloc::vec::Vec::new(), rows: routes6,
                })));
        }
        ticket
    };
    if let Some(ticket) = route_ticket { crate::control_event::publish(ticket); }
    #[cfg(any(target_os = "oxide-kernel", test, feature = "hosted"))]
    { removed |= crate::sock::teardown_packet_namespace(ns); }
    removed |= stack.remove_inet_namespace(ns);
    removed |= security::network::remove_namespace(ns) != 0;
    removed |= NET_NS.lock().remove(&ns).is_some();
    removed
}

fn drain_final_drops_into(stack: &NetStack) -> usize {
    let mut destroyed = 0;
    while take_final_drop_pending() {
        for id in network_namespace::take_dead_namespace_ids() {
            let owner = network_namespace::teardown_owner(id).expect("claimed teardown owner");
            destroyed += usize::from(destroy_namespace_owned(stack,
                crate::control_event::NamespaceOwner::Teardown(owner)));
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
        if FINAL_DROP_PENDING.published_after_arm() {
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
        let _guard = super::super::test_support::LIFETIME_LOCK.lock().unwrap();
        let stack = NetStack::new();
        let owner = super::super::test_support::allocate_namespace();
        let ns = owner.id().as_u64();
        super::super::materialize_loopback_into(&stack, &owner);
        drop(owner);
        assert!(drain_final_drops_into(&stack) >= 1);
        assert_eq!(drain_final_drops_into(&stack), 0);
        assert!(stack.ifaces.snapshot_devs_in_ns(ns).is_empty());
    }
}
