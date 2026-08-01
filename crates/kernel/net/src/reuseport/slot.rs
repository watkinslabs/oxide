// Linux `sk->sk_reuseport_cb`: the per-socket cell naming the group a socket
// belongs to. Bound transport endpoints carry the same cell shape so the
// delivery path reaches the group from the canonical bind table alone.

use alloc::sync::Arc;
use sync::{Socket as SockLockClass, Spinlock};

use super::group::ReuseportGroup;

/// Storage behind one `sk_reuseport_cb`.
pub type SlotCell = Spinlock<Option<Arc<ReuseportGroup>>, SockLockClass>;

/// One socket's or endpoint's `sk_reuseport_cb`, shared by weak reference with
/// the group it joined.
pub type ReuseportSlot = Arc<SlotCell>;

/// Build a cell naming no group. # C: O(1)
pub fn new_slot() -> ReuseportSlot { Arc::new(Spinlock::new(None)) }

/// Read the group this cell names. # C: O(1)
pub fn group(slot: &ReuseportSlot) -> Option<Arc<ReuseportGroup>> { slot.lock().clone() }

/// Move this cell into `group`, leaving any group it already named. # C: O(N members)
pub fn join(slot: &ReuseportSlot, group: &Arc<ReuseportGroup>) {
    let previous = slot.lock().replace(group.clone());
    if let Some(previous) = previous {
        if Arc::ptr_eq(&previous, group) { return; }
        previous.remove_member(slot);
    }
    group.add_member(slot);
}

/// Leave whatever group this cell names. # C: O(N members)
pub fn leave(slot: &ReuseportSlot) {
    let previous = slot.lock().take();
    if let Some(previous) = previous { previous.remove_member(slot); }
}

/// Publish a group into a bound endpoint's cell without claiming membership;
/// the owning socket's cell is the member, so endpoint publication never
/// double-counts one socket. # C: O(1)
pub fn set_endpoint_group(slot: &ReuseportSlot, group: Option<Arc<ReuseportGroup>>) {
    *slot.lock() = group;
}
