//! PMM shrinker registry. Callbacks are copied before invocation so reclaim
//! never holds registry serialization across a subsystem lock or PMM release.

use alloc::vec::Vec;

use sync::{Spinlock, TaskList};

/// One Linux-shaped shrinker callback pair. `count_objects` reports only
/// reclaimable objects; `scan_objects` releases at most its requested budget
/// where the owner can make that guarantee.
#[derive(Copy, Clone)]
pub struct Shrinker {
    pub count_objects: fn() -> usize,
    pub scan_objects: fn(usize) -> usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ShrinkerError { Duplicate, NoMem }

static SHRINKERS: Spinlock<Vec<Shrinker>, TaskList> = Spinlock::new(Vec::new());

/// Register one subsystem's canonical reclaim callbacks. Duplicate callbacks
/// are rejected so one cache cannot have two PMM reclaim owners. # C: O(N)
pub fn register_shrinker(shrinker: Shrinker) -> Result<(), ShrinkerError> {
    let mut shrinkers = SHRINKERS.lock();
    if shrinkers.iter().any(|registered| {
        registered.count_objects as usize == shrinker.count_objects as usize
            && registered.scan_objects as usize == shrinker.scan_objects as usize
    }) { return Err(ShrinkerError::Duplicate); }
    shrinkers.try_reserve(1).map_err(|_| ShrinkerError::NoMem)?;
    shrinkers.push(shrinker);
    Ok(())
}

/// Count reclaimable objects without holding the registry lock over a callback.
/// # C: O(number of shrinkers)
pub fn shrinker_count() -> usize {
    let callbacks = { SHRINKERS.lock().clone() };
    callbacks.into_iter().fold(0usize, |count, shrinker| count.saturating_add((shrinker.count_objects)()))
}

/// Run registered cache reclaim outside registry serialization. Each callback
/// receives only the still-unmet budget, preventing one owner from consuming
/// an unbounded direct-reclaim scan. # C: O(number of shrinkers)
pub fn shrinker_scan(target: usize) -> usize {
    let callbacks = { SHRINKERS.lock().clone() };
    let mut released = 0usize;
    for shrinker in callbacks {
        let Some(remaining) = target.checked_sub(released) else { break; };
        if remaining == 0 { break; }
        released = released.saturating_add((shrinker.scan_objects)(remaining));
    }
    released
}

#[cfg(test)]
mod tests {
    use core::sync::atomic::{AtomicUsize, Ordering};

    use super::{register_shrinker, shrinker_count, shrinker_scan, Shrinker, ShrinkerError};

    static COUNT: AtomicUsize = AtomicUsize::new(0);
    static SCANNED: AtomicUsize = AtomicUsize::new(0);
    const RECLAIMABLE_OBJECTS: usize = 3;
    const REQUESTED_OBJECTS: usize = 2;

    fn count() -> usize { RECLAIMABLE_OBJECTS }
    fn scan(target: usize) -> usize { SCANNED.fetch_add(target, Ordering::SeqCst); target }

    #[test]
    fn callbacks_register_once_and_scan_only_the_requested_budget() {
        let shrinker = Shrinker { count_objects: count, scan_objects: scan };
        let _ = register_shrinker(shrinker);
        assert_eq!(register_shrinker(shrinker), Err(ShrinkerError::Duplicate));
        assert!(shrinker_count() >= RECLAIMABLE_OBJECTS);
        assert_eq!(shrinker_scan(REQUESTED_OBJECTS), REQUESTED_OBJECTS);
        assert!(SCANNED.load(Ordering::SeqCst) >= REQUESTED_OBJECTS);
        COUNT.fetch_add(0, Ordering::SeqCst);
    }
}
