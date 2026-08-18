//! Per-table hardware-version and performance-domain bindings.

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

/// Hardware owner of a PM-domain performance-state request.
pub trait PerformanceOps: Send + Sync {
    /// Program one platform-defined performance state. # C: O(provider)
    fn set_performance_state(&self, state: u32) -> KResult<()>;
}

struct Binding { table_phandle: u32, hardware: Option<Vec<u32>>, performance: Option<Arc<dyn PerformanceOps>> }

static BINDINGS: Spinlock<Vec<Binding>, Devices> = Spinlock::new(Vec::new());
/// Called after a table acquires hardware-version or performance-state ownership.
pub type AvailabilityListener = fn();
static AVAILABILITY_LISTENERS: Spinlock<Vec<AvailabilityListener>, Devices> = Spinlock::new(Vec::new());

/// Associate an OPP table with its platform-known hardware-version hierarchy.
/// A repeated association leaves the first, shared-table configuration intact. # C: O(tables + versions)
pub fn register_supported_hardware(table_phandle: u32, versions: Vec<u32>) -> KResult<()> {
    if table_phandle == 0 || versions.is_empty() { return Err(VfsError::Einval); }
    let mut bindings = BINDINGS.lock();
    let binding = binding_mut(&mut bindings, table_phandle);
    if binding.hardware.is_some() { return Ok(()); }
    binding.hardware = Some(versions);
    drop(bindings);
    notify_available();
    Ok(())
}

/// Register the PM-domain owner selected by one OPP table. # C: O(tables)
pub fn register_performance_domain(table_phandle: u32, ops: Arc<dyn PerformanceOps>) -> KResult<()> {
    if table_phandle == 0 { return Err(VfsError::Einval); }
    let mut bindings = BINDINGS.lock();
    let binding = binding_mut(&mut bindings, table_phandle);
    if binding.performance.is_some() { return Err(VfsError::Eexist); }
    binding.performance = Some(ops);
    drop(bindings);
    notify_available();
    Ok(())
}

/// Whether an OPP's flattened hardware-version matrix admits this table's hardware.
/// Missing platform versions disable only OPPs that declare a matrix. # C: O(levels × groups)
pub fn supports_hardware(table_phandle: u32, masks: Option<&[u32]>) -> bool {
    let Some(masks) = masks else { return true; };
    let versions = BINDINGS.lock().iter().find(|binding| binding.table_phandle == table_phandle)
        .and_then(|binding| binding.hardware.clone());
    let Some(versions) = versions else { return false; };
    masks.len() % versions.len() == 0 && masks.chunks_exact(versions.len()).any(|group| {
        group.iter().zip(&versions).all(|(mask, version)| *mask & *version != 0)
    })
}

/// Request one PM-domain performance state. A table without PM-domain scaling
/// accepts the request without changing hardware. # C: O(tables + provider)
pub fn set_performance_state(table_phandle: u32, state: u32) -> KResult<()> {
    let ops = BINDINGS.lock().iter().find(|binding| binding.table_phandle == table_phandle)
        .and_then(|binding| binding.performance.clone());
    match ops { Some(ops) => ops.set_performance_state(state), None => Ok(()) }
}

/// Subscribe a platform-probe receiver to newly available table ownership. # C: O(listeners)
pub fn subscribe_availability(listener: AvailabilityListener) {
    let mut listeners = AVAILABILITY_LISTENERS.lock();
    if !listeners.iter().any(|registered| core::ptr::fn_addr_eq(*registered, listener)) {
        listeners.push(listener);
    }
}

fn binding_mut(bindings: &mut Vec<Binding>, table_phandle: u32) -> &mut Binding {
    if let Some(index) = bindings.iter().position(|binding| binding.table_phandle == table_phandle) {
        return &mut bindings[index];
    }
    let index = bindings.len();
    bindings.push(Binding { table_phandle, hardware: None, performance: None });
    &mut bindings[index]
}

fn notify_available() {
    let listeners = AVAILABILITY_LISTENERS.lock().clone();
    for listener in listeners { listener(); }
}

#[cfg(test)]
pub fn clear_for_tests() {
    BINDINGS.lock().clear();
    AVAILABILITY_LISTENERS.lock().clear();
}

#[cfg(test)]
static TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[cfg(test)]
pub(crate) fn test_guard() -> std::sync::MutexGuard<'static, ()> {
    let guard = TEST_LOCK.lock().unwrap_or_else(|error| error.into_inner());
    clear_for_tests();
    guard
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

    static CALLS: AtomicUsize = AtomicUsize::new(0);
    static STATE: AtomicU32 = AtomicU32::new(0);
    static AVAILABLE: AtomicUsize = AtomicUsize::new(0);

    struct Domain;
    impl PerformanceOps for Domain {
        fn set_performance_state(&self, state: u32) -> KResult<()> {
            CALLS.fetch_add(1, Ordering::Relaxed);
            STATE.store(state, Ordering::Release);
            Ok(())
        }
    }

    fn available() { AVAILABLE.fetch_add(1, Ordering::Relaxed); }

    #[test]
    fn hardware_versions_require_every_level_of_one_matching_group() {
        let _guard = test_guard();
        register_supported_hardware(3, alloc::vec![0b0010, 0b0100]).expect("hardware");
        assert!(supports_hardware(3, Some(&[0b0010, 0b0100])));
        assert!(supports_hardware(3, Some(&[0b1000, 0b0100, 0b0010, 0b0100])));
        assert!(!supports_hardware(3, Some(&[0b0010, 0b1000])));
        assert!(!supports_hardware(3, Some(&[0b0010])));
        assert!(!supports_hardware(4, Some(&[u32::MAX])));
        assert!(supports_hardware(4, None));
    }

    #[test]
    fn performance_owner_is_unique_and_missing_ownership_is_a_noop() {
        let _guard = test_guard();
        CALLS.store(0, Ordering::Relaxed);
        STATE.store(0, Ordering::Relaxed);
        AVAILABLE.store(0, Ordering::Relaxed);
        subscribe_availability(available);
        set_performance_state(9, 4).expect("optional domain");
        register_performance_domain(9, Arc::new(Domain)).expect("domain");
        assert_eq!(register_performance_domain(9, Arc::new(Domain)), Err(VfsError::Eexist));
        set_performance_state(9, 4).expect("state");
        assert_eq!(CALLS.load(Ordering::Relaxed), 1);
        assert_eq!(STATE.load(Ordering::Acquire), 4);
        assert_eq!(AVAILABLE.load(Ordering::Relaxed), 1);
    }
}
