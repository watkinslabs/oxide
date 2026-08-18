//! Registered clock-provider operations.

use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

/// Hardware owner of one clock rate.
pub trait ClockOps: Send + Sync {
    /// Current hardware rate in hertz. # C: O(provider)
    fn rate_hz(&self) -> Option<u64>;
    /// Program an exact rate in hertz. # C: O(provider)
    fn set_rate_hz(&self, rate_hz: u64) -> KResult<()>;
    /// Whether this owner may change rate after registration. # C: O(1)
    fn rate_changeable(&self) -> bool { true }
}

/// One fully-qualified DT clock reference: provider phandle plus every cell
/// selecting one output from that provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClockSpec { provider: u32, arguments: Vec<u32> }

impl ClockSpec {
    /// Construct a non-null provider reference. # C: O(arguments)
    pub fn new(provider: u32, arguments: Vec<u32>) -> Option<Self> {
        (provider != 0).then_some(Self { provider, arguments })
    }
    /// Provider phandle. # C: O(1)
    pub fn provider(&self) -> u32 { self.provider }
    /// Provider-specific selector cells. # C: O(1)
    pub fn arguments(&self) -> &[u32] { &self.arguments }
}

/// One DT-addressable clock provider.
pub struct Clock { spec: ClockSpec, ops: Arc<dyn ClockOps> }

impl Clock {
    /// Device-tree clock spec naming this output. # C: O(1)
    pub fn spec(&self) -> &ClockSpec { &self.spec }
    /// Current rate in hertz. # C: O(provider)
    pub fn rate_hz(&self) -> Option<u64> { self.ops.rate_hz() }
    /// Program one exact rate in hertz. # C: O(provider)
    pub fn set_rate_hz(&self, rate_hz: u64) -> KResult<()> { self.ops.set_rate_hz(rate_hz) }
    /// Whether this clock can change rate. # C: O(1)
    pub fn rate_changeable(&self) -> bool { self.ops.rate_changeable() }
}

static CLOCKS: Spinlock<Vec<Arc<Clock>>, Devices> = Spinlock::new(Vec::new());
/// Called after a newly registered owner becomes visible to lookups.
pub type AvailabilityListener = fn();
static AVAILABILITY_LISTENERS: Spinlock<Vec<AvailabilityListener>, Devices> = Spinlock::new(Vec::new());

/// Register a clock owner at its complete device-tree spec. # C: O(clocks)
pub fn register(spec: ClockSpec, ops: Arc<dyn ClockOps>) -> KResult<Arc<Clock>> {
    let mut clocks = CLOCKS.lock();
    if clocks.iter().any(|clock| clock.spec == spec) { return Err(VfsError::Eexist); }
    let clock = Arc::new(Clock { spec, ops });
    clocks.push(Arc::clone(&clock));
    drop(clocks);
    notify_available();
    Ok(clock)
}

/// Resolve a registered complete DT clock spec. # C: O(clocks)
pub fn by_spec(spec: &ClockSpec) -> Option<Arc<Clock>> {
    CLOCKS.lock().iter().find(|clock| clock.spec == *spec).cloned()
}

/// Subscribe a platform-probe receiver to future clock-owner registration. # C: O(listeners)
pub fn subscribe_availability(listener: AvailabilityListener) {
    let mut listeners = AVAILABILITY_LISTENERS.lock();
    if !listeners.iter().any(|registered| core::ptr::fn_addr_eq(*registered, listener)) {
        listeners.push(listener);
    }
}

fn notify_available() {
    let listeners = AVAILABILITY_LISTENERS.lock().clone();
    for listener in listeners { listener(); }
}

#[cfg(test)]
pub fn clear_for_tests() {
    CLOCKS.lock().clear();
    AVAILABILITY_LISTENERS.lock().clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

    static AVAILABLE: AtomicUsize = AtomicUsize::new(0);
    static ALSO_AVAILABLE: AtomicUsize = AtomicUsize::new(0);

    fn available() { AVAILABLE.fetch_add(1, Ordering::Relaxed); }
    fn also_available() { ALSO_AVAILABLE.fetch_add(1, Ordering::Relaxed); }

    struct Mock { rate: AtomicU64 }
    impl ClockOps for Mock {
        fn rate_hz(&self) -> Option<u64> { Some(self.rate.load(Ordering::Acquire)) }
        fn set_rate_hz(&self, rate_hz: u64) -> KResult<()> { self.rate.store(rate_hz, Ordering::Release); Ok(()) }
    }

    #[test]
    fn a_clock_phandle_has_one_authoritative_rate_owner() {
        clear_for_tests();
        AVAILABLE.store(0, Ordering::Relaxed);
        ALSO_AVAILABLE.store(0, Ordering::Relaxed);
        subscribe_availability(available);
        subscribe_availability(available);
        subscribe_availability(also_available);
        let spec = ClockSpec::new(7, alloc::vec![3]).expect("spec");
        let first = register(spec.clone(), Arc::new(Mock { rate: AtomicU64::new(1_000_000) })).expect("clock");
        assert_eq!(by_spec(&spec).and_then(|clock| clock.rate_hz()), Some(1_000_000));
        first.set_rate_hz(2_000_000).expect("rate");
        assert_eq!(first.rate_hz(), Some(2_000_000));
        assert_eq!(AVAILABLE.load(Ordering::Relaxed), 1);
        assert_eq!(ALSO_AVAILABLE.load(Ordering::Relaxed), 1);
        assert!(matches!(register(spec, Arc::new(Mock { rate: AtomicU64::new(1) })), Err(VfsError::Eexist)));
    }
}
