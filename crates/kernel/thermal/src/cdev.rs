// A cooling device: something that can be driven between a shallowest and a
// deepest state to remove heat — a fan with a speed ladder, a processor whose
// clock can be capped, a charger whose current can be limited.
//
// The device holds no policy. It records what it was last driven to and how
// long it spent in each state; which state it should be in is decided by the
// zones bound to it, and the deepest request wins.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};
use vfs::{KResult, VfsError};

/// The provider half of a cooling device.
pub trait CoolingOps: Send + Sync {
    /// Deepest state this device supports; state `0` is always "off".
    /// # C: O(1)
    fn max_state(&self) -> KResult<u64>;
    /// State the device is in now. # C: O(1)
    fn cur_state(&self) -> KResult<u64>;
    /// Drive the device to `state`. # C: O(1)
    fn set_cur_state(&self, state: u64) -> KResult<()>;
}

/// Per-state occupancy, for the transition statistics.
struct Stats {
    /// Total transitions into any state.
    transitions: u64,
    /// Monotonic nanoseconds spent in each state, indexed by state.
    time_ns: Vec<u64>,
    /// Transition counts, `from * states + to`.
    table: Vec<u64>,
    /// When the current state was entered.
    entered_ns: u64,
    /// State the accounting believes the device is in.
    state: u64,
}

/// One registered cooling device.
pub struct CoolingDevice {
    id: u32,
    ty: String,
    ops: Arc<dyn CoolingOps>,
    max_state: u64,
    stats: Spinlock<Stats, Devices>,
}

impl CoolingDevice {
    /// Build a device around its provider. # C: O(N_states)
    pub fn new(id: u32, ty: &str, ops: Arc<dyn CoolingOps>, max_state: u64, now_ns: u64)
        -> CoolingDevice
    {
        let states = (max_state as usize).saturating_add(1);
        CoolingDevice {
            id,
            ty: String::from(ty),
            ops,
            max_state,
            stats: Spinlock::new(Stats {
                transitions: 0,
                time_ns: alloc::vec![0; states],
                table: alloc::vec![0; states * states],
                entered_ns: now_ns,
                state: 0,
            }),
        }
    }

    /// Class-visible index. # C: O(1)
    pub fn id(&self) -> u32 { self.id }
    /// Provider-declared kind, as `type` reads it back. # C: O(1)
    pub fn ty(&self) -> &str { &self.ty }
    /// Deepest supported state. # C: O(1)
    pub fn max_state(&self) -> u64 { self.max_state }
    /// Class device name. # C: O(1)
    pub fn name(&self) -> String { crate::uapi::cdev_name(self.id) }

    /// Read the device's current state from the provider. # C: O(provider)
    pub fn cur_state(&self) -> KResult<u64> { self.ops.cur_state() }

    /// Drive the device, refusing a state it does not have. Statistics are
    /// recorded only for a transition the provider accepted, so a device that
    /// rejects a write does not appear to have moved. # C: O(provider)
    pub fn set_cur_state(&self, state: u64, now_ns: u64) -> KResult<()> {
        if state > self.max_state { return Err(VfsError::Einval); }
        self.ops.set_cur_state(state)?;
        self.record(state, now_ns);
        Ok(())
    }

    /// Account one accepted transition. # C: O(1)
    fn record(&self, state: u64, now_ns: u64) {
        let mut stats = self.stats.lock();
        let previous = stats.state;
        let elapsed = now_ns.saturating_sub(stats.entered_ns);
        if let Some(slot) = stats.time_ns.get_mut(previous as usize) {
            *slot = slot.saturating_add(elapsed);
        }
        stats.entered_ns = now_ns;
        if previous == state { return; }
        let width = stats.time_ns.len();
        let index = previous as usize * width + state as usize;
        if let Some(slot) = stats.table.get_mut(index) { *slot += 1; }
        stats.transitions += 1;
        stats.state = state;
    }

    /// Total accepted transitions. # C: O(1)
    pub fn transitions(&self) -> u64 { self.stats.lock().transitions }

    /// Nanoseconds spent in each state, with the current state's occupancy
    /// brought up to `now_ns`. # C: O(N_states)
    pub fn time_in_state_ns(&self, now_ns: u64) -> Vec<u64> {
        let stats = self.stats.lock();
        let mut times = stats.time_ns.clone();
        let elapsed = now_ns.saturating_sub(stats.entered_ns);
        if let Some(slot) = times.get_mut(stats.state as usize) {
            *slot = slot.saturating_add(elapsed);
        }
        times
    }

    /// Transition counts, row-major from-state by to-state. # C: O(N_states²)
    pub fn trans_table(&self) -> Vec<u64> { self.stats.lock().table.clone() }

    /// Clear the statistics without disturbing the device. # C: O(N_states²)
    pub fn reset_stats(&self, now_ns: u64) {
        let mut stats = self.stats.lock();
        stats.transitions = 0;
        stats.time_ns.iter_mut().for_each(|slot| *slot = 0);
        stats.table.iter_mut().for_each(|slot| *slot = 0);
        stats.entered_ns = now_ns;
    }
}

#[cfg(test)]
#[path = "tests/cdev.rs"]
mod tests;
