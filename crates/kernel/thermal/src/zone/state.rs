// The zone object and its mutable half.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use sync::{Devices, Spinlock};

use crate::cdev::CoolingDevice;
use crate::governor::{default_governor, Governor, InstanceView};
use crate::limits::RECHECK_DELAY_MS;
use crate::monitor::Cadence;
use crate::trip::TripDesc;
use crate::uapi::{Mode, TEMP_INVALID};
use crate::update::Window;

use super::desc::{ZoneDesc, ZoneOps};

/// One cooling device bound to one trip of this zone.
pub struct Instance {
    /// Index within the zone; the `cdev<N>` link is named after it.
    pub id: u32,
    /// Trip this binding cools.
    pub trip: usize,
    pub cdev: Arc<CoolingDevice>,
    pub upper: u64,
    pub lower: u64,
    pub weight: u32,
    /// Whether `upper` tracks the device's maximum as it changes.
    pub upper_no_limit: bool,
    /// State this binding asks for, or `NO_TARGET`.
    pub target: u64,
    /// Whether a governor has ever assigned this binding a target.
    pub initialized: bool,
}

/// Everything about a zone that changes.
pub struct ZoneState {
    pub mode: Mode,
    /// Most recent reading, millidegrees Celsius.
    pub temperature: i32,
    /// The reading before it, for the fallback trend.
    pub last_temperature: i32,
    pub trips: Vec<TripDesc>,
    /// Ordinary and throttled polling cadences. Firmware may replace these
    /// together with its trip ladder after a threshold notification.
    pub cadence: Cadence,
    pub instances: Vec<Instance>,
    pub governor: &'static Governor,
    /// Current sensor-failure backoff, milliseconds.
    pub backoff_ms: u64,
    /// Last window handed to the provider, so an unchanged one is not
    /// re-programmed on every sample.
    pub window: Option<Window>,
    /// Monotonic deadline of the next scheduled read, or `None` when the zone
    /// is event-driven or disabled.
    pub deadline_ns: Option<u64>,
    /// Next instance id.
    pub next_instance: u32,
}

/// One registered thermal zone.
pub struct ThermalZone {
    id: u32,
    ty: String,
    ops: Arc<dyn ZoneOps>,
    pub(crate) state: Spinlock<ZoneState, Devices>,
}

impl ThermalZone {
    /// Build a zone from a provider's declaration. # C: O(N_trips)
    pub fn new(id: u32, desc: ZoneDesc, ops: Arc<dyn ZoneOps>) -> ThermalZone {
        let governor = desc.governor.as_deref()
            .and_then(crate::governor::by_name)
            .unwrap_or_else(default_governor);
        ThermalZone {
            id,
            ty: desc.ty,
            ops,
            state: Spinlock::new(ZoneState {
                mode: Mode::Enabled,
                temperature: TEMP_INVALID,
                last_temperature: TEMP_INVALID,
                trips: desc.trips.into_iter().map(TripDesc::new).collect(),
                cadence: desc.cadence,
                instances: Vec::new(),
                governor,
                backoff_ms: RECHECK_DELAY_MS,
                window: None,
                deadline_ns: None,
                next_instance: 0,
            }),
        }
    }

    /// Class-visible index. # C: O(1)
    pub fn id(&self) -> u32 { self.id }
    /// Provider-declared kind, as `type` reads it back. # C: O(1)
    pub fn ty(&self) -> &str { &self.ty }
    /// Class device name. # C: O(1)
    pub fn name(&self) -> String { crate::uapi::zone_name(self.id) }
    /// The declared cadences. # C: O(1)
    pub fn cadence(&self) -> Cadence { self.state.lock().cadence }
    /// The provider. # C: O(1)
    pub fn ops(&self) -> &Arc<dyn ZoneOps> { &self.ops }

    /// Last reading. # C: O(1)
    pub fn temperature(&self) -> i32 { self.state.lock().temperature }
    /// Whether the zone participates in updates. # C: O(1)
    pub fn mode(&self) -> Mode { self.state.lock().mode }
    /// Name of the governor in force. # C: O(1)
    pub fn policy(&self) -> &'static str { self.state.lock().governor.name }
    /// How many trips the zone declares. # C: O(1)
    pub fn trip_count(&self) -> usize { self.state.lock().trips.len() }
    /// Copy of one trip. # C: O(1)
    pub fn trip(&self, index: usize) -> Option<TripDesc> {
        self.state.lock().trips.get(index).copied()
    }
    /// The scheduled deadline of the next read. # C: O(1)
    pub fn deadline_ns(&self) -> Option<u64> { self.state.lock().deadline_ns }

    /// `(instance id, cooling device)` for every binding. # C: O(N_instances)
    pub fn bindings(&self) -> Vec<(u32, usize, Arc<CoolingDevice>)> {
        self.state.lock().instances.iter()
            .map(|inst| (inst.id, inst.trip, Arc::clone(&inst.cdev)))
            .collect()
    }

    /// Weight of one binding. # C: O(N_instances)
    pub fn binding_weight(&self, id: u32) -> Option<u32> {
        self.state.lock().instances.iter().find(|inst| inst.id == id).map(|inst| inst.weight)
    }

    /// Set the weight of one binding. # C: O(N_instances)
    pub fn set_binding_weight(&self, id: u32, weight: u32) -> bool {
        let mut state = self.state.lock();
        match state.instances.iter_mut().find(|inst| inst.id == id) {
            Some(inst) => { inst.weight = weight; true }
            None => false,
        }
    }

    /// Every state this zone currently asks of `cdev`. Aggregation across all
    /// zones needs each zone's requests, and a binding the governor has not
    /// assigned yet contributes nothing. # C: O(N_instances)
    pub fn requests_for(&self, cdev: &Arc<CoolingDevice>) -> Vec<u64> {
        self.state.lock().instances.iter()
            .filter(|inst| Arc::ptr_eq(&inst.cdev, cdev))
            .filter(|inst| inst.initialized)
            .map(|inst| inst.target)
            .collect()
    }

    /// Select a governor by name. # C: O(N_governors)
    pub fn set_policy(&self, name: &str) -> bool {
        let Some(governor) = crate::governor::by_name(name) else { return false; };
        let mut state = self.state.lock();
        if core::ptr::eq(state.governor, governor) { return true; }
        state.governor = governor;
        // A new governor has assigned nothing yet, so every binding must be
        // pushed again: otherwise a device left engaged by the outgoing
        // governor stays there until the next crossing.
        for inst in state.instances.iter_mut() { inst.initialized = false; }
        true
    }

    /// Enable or disable the zone. A disabled zone is not read and not
    /// polled; its bindings keep whatever they were last driven to, which is
    /// the conservative choice for a fan. # C: O(1)
    pub fn set_mode(&self, mode: Mode) {
        let mut state = self.state.lock();
        state.mode = mode;
        if mode == Mode::Disabled { state.deadline_ns = None; }
    }
}

/// Snapshot of the bindings for a governor pass. Reading each device's current
/// state is a provider call, so it happens before the zone lock is taken.
/// # C: O(N_instances)
pub fn views(instances: &[Instance], cur_states: &[u64]) -> Vec<InstanceView> {
    instances.iter().zip(cur_states).map(|(inst, cur)| InstanceView {
        trip: inst.trip,
        cdev_max: inst.cdev.max_state(),
        cdev_cur: *cur,
        upper: inst.upper,
        lower: inst.lower,
        weight: inst.weight,
        target: inst.target,
        initialized: inst.initialized,
    }).collect()
}
