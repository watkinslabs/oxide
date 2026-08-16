//! Control descriptions and the handler that owns a device's controls.

use alloc::vec::Vec;
use sync::{Spinlock, TaskList};

use crate::uapi::ctrl_ids as cid;

/// A control's fixed description, as the driver declares it.
#[derive(Copy, Clone, Debug)]
pub struct ControlDesc {
    pub id: u32,
    pub ctrl_type: u32,
    pub name: &'static str,
    pub minimum: i64,
    pub maximum: i64,
    /// Step for a numeric control; the skip mask for a menu.
    pub step: u64,
    pub default_value: i64,
    /// `V4L2_CTRL_FLAG_*` the driver declares. The handler adds the ones it
    /// derives itself, such as the slider hint on a plain integer.
    pub flags: u32,
    /// Menu entry names, indexed from `minimum`. Empty for a non-menu control
    /// and for an integer menu, whose entries are values rather than names.
    pub menu: &'static [&'static str],
    /// Integer-menu values, indexed from `minimum`.
    pub menu_values: &'static [i64],
    /// Controls that must move together with this one. A cluster's first
    /// member is the one an application addresses; the rest follow.
    pub cluster: &'static [u32],
}

impl ControlDesc {
    /// Flags reported to userspace: the driver's, plus the ones the type
    /// itself implies. A plain bounded integer is a slider, and a button
    /// carries no value to read back.
    /// # C: O(1)
    pub fn effective_flags(&self) -> u32 {
        let mut flags = self.flags;
        match self.ctrl_type {
            cid::CTRL_TYPE_INTEGER | cid::CTRL_TYPE_INTEGER64 => flags |= cid::CTRL_FLAG_SLIDER,
            cid::CTRL_TYPE_BUTTON => {
                flags |= cid::CTRL_FLAG_WRITE_ONLY | cid::CTRL_FLAG_EXECUTE_ON_WRITE;
            }
            cid::CTRL_TYPE_CTRL_CLASS => flags |= cid::CTRL_FLAG_READ_ONLY,
            cid::CTRL_TYPE_STRING => flags |= cid::CTRL_FLAG_HAS_PAYLOAD,
            _ => {}
        }
        flags
    }
    /// Does this control hold a 64-bit value? # C: O(1)
    pub fn is_64bit(&self) -> bool { self.ctrl_type == cid::CTRL_TYPE_INTEGER64 }
    /// Is this a compound control, i.e. one whose value is an array rather
    /// than a scalar? The `NEXT_COMPOUND` walk selects on this. # C: O(1)
    pub fn is_compound(&self) -> bool { self.ctrl_type >= cid::CTRL_TYPE_U8 }
}

/// Live state of one control.
#[derive(Copy, Clone, Debug)]
pub struct ControlState {
    pub value: i64,
    /// Runtime flag overlay: `INACTIVE` while another control disables this
    /// one, `GRABBED` while streaming pins it.
    pub runtime_flags: u32,
}

/// A device's controls: their descriptions, kept id-sorted, and their values.
///
/// The list is sorted at construction because every query walks it in id
/// order — `QUERYCTRL` with the next-control flag has to find the smallest id
/// above the one it was given, and an unsorted list makes that answer depend
/// on registration order rather than on the ABI.
pub struct Handler {
    descs: Vec<ControlDesc>,
    state: Spinlock<Vec<ControlState>, TaskList>,
}

impl Handler {
    /// Build a handler over `descs`, sorted by id, with every control at its
    /// declared default. # C: O(n log n)
    pub fn new(descs: &[ControlDesc]) -> Handler {
        let mut descs: Vec<ControlDesc> = descs.to_vec();
        descs.sort_by_key(|d| d.id);
        let state = descs.iter()
            .map(|d| ControlState { value: d.default_value, runtime_flags: 0 })
            .collect();
        Handler { descs, state: Spinlock::new(state) }
    }

    /// Every control, in id order. # C: O(1)
    pub fn descs(&self) -> &[ControlDesc] { &self.descs }

    /// Position of `id` in the sorted list. # C: O(log n)
    pub fn position(&self, id: u32) -> Option<usize> {
        self.descs.binary_search_by_key(&id, |d| d.id).ok()
    }

    /// Description of `id`. # C: O(log n)
    pub fn find(&self, id: u32) -> Option<&ControlDesc> {
        self.position(id).map(|i| &self.descs[i])
    }

    /// Current value of `id`. # C: O(log n)
    pub fn value(&self, id: u32) -> Option<i64> {
        let index = self.position(id)?;
        Some(self.state.lock()[index].value)
    }

    /// Store a value already validated against the control's range. Returns
    /// the previous value, so a caller can tell whether the write changed
    /// anything and skip the change event if it did not.
    /// # C: O(log n)
    pub fn store(&self, id: u32, value: i64) -> Option<i64> {
        let index = self.position(id)?;
        let mut guard = self.state.lock();
        let previous = guard[index].value;
        guard[index].value = value;
        Some(previous)
    }

    /// Flags reported for `id`: the description's, plus the runtime overlay.
    /// # C: O(log n)
    pub fn flags(&self, id: u32) -> Option<u32> {
        let index = self.position(id)?;
        Some(self.descs[index].effective_flags() | self.state.lock()[index].runtime_flags)
    }

    /// Add runtime flags to `id` — `GRABBED` while a stream pins it,
    /// `INACTIVE` while a mode control disables it. # C: O(log n)
    pub fn set_runtime_flags(&self, id: u32, add: u32, remove: u32) {
        if let Some(index) = self.position(id) {
            let mut guard = self.state.lock();
            guard[index].runtime_flags = (guard[index].runtime_flags | add) & !remove;
        }
    }

    /// Apply the same runtime-flag change to every member of `id`'s cluster.
    ///
    /// A cluster exists because its members are not independently meaningful:
    /// an automatic-exposure control that is on makes the manual exposure time
    /// inactive, and an application must see that rather than write a value
    /// the device will ignore.
    /// # C: O(cluster * log n)
    pub fn set_cluster_flags(&self, id: u32, add: u32, remove: u32) {
        let Some(desc) = self.find(id) else { return };
        let cluster = desc.cluster;
        self.set_runtime_flags(id, add, remove);
        for member in cluster { self.set_runtime_flags(*member, add, remove); }
    }

    /// Reset every control to its default. # C: O(n)
    pub fn reset_to_defaults(&self) {
        let mut guard = self.state.lock();
        for (i, desc) in self.descs.iter().enumerate() { guard[i].value = desc.default_value; }
    }
}
