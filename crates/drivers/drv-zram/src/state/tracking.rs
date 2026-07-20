//! Canonical slot-table projection for `CONFIG_ZRAM_MEMORY_TRACKING`.

use alloc::vec::Vec;

use block::{BlockError, KResult};

use super::{Slot, Zram, PRIMARY_COMPRESSION_PRIORITY};

/// One allocated zram page rendered by the optional Linux debugfs ABI. Each
/// value is copied under the canonical slot-table lock; it is never cached.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZramBlockState {
    pub index: usize,
    pub access_ns: u64,
    pub same: bool,
    pub written_back: bool,
    pub huge: bool,
    pub idle: bool,
    pub recompressed: bool,
    pub incompressible: bool,
}

impl ZramBlockState {
    fn from_slot(index: usize, access_ns: u64, idle: bool, slot: &Slot) -> Option<Self> {
        match slot {
            Slot::Empty => None,
            Slot::Same(_) => Some(Self { index, access_ns, same: true, written_back: false, huge: false, idle, recompressed: false, incompressible: false }),
            Slot::Packed { priority, .. } => Some(Self { index, access_ns, same: false, written_back: false, huge: false, idle, recompressed: *priority != PRIMARY_COMPRESSION_PRIORITY, incompressible: false }),
            Slot::Raw { incompressible, priority, .. } => Some(Self { index, access_ns, same: false, written_back: false, huge: true, idle, recompressed: *priority != PRIMARY_COMPRESSION_PRIORITY, incompressible: *incompressible }),
            Slot::Backed { .. } | Slot::Loading { .. } => Some(Self { index, access_ns, same: false, written_back: true, huge: false, idle, recompressed: false, incompressible: false }),
            Slot::Writeback { data, .. } => {
                let mut state = Self::from_slot(index, access_ns, idle, data)?;
                state.written_back = true;
                Some(state)
            }
        }
    }
}

impl Zram {
    /// Return live records for allocated slots in Linux `block_state` order.
    /// The debugfs frontend owns formatting; this owner copies only canonical
    /// slot state and never maintains a parallel tracker.
    /// # C: O(configured zram pages)
    pub fn block_states(&self) -> KResult<Vec<ZramBlockState>> {
        let state = self.state.lock();
        if state.size == 0 { return Err(BlockError::Einval); }
        let mut records = Vec::new();
        records.try_reserve(state.slots.len()).map_err(|_| BlockError::Enomem)?;
        for index in 0..state.slots.len() {
            let slot = state.slots.get(index).expect("zram slot index validated by table length");
            let access_ns = state.slots.last_access_ns(index).expect("zram slot index validated by table length");
            let idle = state.slots.idle(index).expect("zram slot index validated by table length");
            if let Some(record) = ZramBlockState::from_slot(index, access_ns, idle, slot) { records.push(record); }
        }
        Ok(records)
    }
}
