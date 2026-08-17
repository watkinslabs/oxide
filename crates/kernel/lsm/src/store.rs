// Per-object module state, one slot per module.
//
// Replaces the pattern where an object carries a single security field that
// whichever module got there last owns. With one field, the second module to
// attach state destroys the first module's and then reads its own answer back
// as that module's — so a module's own state can report an access its policy
// refuses. Each module writes only the slot the framework granted it.

use alloc::boxed::Box;
use alloc::sync::Arc;
use core::any::Any;

/// State one module hangs off one object.
pub type Blob = Arc<dyn Any + Send + Sync>;

/// The slots of one object.
///
/// Costs one pointer while no module has attached anything, which is the
/// common case for an object created before any module is interested in it.
#[derive(Clone, Default)]
pub struct BlobStore {
    slots: Option<Box<[Option<Blob>]>>,
}

impl BlobStore {
    /// An object no module has attached state to. # C: O(1)
    pub const fn empty() -> Self { Self { slots: None } }

    /// Whether any module holds state here. # C: O(1)
    pub fn is_empty(&self) -> bool {
        self.slots.as_ref().is_none_or(|s| s.iter().all(|v| v.is_none()))
    }

    /// How many slots this object carries. # C: O(1)
    pub fn capacity(&self) -> usize { self.slots.as_ref().map_or(0, |s| s.len()) }

    /// Write one module's state into the slot the framework granted it.
    /// # C: O(slots) on first write, O(1) after
    ///
    /// `total` is the slot count the framework allocated for this object
    /// kind. A write past it is dropped rather than widened: growing here
    /// would let a module invent a slot the framework never granted, and the
    /// module reading that slot would be reading nobody's state.
    pub fn set(&mut self, slot: u16, total: usize, value: Option<Blob>) -> bool {
        let slot = slot as usize;
        if slot >= total { return false; }
        let slots = self.slots.get_or_insert_with(|| {
            let mut v = alloc::vec::Vec::with_capacity(total);
            v.resize_with(total, || None);
            v.into_boxed_slice()
        });
        if slot >= slots.len() { return false; }
        slots[slot] = value;
        true
    }

    /// Read one module's state back, typed. # C: O(1)
    ///
    /// The slot and the type must both match: a module reading its own slot
    /// with the wrong type gets nothing rather than another module's value.
    pub fn get<T: Any + Send + Sync>(&self, slot: u16) -> Option<Arc<T>> {
        let slots = self.slots.as_ref()?;
        slots.get(slot as usize)?.clone()?.downcast::<T>().ok()
    }

    /// Whether a slot holds anything, without caring what type. # C: O(1)
    pub fn occupied(&self, slot: u16) -> bool {
        self.slots.as_ref().and_then(|s| s.get(slot as usize)).is_some_and(|v| v.is_some())
    }
}

impl core::fmt::Debug for BlobStore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlobStore").field("capacity", &self.capacity()).finish()
    }
}

#[cfg(test)]
#[path = "tests/store.rs"]
mod tests;
