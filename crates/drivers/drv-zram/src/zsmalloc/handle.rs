//! Stable opaque object handles and their registry headers.

/// Opaque stable zsmalloc object identity. Physical movement changes only its registry header.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct Handle {
    pub(super) index: usize,
    generation: u64,
    length: usize,
}

impl Handle {
    /// Logical bytes are immutable for a live zsmalloc object, independent of relocation.
    /// # C: O(1)
    pub(crate) const fn len(self) -> usize { self.length }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct ObjectLocation {
    pub(super) zspage: usize,
    pub(super) slot: usize,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(super) struct ObjectHeader {
    pub(super) location: ObjectLocation,
    pub(super) length: usize,
    pub(super) class_bytes: usize,
}

pub(super) struct RegistryEntry {
    pub(super) generation: u64,
    pub(super) header: Option<ObjectHeader>,
}

impl RegistryEntry {
    pub(super) const fn vacant() -> Self { Self { generation: 0, header: None } }

    pub(super) fn handle(&self, index: usize, length: usize) -> Handle { Handle { index, generation: self.generation, length } }

    pub(super) fn matches(&self, handle: Handle) -> bool { self.generation == handle.generation && self.header.is_some_and(|header| header.length == handle.length) }
}
