// What one security module tells the framework about itself.

use crate::blob::BlobRequest;

/// Identity of one security module.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LsmId {
    /// Name the boot line and userspace select the module by.
    pub name: &'static str,
    /// Identity number userspace receives.
    pub id: u64,
}

/// Where a module sits relative to the others.
///
/// Only two positions are fixed. The capability module runs first, because
/// every other module refines a decision it has already taken. Integrity
/// modules run last, because a measurement records what the other modules
/// decided rather than deciding anything itself. Everything between is
/// ordered by the boot list, which is why it is called mutable.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum Order {
    First,
    Mutable,
    Last,
}

/// The module answers to the legacy single-module boot selector.
pub const LSM_FLAG_LEGACY_MAJOR: u32 = 1 << 0;
/// At most one module carrying this flag may run.
pub const LSM_FLAG_EXCLUSIVE: u32 = 1 << 1;

/// One module's registration record.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct LsmInfo {
    pub id: LsmId,
    pub order: Order,
    pub flags: u32,
    /// Per-object state the module wants a slot for.
    pub blobs: BlobRequest,
    /// The module's own enable state before ordering runs.
    ///
    /// `None` means the module publishes no enable control, so nothing can
    /// have disabled it yet. `Some(false)` means the module read its own boot
    /// parameter and turned itself off; ordering must then leave it off even
    /// when the boot list names it, which is what makes `selinux=0` beat a
    /// list that still contains `selinux`.
    pub enabled: Option<bool>,
}

impl LsmInfo {
    /// A module with no ordering constraint, no flags and no blob. # C: O(1)
    pub const fn new(name: &'static str, id: u64) -> Self {
        Self {
            id: LsmId { name, id },
            order: Order::Mutable,
            flags: 0,
            blobs: BlobRequest::NONE,
            enabled: None,
        }
    }

    pub const fn order(mut self, order: Order) -> Self { self.order = order; self }
    pub const fn flags(mut self, flags: u32) -> Self { self.flags = flags; self }
    pub const fn blobs(mut self, blobs: BlobRequest) -> Self { self.blobs = blobs; self }
    pub const fn enabled(mut self, enabled: bool) -> Self { self.enabled = Some(enabled); self }

    /// Whether the module carries the legacy single-module flag. # C: O(1)
    pub const fn is_legacy_major(&self) -> bool { self.flags & LSM_FLAG_LEGACY_MAJOR != 0 }

    /// Whether at most one module like this may run. # C: O(1)
    pub const fn is_exclusive(&self) -> bool { self.flags & LSM_FLAG_EXCLUSIVE != 0 }

    /// Whether something has already turned the module off. # C: O(1)
    ///
    /// A module publishing no enable control has not been disabled; only an
    /// explicit `Some(false)` counts. Treating the absent control as disabled
    /// would silently drop every module that has no boot parameter.
    pub const fn explicitly_disabled(&self) -> bool { matches!(self.enabled, Some(false)) }
}

#[cfg(test)]
#[path = "tests/module.rs"]
mod tests;
