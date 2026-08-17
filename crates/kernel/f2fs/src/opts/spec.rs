//! Which options the mount line actually NAMED.
//!
//! An option set alone cannot answer this. `discard=false` reads the same
//! whether the line said `nodiscard` or said nothing, and the consistency pass
//! turns on exactly that difference: `nodiscard` on a volume whose zones make
//! discard mandatory is a refusal, while a line that never mentioned discard on
//! the same volume is an ordinary mount that gets the feature-derived default.
//! Collapsing the two either refuses mounts that asked for nothing wrong, or
//! silently grants a mount the opposite of what it asked for.
//!
//! Only the keys a consistency or remount decision reads are tracked. A bit
//! nobody consults would be a field that can drift from the parser without
//! anything going red.

/// One bit per option whose "was it named" state a later decision reads.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct Spec {
    pub discard: bool,
    pub discard_unit: bool,
    pub extent_cache: bool,
    pub age_extent_cache: bool,
    pub reserve_root: bool,
    pub reserve_node: bool,
    pub mode: bool,
    pub inline_xattr: bool,
    pub inline_xattr_size: bool,
    pub background_gc: bool,
    pub atgc: bool,
    pub flush_merge: bool,
    pub recovery: bool,
    pub nat_bits: bool,
    pub checkpoint: bool,
    pub dummy_policy: bool,
    /// One bit per quota kind, in `QKind` order: whether the line spelled that
    /// kind's `*jquota=` at all, including the bare spelling that clears it.
    pub qname: [bool; super::jquota::QKINDS],
    pub jqfmt: bool,
}

impl Spec {
    /// Nothing named. # C: O(1)
    pub fn none() -> Self { Self::default() }

    /// Whether any kind's quota file name was spelled. # C: O(1)
    pub fn any_qname(&self) -> bool { self.qname.iter().any(|n| *n) }
}
