// The page-table MARKER family: a non-present leaf that names no page and no
// swap slot, carrying instead a set of per-page facts the fault path must act
// on.
//
// One leaf can carry several of them at once, which is why the kinds are BITS
// in one word rather than separate encodings: a page whose contents were
// declared unrecoverable can also be write-protected on behalf of a monitor,
// and an encoding per kind would force one of the two facts to be dropped when
// the other is set.
//
// The word is packed into a leaf by the architecture (`PtWalker`), never here:
// which bit positions are free in a non-present entry is an architectural fact.
// What IS fixed here is the kind numbering, so both architectures agree on
// which bit means what.

/// Per-page facts a marker leaf can carry.
///
/// Empty is not representable: a marker with no kind would be a non-present
/// leaf that means nothing, indistinguishable in intent from an absent one but
/// decoding as "something is here" — which stops a fill and stops a fault from
/// materialising the page, forever.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct PteMarker(u32);

impl PteMarker {
    /// The page is write-protected on behalf of a userfaultfd monitor, and no
    /// page is present to carry that state in its permissions.
    pub const UFFD_WP: Self = Self(1 << 0);
    /// The page's contents are unrecoverable; an access raises a memory error
    /// rather than materialising anything.
    pub const POISON: Self = Self(1 << 1);
    /// Every defined kind bit.
    pub const MASK: u32 = 0b11;

    /// A marker carrying exactly `bits`, or `None` when that is empty or names
    /// a kind this kernel does not define.
    /// # C: O(1)
    pub const fn from_bits(bits: u32) -> Option<Self> {
        if bits == 0 || bits & !Self::MASK != 0 { return None; }
        Some(Self(bits))
    }

    /// # C: O(1)
    pub const fn bits(self) -> u32 { self.0 }

    /// # C: O(1)
    pub const fn contains(self, other: Self) -> bool { self.0 & other.0 == other.0 }

    /// # C: O(1)
    pub const fn with(self, other: Self) -> Self { Self(self.0 | other.0) }

    /// The marker left once `other`'s kinds are gone, or `None` when nothing
    /// remains — in which case the leaf becomes absent rather than staying a
    /// marker that means nothing.
    /// # C: O(1)
    pub const fn without(self, other: Self) -> Option<Self> { Self::from_bits(self.0 & !other.0) }
}
