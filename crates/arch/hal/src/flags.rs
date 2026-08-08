// Architecture-neutral leaf protection bits.
//
// One flag set travels through every map, fault, fork and protection rewrite,
// so anything a leaf must not lose across such a rewrite belongs here rather
// than beside it: a protection key, and a userfaultfd monitor's write-protect
// barrier. Each architecture's packer translates the set into its own encoding.

bitflags::bitflags! {
    /// PTE protection bits (per 20§5 / 21§5).
    #[derive(Copy, Clone, Debug, Eq, PartialEq)]
    pub struct PageFlags: u64 {
        const READ      = 1 << 0;
        const WRITE     = 1 << 1;
        const EXEC      = 1 << 2;
        const USER      = 1 << 3;
        const GLOBAL    = 1 << 4;
        const NO_CACHE  = 1 << 5;
        const WRITE_THROUGH = 1 << 6;
        /// Normal memory with write-combining semantics. On x86 this selects
        /// the Linux PAT WC entry; on arm64 it selects MAIR Normal-NC, which
        /// is the architecture's `pgprot_writecombine` mapping.
        const WRITE_COMBINE = 1 << 7;
        /// Protection-key value bits. They travel with a user leaf's normal
        /// permissions so fault, fork, and mprotect rewrites cannot lose the
        /// key while preserving R/W/X.
        const PKEY_BIT0 = 1 << 8;
        const PKEY_BIT1 = 1 << 9;
        const PKEY_BIT2 = 1 << 10;
        const PKEY_BIT3 = 1 << 11;
        /// The page is write-protected on behalf of a userfaultfd monitor.
        ///
        /// It rides WITH the permissions rather than beside them so a leaf can
        /// be BUILT already protected: the one store that publishes the mapping
        /// publishes the barrier with it, leaving no window in which the page is
        /// writable. Packing a leaf with this set therefore also removes write
        /// permission — protection and the mark are one fact, never two.
        const UFFD_WP = 1 << 12;
    }
}

impl PageFlags {
    /// All architecture-neutral protection-key value bits. # C: O(1)
    pub const PKEY_MASK: PageFlags = PageFlags::PKEY_BIT0.union(PageFlags::PKEY_BIT1)
        .union(PageFlags::PKEY_BIT2).union(PageFlags::PKEY_BIT3);

    /// Replace this leaf's protection key without changing any other mapping
    /// permission. # C: O(1)
    pub const fn with_pkey(self, pkey: u8) -> Self {
        let bits = (self.bits() & !Self::PKEY_MASK.bits())
            | (((pkey as u64) << 8) & Self::PKEY_MASK.bits());
        Self::from_bits_retain(bits)
    }

    /// This leaf's protection key. # C: O(1)
    pub const fn pkey(self) -> u8 { ((self.bits() & Self::PKEY_MASK.bits()) >> 8) as u8 }
}
