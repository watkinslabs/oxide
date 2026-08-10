// Making a retained EFI memory map honest about what this boot installed.
//
// Ungated on purpose. Every decision here is pure — a stride, an offset and a
// bit — and it is decided ONCE for a map that the next kernel walks blind:
// there is nothing downstream that can notice a wrong answer, so the answer
// has to be checkable without a machine.

/// Offset of `VirtualStart` in an EFI memory descriptor.
const OFF_VIRT_ADDR: usize = 16;
/// Offset of `Attribute` in an EFI memory descriptor.
const OFF_ATTRIBUTE: usize = 32;
/// Smallest descriptor this can decode: through `Attribute`.
pub const MIN_DESC_SIZE: usize = OFF_ATTRIBUTE + 8;
/// `EFI_MEMORY_RUNTIME` — the region must be mapped for runtime services.
pub const EFI_MEMORY_RUNTIME: u64 = 0x8000_0000_0000_0000;

/// The value a `VirtualStart` carries when NO virtual translation was
/// installed for it.
///
/// A reader treats it as the signal to give up on runtime services rather than
/// as an address, which is the only safe reading: a descriptor left at
/// whatever the firmware happened to have there names a virtual address
/// nothing chose, and a kernel that believes it builds page tables for it.
pub const NO_VIRT_MAPPING: u64 = u64::MAX;

/// Stamp every runtime region in `map` as having no virtual translation.
///
/// THE BOOT THAT DOES NOT INSTALL ONE MUST SAY SO. `VirtualStart` is defined
/// by the firmware interface only after a virtual map has been installed;
/// before that it holds whatever the firmware left, and a later kernel handed
/// the map has no way to tell the difference between a real address and a
/// leftover. Measured: a relocated kernel took a leftover for an address and
/// died building page tables for it, having otherwise brought the whole
/// machine up.
///
/// Descriptors shorter than [`MIN_DESC_SIZE`], or a stride that does not
/// divide the map into whole descriptors, leave the map untouched — editing a
/// layout this cannot decode would write the field of some other descriptor.
/// # C: O(map_len / desc_size)
pub fn mark_no_virtual_mapping(map: &mut [u8], desc_size: usize) {
    if desc_size < MIN_DESC_SIZE { return; }
    let mut off = 0usize;
    while off + desc_size <= map.len() {
        let d = &mut map[off..off + desc_size];
        let attr = u64::from_le_bytes(
            d[OFF_ATTRIBUTE..OFF_ATTRIBUTE + 8].try_into().unwrap_or([0; 8]));
        if attr & EFI_MEMORY_RUNTIME != 0 {
            d[OFF_VIRT_ADDR..OFF_VIRT_ADDR + 8]
                .copy_from_slice(&NO_VIRT_MAPPING.to_le_bytes());
        }
        off += desc_size;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    /// Descriptors as the firmware writes them, at a stride WIDER than the
    /// fields — which is what real firmware reports, and what a walker using
    /// `size_of` instead of the reported stride would get wrong.
    const STRIDE: usize = 48;

    fn desc(ty: u32, phys: u64, virt: u64, pages: u64, attr: u64) -> Vec<u8> {
        let mut d = alloc::vec![0u8; STRIDE];
        d[0..4].copy_from_slice(&ty.to_le_bytes());
        d[8..16].copy_from_slice(&phys.to_le_bytes());
        d[OFF_VIRT_ADDR..OFF_VIRT_ADDR + 8].copy_from_slice(&virt.to_le_bytes());
        d[24..32].copy_from_slice(&pages.to_le_bytes());
        d[OFF_ATTRIBUTE..OFF_ATTRIBUTE + 8].copy_from_slice(&attr.to_le_bytes());
        d
    }

    fn virt_of(map: &[u8], i: usize) -> u64 {
        let o = i * STRIDE + OFF_VIRT_ADDR;
        u64::from_le_bytes(map[o..o + 8].try_into().unwrap())
    }
    fn phys_of(map: &[u8], i: usize) -> u64 {
        let o = i * STRIDE + 8;
        u64::from_le_bytes(map[o..o + 8].try_into().unwrap())
    }

    /// A leftover in a runtime region becomes the no-mapping signal; a
    /// non-runtime region is not touched, because nothing will map it and
    /// rewriting it would be a change with no reader.
    #[test]
    fn every_runtime_region_is_stamped_and_nothing_else_is() {
        let mut m: Vec<u8> = Vec::new();
        // Runtime, carrying a leftover that looks exactly like an address.
        m.extend(desc(5, 0xbee9_0000, 0xffff_ffff_fe43_2000, 4, EFI_MEMORY_RUNTIME | 0xf));
        // Ordinary RAM, virt left at zero.
        m.extend(desc(7, 0x4000_0000, 0, 0x1000, 0xf));
        // Runtime again, further down the map: a walker that stopped at the
        // first non-runtime entry would leave this one lying.
        m.extend(desc(6, 0xbef0_0000, 0x1234_5678, 2, EFI_MEMORY_RUNTIME));
        mark_no_virtual_mapping(&mut m, STRIDE);
        assert_eq!(virt_of(&m, 0), NO_VIRT_MAPPING);
        assert_eq!(virt_of(&m, 1), 0, "not a runtime region, not stamped");
        assert_eq!(virt_of(&m, 2), NO_VIRT_MAPPING);
        // …and nothing else moved: the physical addresses are the map.
        assert_eq!(phys_of(&m, 0), 0xbee9_0000);
        assert_eq!(phys_of(&m, 1), 0x4000_0000);
        assert_eq!(phys_of(&m, 2), 0xbef0_0000);
    }

    /// A stride this cannot decode leaves the map exactly as it was. Writing
    /// at a guessed offset would land in the middle of some other
    /// descriptor's fields — a corrupted memory map that still parses.
    #[test]
    fn an_undecodable_stride_changes_nothing() {
        let one = desc(5, 0xbee9_0000, 7, 4, EFI_MEMORY_RUNTIME);
        for stride in [0usize, 1, MIN_DESC_SIZE - 1] {
            let mut m = one.clone();
            mark_no_virtual_mapping(&mut m, stride);
            assert_eq!(m, one, "stride {stride}");
        }
        // A trailing partial descriptor is left alone rather than half-written.
        let mut m = one.clone();
        m.truncate(STRIDE - 1);
        let before = m.clone();
        mark_no_virtual_mapping(&mut m, STRIDE);
        assert_eq!(m, before);
    }
}
