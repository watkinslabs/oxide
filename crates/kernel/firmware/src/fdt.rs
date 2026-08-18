// The retained flattened device tree.
//
// The firmware hands the boot stub one FDT blob and then stops being
// responsible for it. The boot stub carves those pages out of usable RAM and
// publishes their physical extent in `BootInfo`; this module is where the
// kernel turns that extent into a `'static` slice everything else reads —
// `/sys/firmware/fdt`, `/sys/firmware/devicetree/base`, and any later consumer
// that needs the tree after the boot stub is gone.
//
// One slot, written once on the boot CPU before anything can read it. A blob
// that does not re-validate here is not published at all: half a device tree
// is worse than none, because userspace tools treat its presence as proof the
// platform is device-tree based.

use core::sync::atomic::{AtomicU64, Ordering};

pub mod cpufreq;
pub mod idle;
pub mod providers;
pub mod scmi;

/// Direct-map virtual address of the retained blob; 0 = none retained.
static FDT_VA: AtomicU64 = AtomicU64::new(0);
/// Byte length of the retained blob; 0 = none retained.
static FDT_LEN: AtomicU64 = AtomicU64::new(0);
/// Physical address of the retained blob; 0 = none retained, or a handoff that
/// did not name one. Kept alongside the direct-map address because a consumer
/// deriving a NEW tree from this one has to drop this blob's own reservation,
/// and a reservation is stated in physical addresses.
static FDT_PA: AtomicU64 = AtomicU64::new(0);

/// Publish the boot-retained device tree at direct-map address `va`, length
/// `len`, checksummed `crc` when the boot stub scanned it.
///
/// Nothing is stored unless all three agree: the header parses, `len` matches
/// the blob's own `totalsize` (the boot memmap carve is sized from that same
/// field, so a mismatch means the reservation and the blob describe different
/// things), and the blob still checksums to what the boot stub recorded. The
/// last is the `36§4.1` requirement that retention be VERIFIABLE rather than
/// assumed: a tree that changed between the scan and here is not published at
/// all, because userspace reading a device tree treats it as a description of
/// the machine and has no way to notice that it is stale.
///
/// A `crc` of 0 means the handoff recorded none, and the check is skipped —
/// the two live boot stubs both record one, so this only covers a handoff that
/// predates the field.
///
/// Returns whether a tree is now published.
///
/// # SAFETY: `va` must be a live kernel-readable mapping of at least `len`
/// bytes that stays mapped for the life of the kernel — the boot memmap marks
/// the device tree's pages reserved, which is what makes that true.
/// # C: O(1)
pub unsafe fn retain(va: u64, pa: u64, len: u64, crc: u32) -> bool {
    if va == 0 || len < ::fdt::FDT_HEADER_LEN as u64 || len > ::fdt::FDT_MAX_TOTALSIZE as u64 {
        return false;
    }
    // SAFETY: caller guarantees `va` maps `len` readable bytes for 'static.
    let blob: &'static [u8] = unsafe { core::slice::from_raw_parts(va as *const u8, len as usize) };
    let Ok(h) = ::fdt::parse_header(blob) else { return false };
    if h.totalsize as u64 != len { return false; }
    if crc != 0 && ::crc::crc32_be_update(!0u32, blob) != crc { return false; }
    FDT_LEN.store(len, Ordering::Release);
    FDT_PA.store(pa, Ordering::Release);
    FDT_VA.store(va, Ordering::Release);
    true
}

/// The retained device tree, or `None` on a platform that has none. The slice
/// is exactly `totalsize` bytes — the same length `/sys/firmware/fdt` reports,
/// so a reader that trusts the file size reads the whole blob and no more.
/// # C: O(1)
pub fn blob() -> Option<&'static [u8]> {
    let va = FDT_VA.load(Ordering::Acquire);
    let len = FDT_LEN.load(Ordering::Acquire);
    if va == 0 || len == 0 { return None; }
    // SAFETY: `retain` only stores a `va`/`len` pair it has validated against a
    // mapping the boot memmap keeps reserved for the life of the kernel.
    Some(unsafe { core::slice::from_raw_parts(va as *const u8, len as usize) })
}

/// Device-tree CPU nodes, including their complete MPIDR affinity and whether
/// firmware marked each node available. # C: O(struct_block_size)
pub fn cpu_nodes(out: &mut [::fdt::CpuNode]) -> usize {
    blob().map(|tree| ::fdt::cpu_nodes(tree, out)).unwrap_or(0)
}

/// Publish every retained device-tree CPU into the shared topology before any
/// policy or SMP consumer resolves a logical CPU. # C: O(struct_block_size)
pub fn populate_cpu_topology() -> usize {
    let mut nodes = [::fdt::CpuNode { mpidr: 0, enabled: false }; cpu::MAX_CPUS];
    let count = cpu_nodes(&mut nodes).min(nodes.len());
    let mut added = 0usize;
    for node in &nodes[..count] {
        let flags = if node.enabled { cpu::FLAG_ENABLED } else { 0 };
        // SAFETY: called only from the boot CPU before AP startup.
        if unsafe { cpu::add_cpu(node.mpidr, flags, u32::MAX) } { added += 1; }
    }
    added
}

/// Physical extent of the retained tree as `(pa, len)`, or `None` when none
/// was retained or the handoff named no physical address.
///
/// A tree derived from this one must drop the reservation covering THIS blob:
/// the new kernel is handed a different blob at a different address, so
/// carrying it forward reserves memory nothing occupies.
/// # C: O(1)
pub fn phys_extent() -> Option<(u64, u64)> {
    let pa = FDT_PA.load(Ordering::Acquire);
    let len = FDT_LEN.load(Ordering::Acquire);
    if pa == 0 || len == 0 || FDT_VA.load(Ordering::Acquire) == 0 { return None; }
    Some((pa, len))
}

/// Whether a device tree was retained. # C: O(1)
pub fn present() -> bool { FDT_VA.load(Ordering::Acquire) != 0 }

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::vec::Vec;

    /// Smallest legal blob: a header, a struct block holding an empty root
    /// node, and no strings.
    fn minimal_fdt() -> Vec<u8> {
        let mut st: Vec<u8> = Vec::new();
        st.extend_from_slice(&1u32.to_be_bytes()); // FDT_BEGIN_NODE
        st.extend_from_slice(&[0, 0, 0, 0]);       // "" name, padded
        st.extend_from_slice(&2u32.to_be_bytes()); // FDT_END_NODE
        st.extend_from_slice(&9u32.to_be_bytes()); // FDT_END
        let off_rsvmap = ::fdt::FDT_HEADER_LEN as u32;
        let off_struct = off_rsvmap + 16;
        let total = off_struct + st.len() as u32;
        let mut v = alloc::vec![0u8; ::fdt::FDT_HEADER_LEN + 16];
        v[0..4].copy_from_slice(&::fdt::FDT_MAGIC.to_be_bytes());
        v[4..8].copy_from_slice(&total.to_be_bytes());
        v[8..12].copy_from_slice(&off_struct.to_be_bytes());
        v[12..16].copy_from_slice(&total.to_be_bytes()); // empty strings block
        v[16..20].copy_from_slice(&off_rsvmap.to_be_bytes());
        v[20..24].copy_from_slice(&17u32.to_be_bytes());
        v[24..28].copy_from_slice(&::fdt::FDT_LAST_COMPAT_VERSION.to_be_bytes());
        v[36..40].copy_from_slice(&(st.len() as u32).to_be_bytes());
        v.extend_from_slice(&st);
        v
    }

    /// One test, because the slot is process-global: nothing published before,
    /// bad extents rejected, a real blob published exactly, and a later bad
    /// retain unable to disturb what is already published.
    #[test]
    fn retain_publishes_only_a_blob_it_can_validate() {
        /// Physical address the handoff named for the blob under test.
        const PA: u64 = 0x4000_0000;

        assert!(blob().is_none() && !present(), "nothing published before retain");
        assert_eq!(phys_extent(), None, "…and no physical extent either");

        // SAFETY: each of these is rejected on its arguments before any slice
        // is formed, so no invalid address is ever dereferenced.
        unsafe {
            assert!(!retain(0, 0x1000, 4096, 0), "null va");
            assert!(!retain(0x1000, 0x1000, 0, 0), "zero length");
            assert!(!retain(0x1000, 0x1000, 8, 0), "shorter than a header");
            assert!(!retain(0x1000, 0x1000, ::fdt::FDT_MAX_TOTALSIZE as u64 + 1, 0), "past the ceiling");
        }
        assert!(blob().is_none(), "a rejected retain publishes nothing");

        // Padded so an over-long extent is still readable memory: the point is
        // that `retain` refuses it on the blob's own `totalsize`, not that it
        // faults. A reservation longer than the blob would publish trailing
        // bytes as part of the device tree.
        let one = minimal_fdt();
        let exact = one.len() as u64;
        let mut padded = one;
        padded.resize(padded.len() + 64, 0);
        let leaked: &'static [u8] = Box::leak(padded.into_boxed_slice());
        let va = leaked.as_ptr() as u64;
        // SAFETY: `leaked` maps `leaked.len()` readable bytes for 'static.
        assert!(!unsafe { retain(va, PA, leaked.len() as u64, 0) }, "longer than totalsize");
        assert!(blob().is_none());
        // SAFETY: `leaked` is a live 'static allocation; `exact` is shorter.
        assert!(!unsafe { retain(va, PA, exact - 4, 0) }, "shorter than totalsize");
        assert!(blob().is_none());

        // A blob that no longer checksums to what the boot stub scanned is not
        // published, however well it parses (`36§4.1`).
        let good = ::crc::crc32_be_update(!0u32, &leaked[..exact as usize]);
        // SAFETY: `leaked` covers `exact` readable 'static bytes.
        assert!(!unsafe { retain(va, PA, exact, good ^ 1) }, "checksum disagrees with the scan");
        assert!(blob().is_none());

        // SAFETY: `leaked` is a live 'static allocation covering `exact` bytes.
        assert!(unsafe { retain(va, PA, exact, good) });
        assert!(present());
        assert_eq!(phys_extent(), Some((PA, exact)),
                   "the physical extent a derived tree must un-reserve");
        assert_eq!(blob(), Some(&leaked[..exact as usize]), "the published slice is the blob, whole and exact");

        // SAFETY: rejected on its arguments; no dereference.
        assert!(!unsafe { retain(0, 0, 0, 0) });
        assert_eq!(blob(), Some(&leaked[..exact as usize]), "a failed retain leaves the published tree alone");
    }
}
