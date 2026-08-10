// What the trampoline runs under, decided BEFORE the point of no return.
//
// Everything here is ungated on purpose. The jump itself cannot be tested —
// it does not return — so every decision it depends on is made in a module a
// hosted test can compile: which physical ranges the identity map has to
// cover, how many pages that costs, and the control-register state the entry
// contract fixes. The trampoline then only executes what was already decided.
//
// The identity tables are built at LOAD time, and that ordering is the whole
// reason this file exists at load time too: a table that cannot be built must
// surface as an errno from `kexec_load(2)`, not as a machine that stopped
// halfway through relocating.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::{KexecSegment, PAGE_SIZE};

/// Leaf level of the identity map: a 2 MiB block (L2 on both walkers).
///
/// 1 GiB leaves would ride on a CPU feature that has to be tested for
/// separately, and a table that needs no feature test cannot be built wrong on
/// a machine that lacks it.
pub const BLOCK_LEVEL: u8 = 2;
/// Bytes one identity-map leaf spans.
pub const BLOCK_SIZE: u64 = 2 * 1024 * 1024;
/// Bytes one L1 (1 GiB) table entry spans — the granularity at which a fresh
/// L2 table is needed.
pub const L1_SPAN: u64 = 1024 * 1024 * 1024;
/// Bytes one L0 (512 GiB) entry spans — the granularity at which a fresh L1
/// table is needed.
pub const L0_SPAN: u64 = 512 * L1_SPAN;

/// Intermediate tables the transition mapping needs on top of the identity
/// map's: its virtual address is in the other half of the space, so it shares
/// only the root and brings its own L1, L2 and L3.
pub const TRANSITION_TABLE_PAGES: u64 = 3;

// --- range plan ----------------------------------------------------------

/// Physical ranges the identity map must cover, block-aligned, sorted and
/// merged. THREE sources, and dropping any one of them faults the trampoline
/// or the image at a point where nothing is left able to report it:
///
/// - every usable RAM range, because the relocation reads its source pages
///   out of exactly that memory;
/// - every segment's destination range, because a destination is not required
///   to lie inside RAM the running kernel manages — an image loaded below the
///   running kernel's usable window is the ordinary case on a machine whose
///   firmware claims the bottom of memory, and a map built from RAM alone
///   faults on the first copy into such a segment;
/// - every firmware-owned range, because the description tables a replacement
///   kernel reads before it has built any mapping of its own live there, and
///   they are outside usable RAM by construction.
/// # C: O(N log N) over ranges
pub fn ranges_for(
    ram: &[(u64, u64)], segs: &[KexecSegment], firmware: &[(u64, u64)],
) -> Vec<(u64, u64)> {
    let mut raw: Vec<(u64, u64)> = Vec::new();
    for &(s, e) in ram { raw.push((s, e)); }
    for s in segs {
        if s.memsz == 0 { continue; }
        raw.push((s.mem, s.mem.saturating_add(s.memsz)));
    }
    for &(s, e) in firmware { raw.push((s, e)); }
    normalize(&raw)
}

/// Block-align, sort and merge. Adjacent ranges merge too: two ranges that
/// meet exactly would otherwise each claim the block they share, and the
/// second claim is what turns a build into a spurious "already mapped".
/// # C: O(N log N)
pub fn normalize(raw: &[(u64, u64)]) -> Vec<(u64, u64)> {
    let mut v: Vec<(u64, u64)> = Vec::new();
    for &(s, e) in raw {
        if e <= s { continue; }
        let s = s & !(BLOCK_SIZE - 1);
        let e = e.saturating_add(BLOCK_SIZE - 1) & !(BLOCK_SIZE - 1);
        v.push((s, e));
    }
    v.sort_unstable();
    let mut out: Vec<(u64, u64)> = Vec::new();
    for (s, e) in v {
        match out.last_mut() {
            Some(last) if s <= last.1 => { if e > last.1 { last.1 = e; } }
            _ => out.push((s, e)),
        }
    }
    out
}

/// Highest address the plan maps, exclusive. Zero when nothing is mapped.
/// # C: O(1)
pub fn max_address(ranges: &[(u64, u64)]) -> u64 { ranges.last().map_or(0, |r| r.1) }

/// Leaves the identity map installs.
/// # C: O(N ranges)
pub fn block_count(ranges: &[(u64, u64)]) -> u64 {
    ranges.iter().map(|&(s, e)| (e - s) / BLOCK_SIZE).sum()
}

/// Pages of intermediate table the identity map costs: the root, one L1 per
/// distinct 512 GiB span touched, one L2 per distinct 1 GiB span touched.
///
/// Counted exactly rather than bounded, because every one of these comes from
/// `alloc_control_page` — a supply that is deliberately constrained to pages
/// no relocation can overwrite, and an over-estimate parks pages there that
/// the image then holds for its whole life.
/// # C: O(total blocks)
pub fn table_pages(ranges: &[(u64, u64)]) -> u64 {
    let mut l0: Vec<u64> = Vec::new();
    let mut l1: Vec<u64> = Vec::new();
    for &(s, e) in ranges {
        let mut a = s;
        while a < e {
            let i0 = a / L0_SPAN;
            let i1 = a / L1_SPAN;
            if !l0.contains(&i0) { l0.push(i0); }
            if !l1.contains(&i1) { l1.push(i1); }
            a += BLOCK_SIZE;
        }
    }
    1 + l0.len() as u64 + l1.len() as u64
}

/// Every control page `prepare` must have in hand before it writes the first
/// table entry: the identity map's, plus the transition mapping's.
/// # C: O(total blocks)
pub fn control_pages_needed(ranges: &[(u64, u64)]) -> u64 {
    table_pages(ranges) + TRANSITION_TABLE_PAGES
}

// --- relocation-entry bit positions --------------------------------------

// One architecture tests the relocation tags as MASKS (`test cl, imm8`) and the
// other as BIT POSITIONS (`tbz xN, #bit`). Both must name the same bits, so the
// positions are derived from the masks rather than written down a second time:
// a literal `#3` beside `IND_SOURCE = 1 << 3` is two sources of truth for one
// fact, and only one of them moves when the encoding does.

/// Bit position of [`crate::uapi::IND_DESTINATION`].
pub const IND_DESTINATION_BIT: u32 = crate::uapi::IND_DESTINATION.trailing_zeros();
/// Bit position of [`crate::uapi::IND_INDIRECTION`].
pub const IND_INDIRECTION_BIT: u32 = crate::uapi::IND_INDIRECTION.trailing_zeros();
/// Bit position of [`crate::uapi::IND_DONE`].
pub const IND_DONE_BIT: u32 = crate::uapi::IND_DONE.trailing_zeros();
/// Bit position of [`crate::uapi::IND_SOURCE`].
pub const IND_SOURCE_BIT: u32 = crate::uapi::IND_SOURCE.trailing_zeros();

// --- x86_64 entry state --------------------------------------------------

/// `CR4.PGE`. Cleared before the identity tables take effect: a global TLB
/// entry from the old map survives a `mov cr3` and would let the trampoline
/// read a translation the new tables do not describe.
pub const CR4_PGE: u64 = 1 << 7;

/// The only `CR4` bits the trampoline keeps: `PAE` (bit 5), without which
/// long mode cannot page at all, and `LA57` (bit 12), because dropping to
/// four-level paging mid-flight would reinterpret every address in the tables
/// it is running on.
///
/// Everything else goes, which is what clears `CET` before `CR0.WP` is
/// cleared — two steps, in that order, for that reason.
pub const CR4_KEEP: u64 = (1 << 5) | (1 << 12);

/// `CR0` bits the trampoline clears: `AM` (18), `WP` (16), `TS` (3), `EM` (2).
pub const CR0_CLEAR: u64 = (1 << 18) | (1 << 16) | (1 << 3) | (1 << 2);
/// `CR0` bits it sets: `PG` (31) and `PE` (0).
pub const CR0_SET: u64 = (1 << 31) | 1;

// --- x86_64 descriptor table left at entry -------------------------------
//
// The trampoline invalidates the running kernel's descriptor table on its way
// out, because that table lives in memory the relocation is about to
// overwrite. It cannot simply leave nothing behind: an image whose first act
// is to reload a segment register — a purgatory, a second-stage loader, any
// code that does not build its own table first — would take a fault with no
// table to describe the handler. So a flat table of its own travels inside the
// trampoline blob and is installed once the identity map is live.

/// Null descriptor. Selector 0 is not a usable segment on this architecture.
pub const GDT_ENTRY_NULL: u64 = 0;
/// Flat 32-bit code: base 0, limit 4 GiB, present, ring 0, execute/read.
pub const GDT_ENTRY_CODE32: u64 = 0x00cf_9a00_0000_ffff;
/// Flat 64-bit code: as above with the long-mode bit set and the default
/// operand-size bit clear, which is the only legal combination in long mode.
pub const GDT_ENTRY_CODE64: u64 = 0x00af_9a00_0000_ffff;
/// Flat data: base 0, limit 4 GiB, present, ring 0, read/write.
pub const GDT_ENTRY_DATA: u64 = 0x00cf_9200_0000_ffff;
/// Entries in that table, the null descriptor included.
pub const GDT_ENTRIES: u64 = 4;
/// Limit field of the pseudo-descriptor: the table's size in bytes, less one.
pub const GDT_LIMIT: u64 = GDT_ENTRIES * 8 - 1;

// --- aarch64 entry state -------------------------------------------------

/// `SCTLR_EL1` with the MMU, caches and stack alignment checking off, and
/// every RES1 field of the current architecture still set: `LSMAOE` (29),
/// `nTLSMD` (28), `EIS` (22), `TSCXT` (20), `EOS` (11).
///
/// Writing a bare zero here instead would clear fields the architecture
/// requires to read as one, which is a different machine state from "MMU
/// off" and not one the next kernel's entry contract describes.
pub const SCTLR_EL1_MMU_OFF: u64 =
    (1 << 29) | (1 << 28) | (1 << 22) | (1 << 20) | (1 << 11);

/// Bytes the arm64 boot contract requires every relocated page to be visible
/// at with the caches off — the point of coherency. The trampoline cleans
/// each destination page to it before the branch (`docs/36 §4`).
pub const ARM_CLEAN_TO_POC: bool = true;

// --- aarch64 translation control -----------------------------------------
//
// The identity map goes into the low-address translation regime, whose reach
// is set by a size field in the live translation-control register. Deriving
// the reach from that register — rather than assuming the value this kernel
// happens to boot with — is what makes the refusal below honest: a kernel
// configured for a smaller address space would otherwise have an identity map
// built for an address space its hardware does not walk, and no check would
// notice. The size field is also PROGRAMMED for the image rather than
// inherited, so the map that is installed is the map that was planned.

/// `T0SZ` field of the translation-control register — bits 5:0. The regime
/// describes `64 - T0SZ` address bits.
pub const TCR_T0SZ_MASK: u64 = 0x3f;
/// Shift of the intermediate-physical-address-size field, bits 34:32.
pub const TCR_IPS_SHIFT: u32 = 32;
/// Width of that field.
pub const TCR_IPS_MASK: u64 = 0x7;

/// Address bits an intermediate-physical-address-size encoding permits.
/// # C: O(1)
pub fn ips_bits(ips: u64) -> u32 {
    match ips & TCR_IPS_MASK { 0 => 32, 1 => 36, 2 => 40, 3 => 42, 4 => 44, 5 => 48, 6 => 52, _ => 56 }
}

/// Address bits the identity map's table format describes: four levels of
/// 4 KiB tables, nine index bits each, over a twelve-bit page offset.
pub const ARM_IDMAP_VA_BITS: u32 = 4 * 9 + 12;

/// `T0SZ` the identity map is installed under.
/// # C: O(1)
pub const ARM_IDMAP_T0SZ: u64 = 64 - ARM_IDMAP_VA_BITS as u64;

/// Highest physical address, exclusive, that can be both produced by this
/// translation regime and described by the identity map's table format.
///
/// The smaller of the two limits, because either one alone is a map that
/// cannot be walked: a plan past the output-size field produces addresses the
/// hardware truncates, and a plan past the table format's reach has no index
/// bits left to name it.
/// # C: O(1)
pub fn arm_idmap_limit(tcr: u64) -> u64 {
    let out = ips_bits(tcr >> TCR_IPS_SHIFT);
    let bits = if out < ARM_IDMAP_VA_BITS { out } else { ARM_IDMAP_VA_BITS };
    1u64 << bits
}

/// The translation-control value the identity map is installed under: the
/// live one with the size field replaced by the map's own.
/// # C: O(1)
pub fn tcr_with_idmap_t0sz(tcr: u64) -> u64 { (tcr & !TCR_T0SZ_MASK) | ARM_IDMAP_T0SZ }

/// Pages a byte range spans at the identity map's leaf size.
/// # C: O(1)
pub fn blocks_in(start: u64, end: u64) -> u64 {
    if end <= start { 0 } else { (end - start).div_ceil(BLOCK_SIZE) }
}

/// Bytes of trampoline that fit in one control page, leaving the tail for the
/// stack the trampoline runs on: one page serves as both.
/// # C: O(1)
pub const fn max_trampoline_bytes() -> u64 { PAGE_SIZE - 256 }

#[cfg(test)]
mod tests {
    use super::*;

    fn seg(mem: u64, memsz: u64) -> KexecSegment {
        KexecSegment { buf: 0, bufsz: 0, mem, memsz }
    }

    #[test]
    fn normalize_aligns_outward_to_whole_blocks() {
        // A range starting one page in must still be reachable: the block that
        // contains it is what the map installs, so the start rounds DOWN.
        let v = normalize(&[(BLOCK_SIZE + PAGE_SIZE, BLOCK_SIZE + 3 * PAGE_SIZE)]);
        assert_eq!(v, [(BLOCK_SIZE, 2 * BLOCK_SIZE)]);
    }

    #[test]
    fn normalize_merges_overlapping_and_adjacent() {
        let v = normalize(&[(0, BLOCK_SIZE), (BLOCK_SIZE, 2 * BLOCK_SIZE),
                            (4 * BLOCK_SIZE, 5 * BLOCK_SIZE)]);
        assert_eq!(v, [(0, 2 * BLOCK_SIZE), (4 * BLOCK_SIZE, 5 * BLOCK_SIZE)]);
    }

    #[test]
    fn normalize_drops_empty_ranges() {
        assert!(normalize(&[(BLOCK_SIZE, BLOCK_SIZE), (8, 4)]).is_empty());
    }

    #[test]
    fn a_segment_outside_ram_is_still_mapped() {
        // A destination the running kernel does not manage. Dropping it
        // leaves the trampoline faulting on its first copy, with nothing left
        // able to report it.
        let ram = [(0x1000_0000u64, 0x2000_0000u64)];
        let out = ranges_for(&ram, &[seg(0x8000_0000, BLOCK_SIZE)], &[]);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&(0x8000_0000, 0x8000_0000 + BLOCK_SIZE)));
    }

    #[test]
    fn firmware_ranges_outside_ram_are_mapped_too() {
        // The description tables a replacement kernel reads before it has any
        // mapping of its own are outside usable RAM by construction, so a plan
        // built from RAM and segments alone leaves them untranslated.
        let ram = [(0u64, BLOCK_SIZE)];
        let fw = [(0x7f00_0000u64, 0x7f01_0000u64)];
        let out = ranges_for(&ram, &[], &fw);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&(0x7f00_0000, 0x7f00_0000 + BLOCK_SIZE)),
                "a firmware range must be covered by the block that contains it");
        // And dropping them is exactly the defect: same inputs, no firmware.
        assert_eq!(ranges_for(&ram, &[], &[]).len(), 1);
    }

    #[test]
    fn a_firmware_range_inside_ram_costs_no_extra_block() {
        // Merging matters here: firmware ranges routinely abut or fall inside
        // the RAM the map already covers, and a duplicate claim on one block
        // is refused by the table builder as already mapped.
        let ram = [(0u64, 4 * BLOCK_SIZE)];
        let out = ranges_for(&ram, &[], &[(BLOCK_SIZE, BLOCK_SIZE + 4096)]);
        assert_eq!(out, [(0, 4 * BLOCK_SIZE)]);
    }

    #[test]
    fn a_zero_length_segment_claims_nothing() {
        let out = ranges_for(&[], &[seg(0x8000_0000, 0)], &[]);
        assert!(out.is_empty());
    }

    #[test]
    fn table_pages_counts_root_plus_one_table_per_span() {
        // One 2 MiB block: root + one L1 + one L2.
        assert_eq!(table_pages(&[(0, BLOCK_SIZE)]), 3);
        // Two blocks in the same gigabyte share both tables.
        assert_eq!(table_pages(&[(0, 2 * BLOCK_SIZE)]), 3);
        // Crossing a gigabyte adds one L2.
        assert_eq!(table_pages(&[(0, L1_SPAN + BLOCK_SIZE)]), 4);
        // Crossing 512 GiB adds an L1 as well.
        assert_eq!(table_pages(&[(0, BLOCK_SIZE), (L0_SPAN, L0_SPAN + BLOCK_SIZE)]), 5);
    }

    #[test]
    fn control_pages_needed_covers_the_transition_chain() {
        let r = [(0u64, BLOCK_SIZE)];
        assert_eq!(control_pages_needed(&r), table_pages(&r) + 3);
    }

    #[test]
    fn block_and_max_accounting() {
        let r = normalize(&[(0, 4 * BLOCK_SIZE + 1)]);
        assert_eq!(block_count(&r), 5);
        assert_eq!(max_address(&r), 5 * BLOCK_SIZE);
        assert_eq!(blocks_in(0, PAGE_SIZE), 1);
        assert_eq!(blocks_in(0, 0), 0);
    }

    #[test]
    fn x86_control_register_masks_name_the_documented_bits() {
        // The trampoline consumes these as assembler immediates, so a change
        // here that is not mirrored there — or vice versa — has no other check.
        assert_eq!(CR4_PGE, 0x80);
        assert_eq!(CR4_KEEP, 0x1020);
        assert_eq!(CR0_CLEAR, 0x0005_000c);
        assert_eq!(CR0_SET, 0x8000_0001);
        // PGE must not survive the keep mask, or the stale global entries the
        // clear exists to drop come straight back.
        assert_eq!(CR4_KEEP & CR4_PGE, 0);
    }

    #[test]
    fn every_relocation_bit_position_reconstructs_its_mask() {
        // The aarch64 trampoline branches on these positions and the x86_64 one
        // tests the masks; a divergence would make one arch relocate an image
        // the other could not, with no other check able to see it.
        use crate::uapi::*;
        for (bit, mask) in [(IND_DESTINATION_BIT, IND_DESTINATION),
                            (IND_INDIRECTION_BIT, IND_INDIRECTION),
                            (IND_DONE_BIT, IND_DONE),
                            (IND_SOURCE_BIT, IND_SOURCE)] {
            assert_eq!(1u64 << bit, mask);
            assert!(bit < 12, "a tag bit inside the page-offset field would be masked away");
        }
    }

    #[test]
    fn the_descriptor_table_left_behind_describes_flat_ring_zero_segments() {
        // Each field is separately load-bearing, and a wrong one faults an
        // image at its first segment load with no handler left to take it.
        for e in [GDT_ENTRY_CODE32, GDT_ENTRY_CODE64, GDT_ENTRY_DATA] {
            // Base is zero across all three base fields (bits 39:16, 63:56).
            assert_eq!((e >> 16) & 0xff_ffff, 0, "segment base must be flat");
            assert_eq!((e >> 56) & 0xff, 0, "segment base must be flat");
            // Limit 0xfffff with granularity set (bit 55) spans 4 GiB.
            assert_eq!(e & 0xffff, 0xffff);
            assert_eq!((e >> 48) & 0xf, 0xf);
            assert_ne!(e & (1 << 55), 0, "granularity must scale the limit");
            // Present (47), ring 0 (46:45), code/data rather than system (44).
            assert_ne!(e & (1 << 47), 0, "descriptor must be present");
            assert_eq!((e >> 45) & 3, 0, "descriptor must be ring 0");
            assert_ne!(e & (1 << 44), 0);
        }
        // Executable (43) separates the code entries from the data one.
        assert_ne!(GDT_ENTRY_CODE32 & (1 << 43), 0);
        assert_ne!(GDT_ENTRY_CODE64 & (1 << 43), 0);
        assert_eq!(GDT_ENTRY_DATA & (1 << 43), 0);
        // Data must be writable (41), or every stack push faults.
        assert_ne!(GDT_ENTRY_DATA & (1 << 41), 0);
        // Long mode (53) and default-operand-size (54) are mutually exclusive:
        // setting both is an illegal descriptor the processor rejects.
        assert_ne!(GDT_ENTRY_CODE64 & (1 << 53), 0, "the 64-bit entry must set L");
        assert_eq!(GDT_ENTRY_CODE64 & (1 << 54), 0, "L and D cannot both be set");
        assert_eq!(GDT_ENTRY_CODE32 & (1 << 53), 0);
        assert_ne!(GDT_ENTRY_CODE32 & (1 << 54), 0);
        assert_eq!(GDT_ENTRY_NULL, 0);
    }

    #[test]
    fn the_descriptor_table_limit_covers_exactly_its_entries() {
        // A limit one entry short leaves the last selector unloadable; one
        // entry long lets a selector index past the table into whatever
        // follows it in the control page.
        assert_eq!(GDT_LIMIT, GDT_ENTRIES * 8 - 1);
        assert_eq!(GDT_LIMIT, 31);
        // Every selector the trampoline can name has to fit under the limit.
        for sel in [8u64, 16, 24] { assert!(sel + 7 <= GDT_LIMIT); }
    }

    #[test]
    fn arm_mmu_off_keeps_every_res1_field() {
        assert_eq!(SCTLR_EL1_MMU_OFF, 0x3050_0800);
        // The MMU, cache and instruction-cache enables are the point.
        for bit in [0u32, 2, 12] { assert_eq!(SCTLR_EL1_MMU_OFF & (1 << bit), 0); }
    }

    #[test]
    fn the_identity_maps_reach_is_derived_and_not_assumed() {
        // A translation regime configured for a smaller output size must
        // shrink the plan's reach with it. Assuming the widest case builds a
        // map whose high half the hardware cannot produce addresses for.
        let forty_bits = 2u64 << TCR_IPS_SHIFT;
        assert_eq!(arm_idmap_limit(forty_bits), 1 << 40);
        let forty_eight = 5u64 << TCR_IPS_SHIFT;
        assert_eq!(arm_idmap_limit(forty_eight), 1 << ARM_IDMAP_VA_BITS);
        // And a regime that can produce MORE than the table format describes
        // is still capped by the table format.
        let fifty_two = 6u64 << TCR_IPS_SHIFT;
        assert_eq!(arm_idmap_limit(fifty_two), 1 << ARM_IDMAP_VA_BITS);
        // Bits outside the field must not reach the answer.
        assert_eq!(arm_idmap_limit(u64::MAX & !(TCR_IPS_MASK << TCR_IPS_SHIFT)), 1 << 32);
    }

    #[test]
    fn every_output_size_encoding_is_named() {
        // An unnamed encoding read as a wider one is a map built past what the
        // hardware produces; read as a narrower one it refuses a legal plan.
        for (enc, bits) in [(0u64, 32u32), (1, 36), (2, 40), (3, 42),
                            (4, 44), (5, 48), (6, 52), (7, 56)] {
            assert_eq!(ips_bits(enc), bits);
        }
    }

    #[test]
    fn the_installed_size_field_matches_the_table_format() {
        // The size field and the number of table levels are one decision. A
        // field that describes more bits than the four-level format indexes
        // makes the hardware start its walk at a level the map does not have.
        assert_eq!(ARM_IDMAP_VA_BITS, 48);
        assert_eq!(ARM_IDMAP_T0SZ, 16);
        assert_eq!(64 - ARM_IDMAP_T0SZ, ARM_IDMAP_VA_BITS as u64);
        // Programming it replaces only that field.
        let live = 0x0000_0005_B510_3520u64;
        let out = tcr_with_idmap_t0sz(live);
        assert_eq!(out & TCR_T0SZ_MASK, ARM_IDMAP_T0SZ);
        assert_eq!(out & !TCR_T0SZ_MASK, live & !TCR_T0SZ_MASK);
        // A regime already at the right size is left bit-identical.
        let already = (live & !TCR_T0SZ_MASK) | ARM_IDMAP_T0SZ;
        assert_eq!(tcr_with_idmap_t0sz(already), already);
    }

    #[test]
    fn the_trampoline_must_leave_room_for_its_own_stack() {
        assert!(max_trampoline_bytes() < PAGE_SIZE);
    }
}
