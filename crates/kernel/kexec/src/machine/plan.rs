// What the trampoline runs under, decided BEFORE the point of no return.
//
// Everything here is ungated on purpose. The jump itself cannot be tested —
// it does not return — so every decision it depends on is made in a module a
// hosted test can compile: which physical ranges the identity map has to
// cover, how many pages that costs, and the control-register state the entry
// contract fixes. The trampoline then only executes what was already decided.
//
// The reference builds its identity tables in `machine_kexec_prepare`, i.e. at
// LOAD time, and that ordering is the whole reason this file exists at load
// time too: a table that cannot be built must surface as an errno from
// `kexec_load(2)`, not as a machine that stopped halfway through relocating.

extern crate alloc;
use alloc::vec::Vec;

use crate::uapi::{KexecSegment, PAGE_SIZE};

/// Leaf level of the identity map: a 2 MiB block (L2 on both walkers).
///
/// The reference's default too — 1 GiB leaves ride on a CPU feature it tests
/// for separately, and a table that needs no feature test cannot be built
/// wrong on a machine that lacks it.
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
/// merged: every usable RAM range (the reference's `pfn_mapped`) plus every
/// segment's destination range.
///
/// Segments are included SEPARATELY from RAM because a destination is not
/// required to be inside RAM the running kernel manages — a second kernel
/// loaded below the first one's usable window is the reference's stated
/// reason for the same loop, and a map built from RAM alone would fault the
/// trampoline on its first copy into such a segment.
/// # C: O(N log N) over ranges
pub fn ranges_for(ram: &[(u64, u64)], segs: &[KexecSegment]) -> Vec<(u64, u64)> {
    let mut raw: Vec<(u64, u64)> = Vec::new();
    for &(s, e) in ram { raw.push((s, e)); }
    for s in segs {
        if s.memsz == 0 { continue; }
        raw.push((s.mem, s.mem.saturating_add(s.memsz)));
    }
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
/// cleared — the reference does that in two steps for the same reason and in
/// the same order.
pub const CR4_KEEP: u64 = (1 << 5) | (1 << 12);

/// `CR0` bits the trampoline clears: `AM` (18), `WP` (16), `TS` (3), `EM` (2).
pub const CR0_CLEAR: u64 = (1 << 18) | (1 << 16) | (1 << 3) | (1 << 2);
/// `CR0` bits it sets: `PG` (31) and `PE` (0).
pub const CR0_SET: u64 = (1 << 31) | 1;

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

/// Highest physical address the aarch64 identity map can describe under the
/// kernel's `TCR_EL1.T0SZ` of 16 (48-bit `TTBR0` virtual addresses). A plan
/// reaching past it cannot be identity mapped at all, and the reference
/// answers the same question by recomputing `T0SZ`; refusing at LOAD time is
/// the half of that this port implements, so the failure is an errno.
pub const ARM_MAX_IDMAP_PA: u64 = 1 << 48;

/// Pages a byte range spans at the identity map's leaf size.
/// # C: O(1)
pub fn blocks_in(start: u64, end: u64) -> u64 {
    if end <= start { 0 } else { (end - start).div_ceil(BLOCK_SIZE) }
}

/// Bytes of trampoline that fit in one control page, leaving the tail for the
/// stack the trampoline runs on. The reference uses the same page for both.
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
        // The case the reference calls out: a destination the running kernel
        // does not manage. Dropping it leaves the trampoline faulting on its
        // first copy, with nothing left able to report it.
        let ram = [(0x1000_0000u64, 0x2000_0000u64)];
        let out = ranges_for(&ram, &[seg(0x8000_0000, BLOCK_SIZE)]);
        assert_eq!(out.len(), 2);
        assert!(out.contains(&(0x8000_0000, 0x8000_0000 + BLOCK_SIZE)));
    }

    #[test]
    fn a_zero_length_segment_claims_nothing() {
        let out = ranges_for(&[], &[seg(0x8000_0000, 0)]);
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
    fn arm_mmu_off_keeps_every_res1_field() {
        assert_eq!(SCTLR_EL1_MMU_OFF, 0x3050_0800);
        // The MMU, cache and instruction-cache enables are the point.
        for bit in [0u32, 2, 12] { assert_eq!(SCTLR_EL1_MMU_OFF & (1 << bit), 0); }
    }

    #[test]
    fn the_trampoline_must_leave_room_for_its_own_stack() {
        assert!(max_trampoline_bytes() < PAGE_SIZE);
    }
}
