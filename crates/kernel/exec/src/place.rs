// How an image's load bias is chosen. Linux `load_elf_binary`
// (`fs/binfmt_elf.c:1073-1202`) has exactly two strategies and picks between
// them on `e_type` and whether a PT_INTERP is present; this module is that
// choice plus the two phdr scans it needs.

use elf::{ElfType, LoadSegment};
use vmm::AddressSpace;

use crate::{LoadError, PAGE};

/// Linux's two placement strategies.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) enum Placement {
    /// An explicit bias, mapped `MAP_FIXED`. ET_EXEC uses `0` (`p_vaddr` is
    /// absolute); a PIE that carries a PT_INTERP uses
    /// `ELF_ET_DYN_BASE + arch_mmap_rnd()` (`fs/binfmt_elf.c:1140-1146`, where
    /// Linux sets `MAP_FIXED_NOREPLACE`).
    Fixed(u64),
    /// Hint `0` with no `MAP_FIXED`, so `get_unmapped_area` picks the address
    /// (`fs/binfmt_elf.c:686-689` for the interpreter, `:1175` for a PIE with
    /// no interpreter). Inherits `mmap_base`'s randomisation rather than
    /// drawing its own.
    Unmapped,
}

/// Linux `total_mapping_size()` (`fs/binfmt_elf.c:463-478`): the VA span from
/// the lowest PT_LOAD's page start to the highest PT_LOAD's end. This is the
/// size reserved as one unit so the image cannot be split across two holes.
///
/// Rounded UP to a page. Linux leaves the raw span and lets `vm_mmap` round it
/// (`PAGE_ALIGN(len)`); here the reservation goes to `get_unmapped_area`, which
/// rejects a non-page-multiple length outright — and the last PT_LOAD's
/// `p_vaddr + p_memsz` is the end of `.bss`, so the raw span is essentially
/// never page-aligned. Returning it unrounded fails every dynamically linked
/// exec, and a hole address derived from it would be misaligned besides.
/// # C: O(phdrs)
pub(crate) fn total_mapping_size(loads: &[LoadSegment]) -> u64 {
    let (mut min, mut max) = (u64::MAX, 0u64);
    for s in loads {
        min = min.min(align_down(s.vaddr));
        max = max.max(s.vaddr.saturating_add(s.mem_sz));
    }
    if min == u64::MAX { 0 } else { align_up(max).saturating_sub(min) }
}

/// Page start of the lowest PT_LOAD — the offset the chosen base must be
/// biased by so segment `p_vaddr + bias` lands at the base.
/// # C: O(phdrs)
pub(crate) fn min_vaddr(loads: &[LoadSegment]) -> u64 {
    loads.iter().map(|s| align_down(s.vaddr)).min().unwrap_or(0)
}

/// Linux `maximum_alignment()` (`fs/binfmt_elf.c:491-509`): the coarsest
/// power-of-two `p_align` across the PT_LOADs, page-aligned. Non-power-of-two
/// `p_align` values are skipped exactly as Linux skips them.
/// # C: O(phdrs)
pub(crate) fn maximum_alignment(loads: &[LoadSegment]) -> u64 {
    let mut a = 0u64;
    for s in loads {
        if s.align.is_power_of_two() { a = a.max(s.align); }
    }
    if a == 0 { 0 } else { align_up(a) }
}

/// Resolve a `Placement` to the concrete bias added to every `p_vaddr`.
///
/// For `Fixed`, Linux's `load_bias = ELF_PAGESTART(load_bias - vaddr)`
/// (`fs/binfmt_elf.c:1185`) — which runs only in the ET_DYN branch, so ET_EXEC
/// keeps a bias of exactly `0`. For `Unmapped`, the bias is whatever makes the
/// image start at the address the arena search returned.
/// # C: O(phdrs) + O(N) hole search
pub(crate) fn resolve(
    p: Placement,
    elf_type: ElfType,
    loads: &[LoadSegment],
    as_: &AddressSpace,
) -> Result<u64, LoadError> {
    match p {
        Placement::Fixed(_) if elf_type == ElfType::Exec => Ok(0),
        Placement::Fixed(base) => Ok(align_down(base.wrapping_sub(min_vaddr(loads)))),
        Placement::Unmapped => {
            let total = total_mapping_size(loads);
            if total == 0 { return Err(LoadError::Einval); }
            let at = as_.get_unmapped_area(total as usize).map_err(|_| LoadError::Enomem)?;
            at.as_u64().checked_sub(min_vaddr(loads)).ok_or(LoadError::Einval)
        }
    }
}

#[inline]
fn align_down(v: u64) -> u64 { v & !(PAGE - 1) }

#[inline]
fn align_up(v: u64) -> u64 { (v + (PAGE - 1)) & !(PAGE - 1) }

#[cfg(test)]
mod tests;
