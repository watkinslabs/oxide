// Walking a live VMA tree through the selection ladder.
//
// One planned segment per mapping, in ascending address order, each carrying
// the byte count the ladder settled on and — for a mapping with an object
// behind it — the path and page offset `NT_FILE` reports. A mapping the filter
// excludes is still planned, with nothing to write: a debugger that sees the
// range existed and was empty learns more than one that sees no range at all,
// and it is what the reference image does.
//
// Ungated on purpose. The decisions here (which mappings appear, how much of
// each, what `NT_FILE` says about them) are exactly the ones a kernel-gated
// module could not be tested for.

use alloc::vec::Vec;

use vmm::coredump_filter::CoredumpFilter;
use vmm::{Vma, VmaBacking, VmaProt};

use super::elf::{SEG_EXEC, SEG_READ, SEG_WRITE};
use super::filter::{describe_vma_in_range, dump_size, resolve_elf_probe, vma_dump_verdict, VmaDumpVerdict};

/// Bytes read to settle an [`VmaDumpVerdict::ElfProbe`]: enough for the magic
/// that tells a mapped object from anything else.
pub const PROBE_BYTES: usize = 4;

/// What `NT_FILE` says about one mapping.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlannedFile {
    /// Path the mapping was faulted from, empty when the object has no name
    /// reachable from this mapping.
    pub path: Vec<u8>,
    /// Mapping's starting offset into that object, in pages.
    pub pgoff_pages: u64,
}

/// One mapping, ready to become a program header.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct PlannedSegment {
    pub start: u64,
    pub end: u64,
    pub prot: u32,
    pub dump_size: u64,
    pub file: Option<PlannedFile>,
}

/// Program-header permission bits of a mapping.
/// # C: O(1)
pub fn seg_prot(p: VmaProt) -> u32 {
    let mut f = 0;
    if p.contains(VmaProt::READ)  { f |= SEG_READ }
    if p.contains(VmaProt::WRITE) { f |= SEG_WRITE }
    if p.contains(VmaProt::EXEC)  { f |= SEG_EXEC }
    f
}

/// The object behind a mapping, as `NT_FILE` names it. A mapping with no
/// directory entry behind it contributes no entry, which is why anonymous
/// shared memory never appears in the table.
fn planned_file(vma: &Vma, page_size: u64) -> Option<PlannedFile> {
    let VmaBacking::File { backing, off } = &vma.backing else { return None };
    let path = backing.map_path()?;
    if path.is_empty() { return None }
    Some(PlannedFile { path: path.to_vec(), pgoff_pages: off / page_size })
}

/// Plan every mapping of an address space.
///
/// `head` reads the first bytes of a mapping and returns how many it produced;
/// it settles the header-page rule for an object whose permissions do not
/// already say it is a program image. It is only called for a mapping the
/// ladder defers, so an address space with no such mapping never reads memory
/// here at all.
/// # C: O(mappings)
pub fn plan_mappings<R: FnMut(u64, &mut [u8]) -> usize>(
    vmas: &[Vma], vdso_start: u64, vdso_end: u64, filter: CoredumpFilter, page_size: u64, head: &mut R,
) -> Vec<PlannedSegment> {
    let mut out: Vec<PlannedSegment> = Vec::with_capacity(vmas.len());
    for vma in vmas.iter() {
        let d = describe_vma_in_range(vma, vdso_start, vdso_end);
        let mut v = vma_dump_verdict(&d, filter);
        if v == VmaDumpVerdict::ElfProbe {
            let mut probe = [0u8; PROBE_BYTES];
            let got = head(d.start, &mut probe).min(PROBE_BYTES);
            v = resolve_elf_probe(v, &probe[..got]);
        }
        out.push(PlannedSegment {
            start: d.start,
            end: d.end,
            prot: seg_prot(vma.prot),
            dump_size: dump_size(v, &d, page_size),
            file: planned_file(vma, page_size),
        });
    }
    out
}

/// Bytes the memory half of a planned image occupies.
/// # C: O(segments)
pub fn planned_bytes(segs: &[PlannedSegment]) -> u64 { segs.iter().map(|s| s.dump_size).sum() }
