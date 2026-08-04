// Which memory goes into a dump.
//
// For one mapping and the dying process's core-dump filter, decide whether the
// mapping's contents are written, elided down to a single identifying page, or
// left out entirely. The ladder is order-sensitive: an earlier rule that
// matches settles the question, so moving a test changes which pages a debugger
// gets. It is expressed over a plain descriptor rather than over the live VMA
// so that every rung is decidable without an address space.

use vmm::coredump_filter::CoredumpFilter;
use vmm::{Vma, VmaBacking, VmaFlags, VmaProt};

/// Magic bytes at the start of an ELF object.
pub const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Permission bits that make a mapped object a program image rather than data.
const MODE_ANY_EXEC: u16 = 0o111;

/// Page granularity the header-page rules work in.
pub const PAGE_BYTES: u64 = hal::PAGE_SIZE_BYTES;

/// How much of one mapping the dump carries.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VmaDumpVerdict {
    /// No contents. The mapping is still described by a program header, with a
    /// zero file size, so a debugger can see the range existed.
    Skipped,
    /// Every page of the mapping.
    Whole,
    /// One page, at the mapping's start — enough to identify the object mapped
    /// there without carrying its whole image.
    FirstPage,
    /// One page, but only if the mapping really starts with an ELF object.
    /// Deciding needs the mapping's first bytes, which cannot be read while the
    /// VMA tree is held, so the reader resolves it later through
    /// [`resolve_elf_probe`].
    ElfProbe,
}

/// One mapping, reduced to the properties the ladder tests.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct VmaDumpDesc {
    /// Mapping bounds, `[start, end)`.
    pub start: u64,
    pub end: u64,
    /// A kernel-provided special mapping (the vDSO, its data page, an
    /// architecture gate page). Always dumped, so a dump stays interpretable
    /// without the exact kernel build that produced it.
    pub always_dump: bool,
    /// The process asked for this range to be left out.
    pub dontdump: bool,
    /// Device memory mapped straight through, with no page frames behind it.
    pub io: bool,
    /// Directly-addressable persistent memory.
    pub dax: bool,
    /// Huge-page mapping.
    pub hugetlb: bool,
    /// Shared rather than private.
    pub shared: bool,
    /// Backed by an object rather than by anonymous memory.
    pub file_backed: bool,
    /// The backing object has no directory entry — anonymous shared memory, or
    /// an unlinked file. Separates the two shared classes.
    pub unlinked_backing: bool,
    /// The mapping has pages of its own, i.e. something has been written to it.
    pub anon_vma: bool,
    /// Readable by the process.
    pub readable: bool,
    /// Mapped from the start of its backing object.
    pub pgoff_zero: bool,
    /// The backing object carries an execute permission bit.
    pub backing_executable: bool,
}

/// Decide how much of `d` a dump taken under `f` contains.
///
/// Order matters and is fixed: special mappings, then the explicit exclusion,
/// then the two memory kinds that have their own filter pair (persistent memory
/// and huge pages), then device memory, then shared mappings, then the private
/// ladder — written-to pages, anonymous with nothing behind them, whole file
/// mapping, identifying header page.
/// # C: O(1)
pub fn vma_dump_verdict(d: &VmaDumpDesc, f: CoredumpFilter) -> VmaDumpVerdict {
    use VmaDumpVerdict::{ElfProbe, FirstPage, Skipped, Whole};

    if d.always_dump { return Whole; }
    if d.dontdump { return Skipped; }

    // Persistent memory and huge pages each answer to their own private/shared
    // pair and to nothing else — neither falls through to the ordinary classes.
    if d.dax {
        return if f.contains(pair(d.shared, CoredumpFilter::DAX_SHARED, CoredumpFilter::DAX_PRIVATE))
            { Whole } else { Skipped };
    }
    if d.hugetlb {
        return if f.contains(pair(d.shared, CoredumpFilter::HUGETLB_SHARED, CoredumpFilter::HUGETLB_PRIVATE))
            { Whole } else { Skipped };
    }

    // Device memory has no frames to copy, and reading it can have side effects.
    if d.io { return Skipped; }

    // A shared mapping is classed by whether its object has a name: anonymous
    // shared memory has none.
    if d.shared {
        let bit = if d.unlinked_backing { CoredumpFilter::ANON_SHARED } else { CoredumpFilter::MAPPED_SHARED };
        return if f.contains(bit) { Whole } else { Skipped };
    }

    // Private, and something has been written into it: the modified pages are
    // the process's own data whatever they were mapped from.
    if d.anon_vma && f.contains(CoredumpFilter::ANON_PRIVATE) { return Whole; }
    // Private, untouched, and nothing behind it: there is nothing to dump.
    if !d.file_backed { return Skipped; }

    if f.contains(CoredumpFilter::MAPPED_PRIVATE) { return Whole; }

    // The head of a mapped object: one page names what was mapped here.
    if f.contains(CoredumpFilter::ELF_HEADERS) && d.pgoff_zero && d.readable {
        // An executable object is a program image with certainty. A library
        // often is not executable, so its first bytes have to be checked —
        // later, once the mapping can be read.
        return if d.backing_executable { FirstPage } else { ElfProbe };
    }

    Skipped
}

fn pair(shared: bool, on_shared: CoredumpFilter, on_private: CoredumpFilter) -> CoredumpFilter {
    if shared { on_shared } else { on_private }
}

/// Settle an [`VmaDumpVerdict::ElfProbe`] once the mapping's first bytes are
/// readable: an ELF object contributes its header page, anything else nothing.
/// Every other verdict passes through.
/// # C: O(1)
pub fn resolve_elf_probe(v: VmaDumpVerdict, head: &[u8]) -> VmaDumpVerdict {
    if v != VmaDumpVerdict::ElfProbe { return v; }
    if head.len() >= ELF_MAGIC.len() && head[..ELF_MAGIC.len()] == ELF_MAGIC {
        VmaDumpVerdict::FirstPage
    } else {
        VmaDumpVerdict::Skipped
    }
}

/// Bytes of `d` the dump carries under `v`. An unresolved
/// [`VmaDumpVerdict::ElfProbe`] counts as its header page, which is the upper
/// bound; resolve it first when the exact size matters.
/// # C: O(1)
pub fn dump_size(v: VmaDumpVerdict, d: &VmaDumpDesc, page_size: u64) -> u64 {
    let len = d.end.saturating_sub(d.start);
    match v {
        VmaDumpVerdict::Skipped => 0,
        VmaDumpVerdict::Whole => len,
        VmaDumpVerdict::FirstPage | VmaDumpVerdict::ElfProbe => len.min(page_size),
    }
}

/// Reduce a live mapping to the descriptor the ladder tests. `vdso_base` is the
/// address space's vDSO image address (zero before one is mapped); the image
/// and the data page immediately below it are the kernel-provided mappings a
/// dump always carries, so that it stays interpretable without the exact kernel
/// build that produced it.
/// # C: O(1)
pub fn describe_vma(vma: &Vma, vdso_base: u64) -> VmaDumpDesc {
    describe_vma_in_range(vma, vdso_base.saturating_sub(PAGE_BYTES), vdso_base.saturating_add(PAGE_BYTES))
}

/// Reduce a VMA while recognizing every mapping in a vvar + vDSO reservation.
/// # C: O(1)
pub fn describe_vma_in_range(vma: &Vma, vdso_start: u64, vdso_end: u64) -> VmaDumpDesc {
    let start = vma.start.as_u64();
    let end = vma.end.as_u64();
    let always_dump = matches!(vma.backing, VmaBacking::Special)
        || (vdso_end > vdso_start && start < vdso_end && vdso_start < end);
    let file = match &vma.backing { VmaBacking::File { backing, off } => Some((backing, *off)), _ => None };
    VmaDumpDesc {
        start,
        end,
        always_dump,
        dontdump: vma.flags.contains(VmaFlags::DONTDUMP),
        // A directly-mapped physical range carries no page frames, which is
        // exactly the device-memory case.
        io: matches!(vma.backing, VmaBacking::PhysRange { .. }),
        // Neither persistent memory nor huge-page mappings exist in this
        // kernel yet, so no live mapping can set these.
        dax: false,
        hugetlb: false,
        shared: vma.flags.contains(VmaFlags::SHARED),
        file_backed: file.is_some(),
        // Anonymous shared memory has no directory entry by construction.
        unlinked_backing: match &file { Some((b, _)) => b.i_nlink() == 0, None => true },
        // "Has private anonymous pages of its own": an anonymous mapping that
        // has faulted at least one page in. An anonymous mapping that has never
        // been touched holds nothing worth writing out.
        anon_vma: vma.anon_vma.is_some() && vma.rss.load(core::sync::atomic::Ordering::Relaxed) != 0,
        readable: vma.prot.contains(VmaProt::READ),
        pgoff_zero: matches!(file, Some((_, 0))),
        backing_executable: match &file { Some((b, _)) => b.i_mode() & MODE_ANY_EXEC != 0, None => false },
    }
}
