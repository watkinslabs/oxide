/// Memmap-response. Layout per Limine 6 (variable-length entries
/// array follows pointer; we keep the pointer + count and chase the
/// array at parse time).
#[repr(C)]
pub struct MemmapResponse {
    pub revision:    u64,
    pub entry_count: u64,
    /// Physical pointer to `[*const MemmapEntry; entry_count]`.
    pub entries:     *const *const MemmapEntry,
}

#[repr(C)]
pub struct MemmapEntry {
    pub base:   u64,
    pub length: u64,
    pub kind:   u64, // see `MemmapKind`
}

/// Memmap entry kinds per Limine 6.
#[repr(u64)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum MemmapKind {
    Usable                = 0,
    Reserved              = 1,
    AcpiReclaimable       = 2,
    AcpiNvs               = 3,
    BadMemory             = 4,
    BootloaderReclaimable = 5,
    KernelAndModules      = 6,
    Framebuffer           = 7,
}

impl MemmapKind {
    /// # C: O(1)
    pub fn from_u64(v: u64) -> Option<Self> {
        match v {
            0 => Some(Self::Usable),
            1 => Some(Self::Reserved),
            2 => Some(Self::AcpiReclaimable),
            3 => Some(Self::AcpiNvs),
            4 => Some(Self::BadMemory),
            5 => Some(Self::BootloaderReclaimable),
            6 => Some(Self::KernelAndModules),
            7 => Some(Self::Framebuffer),
            _ => None,
        }
    }

    /// Map Limine's `MemmapKind` to our generic `BootMemKind` per
    /// `boot_info::BootMemKind`. Unknown kinds are treated as Reserved.
    /// # C: O(1)
    pub fn to_kernel_kind(self) -> boot_info::BootMemKind {
        use boot_info::BootMemKind as K;
        match self {
            Self::Usable                => K::Usable,
            Self::Reserved              => K::Reserved,
            Self::AcpiReclaimable       => K::AcpiReclaim,
            Self::AcpiNvs               => K::AcpiNvs,
            Self::BadMemory             => K::BadMem,
            Self::BootloaderReclaimable => K::BootloaderUsed,
            Self::KernelAndModules      => K::KernelImage,
            Self::Framebuffer           => K::Reserved,
        }
    }
}

/// HHDM (higher-half direct-map) response.
#[repr(C)]
pub struct HhdmResponse {
    pub revision: u64,
    pub offset:   u64,
}

/// Walk a `MemmapResponse` and populate `out` with up to `out.len()`
/// `BootMemRegion`s converted from Limine entries. Returns the
/// number of entries written.
///
/// Pure function so the conversion logic is hosted-testable without
/// touching the bootloader-owned globals: callers (real boot path
/// or tests) build a `MemmapResponse` and a writable `out` slice
/// and observe what comes back.
///
/// # SAFETY: `resp.entries` points to `[*const MemmapEntry; resp.entry_count]`
/// — typically a bootloader-owned region whose backing memory is
/// reachable for the lifetime of this call. Hosted tests build the
/// pointer table from a stack-local Vec so the lifetime is the test.
/// # C: O(min(entry_count, out.len()))
pub unsafe fn populate_memmap_into(
    out: &mut [boot_info::BootMemRegion],
    resp: &MemmapResponse,
) -> usize {
    let n = (resp.entry_count as usize).min(out.len());
    for i in 0..n {
        // SAFETY: caller asserts `resp.entries` is a valid table of
        // `*const MemmapEntry` of length `resp.entry_count`; index
        // `i` is below `n ≤ entry_count`. Each entry pointer in
        // turn points at a valid `MemmapEntry`.
        let entry = unsafe { &**(resp.entries.add(i)) };
        let kind = MemmapKind::from_u64(entry.kind)
            .map(|k| k.to_kernel_kind())
            .unwrap_or(boot_info::BootMemKind::Reserved);
        out[i] = boot_info::BootMemRegion {
            base_pa: entry.base,
            len:     entry.length,
            kind,
        };
    }
    n
}

/// RSDP response — physical address of the ACPI RSDP.
#[repr(C)]
pub struct RsdpResponse {
    pub revision: u64,
    pub address:  u64,
}
