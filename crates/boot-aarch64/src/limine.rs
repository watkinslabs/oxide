// Limine protocol request types per `36§3`. Subset for the
// aarch64 boot path: just what we need to read the HHDM offset
// before touching MMIO.
//
// (Duplicates types in `boot-x86_64/src/limine.rs`. A shared
// `crates/limine-proto/` would dedupe — separate refactor PR.)

use core::sync::atomic::AtomicPtr;

pub const LIMINE_COMMON_MAGIC_0: u64 = 0xc7b1_dd30_df4c_8b88;
pub const LIMINE_COMMON_MAGIC_1: u64 = 0x0a82_e883_a194_f07b;

#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct RequestId(pub [u64; 4]);

pub const REVISION_0: u64 = 0;

// Magic pinned against `limine-protocol/include/limine.h` v12 line 143.
pub const HHDM_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0x48dc_f1cb_8ad2_b852, 0x6398_4e95_9a98_244b,
]);

// Magic pinned against `limine-protocol/include/limine.h` v12 line 385.
pub const MEMMAP_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0x67cf_3d9d_378a_806f, 0xe304_acdf_c50c_3c62,
]);

#[repr(C)]
pub struct RequestHeader<R> {
    pub id:       RequestId,
    pub revision: u64,
    pub response: AtomicPtr<R>,
}

// SAFETY: RequestHeader is shared with the bootloader before any
// other CPU is alive; afterwards the response pointer is read-only
// from kernel side. Same model as boot-x86_64's identical type.
unsafe impl<R> Sync for RequestHeader<R> {}

#[repr(C)]
pub struct HhdmResponse {
    pub revision: u64,
    pub offset:   u64,
}

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
    pub kind:   u64,
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

    /// Map Limine's `MemmapKind` to `kernel::BootMemKind`. Unknown
    /// kinds are treated as Reserved.
    /// # C: O(1)
    pub fn to_kernel_kind(self) -> kernel::BootMemKind {
        use kernel::BootMemKind as K;
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

/// Walk a `MemmapResponse` and populate `out` with up to `out.len()`
/// `BootMemRegion`s converted from Limine entries. Returns the
/// number of entries written.
///
/// # SAFETY: `resp.entries` points to `[*const MemmapEntry; resp.entry_count]`
/// — typically a bootloader-owned region whose backing memory is
/// reachable for the lifetime of this call.
/// # C: O(min(entry_count, out.len()))
pub unsafe fn populate_memmap_into(
    out: &mut [kernel::BootMemRegion],
    resp: &MemmapResponse,
) -> usize {
    let n = (resp.entry_count as usize).min(out.len());
    for i in 0..n {
        // SAFETY: caller asserts `resp.entries` is a valid table of
        // `*const MemmapEntry` of length `resp.entry_count`; index
        // `i` is below `n ≤ entry_count`. Each entry pointer in turn
        // points to a valid `MemmapEntry`.
        let entry = unsafe { &**(resp.entries.add(i)) };
        let kind = MemmapKind::from_u64(entry.kind)
            .map(|k| k.to_kernel_kind())
            .unwrap_or(kernel::BootMemKind::Reserved);
        out[i] = kernel::BootMemRegion {
            base_pa: entry.base,
            len:     entry.length,
            kind,
        };
    }
    n
}
