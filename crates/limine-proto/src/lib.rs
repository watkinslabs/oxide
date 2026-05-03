// Limine boot protocol request types per `36§3` (Limine ≥ 6.0).
// Each request begins with a `[u64; 4]` magic header the bootloader
// scans for in our ELF; on match, the bootloader writes a physical
// address into `response`.
//
// Shared across both arch boot crates (`boot-x86_64`, `boot-aarch64`)
// — magic-words pinning lives in one place. Magic IDs are pinned
// against `limine-protocol/include/limine.h` v12 by the
// `per_feature_magic_matches_limine_protocol_v12` test below.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

use core::sync::atomic::AtomicPtr;

/// Common Limine header — every request shares these two magic words.
pub const LIMINE_COMMON_MAGIC_0: u64 = 0xc7b1_dd30_df4c_8b88;
pub const LIMINE_COMMON_MAGIC_1: u64 = 0x0a82_e883_a194_f07b;

/// 4-word request id: common magic + per-feature words.
#[repr(C)]
#[derive(Copy, Clone, Eq, PartialEq, Debug)]
pub struct RequestId(pub [u64; 4]);

/// Request-revision word — bootloader inspects to decide which
/// fields are valid; `0` is the lowest baseline.
pub const REVISION_0: u64 = 0;

// ---------------------------------------------------------------------------
// Per-feature request ids
// ---------------------------------------------------------------------------

/// `LIMINE_MEMMAP_REQUEST` — full memory map per `36§3`.
pub const MEMMAP_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0x67cf_3d9d_378a_806f, 0xe304_acdf_c50c_3c62,
]);

/// `LIMINE_HHDM_REQUEST` — higher-half direct-map base per `36§3`.
/// Magic pinned against `limine-protocol/include/limine.h` v12 line 143.
pub const HHDM_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0x48dc_f1cb_8ad2_b852, 0x6398_4e95_9a98_244b,
]);

/// `LIMINE_RSDP_REQUEST` — ACPI RSDP physical address.
/// Magic pinned against `limine-protocol/include/limine.h` v12 line 478.
pub const RSDP_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0xc5e7_7b6b_397e_7b43, 0x2763_7845_accd_cf3c,
]);

// ---------------------------------------------------------------------------
// Request structs
// ---------------------------------------------------------------------------

/// Common request header. Bootloader matches on `id`; on hit, sets
/// `response` to the physical address of a feature-specific
/// response struct.
#[repr(C)]
pub struct RequestHeader<R> {
    pub id:       RequestId,
    pub revision: u64,
    pub response: AtomicPtr<R>,
}

// SAFETY: `RequestHeader` is shared with the bootloader before any
// CPU other than the boot CPU is alive; afterwards it is read-only
// from the kernel side. The `AtomicPtr` is the bootloader's write
// port. Response payloads contain raw pointers that aren't `Sync`
// by default — the bootloader writes them once and the kernel reads
// them serially, so we assert `Sync` unconditionally on the wrapper.
unsafe impl<R> Sync for RequestHeader<R> {}

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
    /// `kernel::BootMemKind`. Unknown kinds are treated as Reserved.
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
    out: &mut [kernel::BootMemRegion],
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
            .unwrap_or(kernel::BootMemKind::Reserved);
        out[i] = kernel::BootMemRegion {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn common_magic_constants_match_limine_protocol() {
        // Pin these — bootloader relies on exact byte match.
        assert_eq!(LIMINE_COMMON_MAGIC_0, 0xc7b1_dd30_df4c_8b88);
        assert_eq!(LIMINE_COMMON_MAGIC_1, 0x0a82_e883_a194_f07b);
    }

    #[test]
    fn per_feature_ids_carry_common_magic() {
        for id in [MEMMAP_ID, HHDM_ID, RSDP_ID] {
            assert_eq!(id.0[0], LIMINE_COMMON_MAGIC_0,
                "request id {:?} missing common magic 0", id);
            assert_eq!(id.0[1], LIMINE_COMMON_MAGIC_1,
                "request id {:?} missing common magic 1", id);
        }
    }

    #[test]
    fn per_feature_magic_matches_limine_protocol_v12() {
        // Pin canonical magic words from
        // `limine-protocol/include/limine.h` (v12.x):
        //   LIMINE_MEMMAP_REQUEST_ID = { ..., 0x67cf3d9d378a806f, 0xe304acdfc50c3c62 }
        //   LIMINE_HHDM_REQUEST_ID   = { ..., 0x48dcf1cb8ad2b852, 0x63984e959a98244b }
        //   LIMINE_RSDP_REQUEST_ID   = { ..., 0xc5e77b6b397e7b43, 0x27637845accdcf3c }
        // A typo here means the bootloader scans for our marker and
        // never finds it, leaving `response` null — and silently so.
        assert_eq!(MEMMAP_ID.0[2], 0x67cf_3d9d_378a_806f);
        assert_eq!(MEMMAP_ID.0[3], 0xe304_acdf_c50c_3c62);
        assert_eq!(HHDM_ID.0[2],   0x48dc_f1cb_8ad2_b852);
        assert_eq!(HHDM_ID.0[3],   0x6398_4e95_9a98_244b);
        assert_eq!(RSDP_ID.0[2],   0xc5e7_7b6b_397e_7b43);
        assert_eq!(RSDP_ID.0[3],   0x2763_7845_accd_cf3c);
    }

    #[test]
    fn per_feature_ids_distinct() {
        assert_ne!(MEMMAP_ID, HHDM_ID);
        assert_ne!(MEMMAP_ID, RSDP_ID);
        assert_ne!(HHDM_ID,   RSDP_ID);
    }

    #[test]
    fn request_header_layout_is_24_plus_ptr() {
        // 32 B magic + 8 B revision + ptr-size response.
        let sz = core::mem::size_of::<RequestHeader<MemmapResponse>>();
        assert_eq!(sz, 32 + 8 + core::mem::size_of::<*mut MemmapResponse>());
    }

    #[test]
    fn memmap_kind_round_trip() {
        for raw in 0..=7u64 {
            let k = MemmapKind::from_u64(raw).unwrap();
            assert_eq!(k as u64, raw);
        }
        assert!(MemmapKind::from_u64(99).is_none());
    }

    #[test]
    fn memmap_kind_to_kernel_kind_maps_usable() {
        assert_eq!(MemmapKind::Usable.to_kernel_kind(),    kernel::BootMemKind::Usable);
        assert_eq!(MemmapKind::Reserved.to_kernel_kind(),  kernel::BootMemKind::Reserved);
        assert_eq!(MemmapKind::AcpiReclaimable.to_kernel_kind(),
                   kernel::BootMemKind::AcpiReclaim);
        assert_eq!(MemmapKind::AcpiNvs.to_kernel_kind(),   kernel::BootMemKind::AcpiNvs);
        assert_eq!(MemmapKind::BadMemory.to_kernel_kind(), kernel::BootMemKind::BadMem);
    }

    extern crate alloc;

    fn fake_memmap(entries: &[(u64, u64, u64)])
        -> (alloc::vec::Vec<MemmapEntry>, alloc::vec::Vec<*const MemmapEntry>)
    {
        let mut backing: alloc::vec::Vec<MemmapEntry> = entries.iter()
            .map(|(b, l, k)| MemmapEntry { base: *b, length: *l, kind: *k })
            .collect();
        let mut ptrs: alloc::vec::Vec<*const MemmapEntry> = backing.iter_mut()
            .map(|e| e as *const _)
            .collect();
        let _ = &mut ptrs;
        (backing, ptrs)
    }

    #[test]
    fn populate_memmap_writes_each_entry() {
        let (_backing, ptrs) = fake_memmap(&[
            (0x0000_0000, 0x000a_0000, 0), // Usable, 640 KiB
            (0x000a_0000, 0x0006_0000, 1), // Reserved
            (0x0010_0000, 0x4000_0000, 5), // BootloaderReclaimable
        ]);
        let resp = MemmapResponse {
            revision:    0,
            entry_count: ptrs.len() as u64,
            entries:     ptrs.as_ptr(),
        };
        let mut out = [kernel::BootMemRegion {
            base_pa: 0, len: 0, kind: kernel::BootMemKind::Reserved,
        }; 8];
        // SAFETY: hosted test; ptrs/backing live across this call.
        let n = unsafe { populate_memmap_into(&mut out, &resp) };
        assert_eq!(n, 3);
        assert_eq!(out[0].base_pa, 0);
        assert_eq!(out[0].kind,    kernel::BootMemKind::Usable);
        assert_eq!(out[1].kind,    kernel::BootMemKind::Reserved);
        assert_eq!(out[2].kind,    kernel::BootMemKind::BootloaderUsed);
        assert_eq!(out[2].len,     0x4000_0000);
    }

    #[test]
    fn populate_memmap_caps_at_out_len() {
        let (_backing, ptrs) = fake_memmap(&[
            (0, 0x1000, 0), (0x1000, 0x1000, 0), (0x2000, 0x1000, 0),
            (0x3000, 0x1000, 0),
        ]);
        let resp = MemmapResponse {
            revision: 0, entry_count: 4, entries: ptrs.as_ptr(),
        };
        let mut out = [kernel::BootMemRegion {
            base_pa: 0, len: 0, kind: kernel::BootMemKind::Reserved,
        }; 2];
        // SAFETY: hosted test; pointers live across the call.
        let n = unsafe { populate_memmap_into(&mut out, &resp) };
        assert_eq!(n, 2, "must cap at out.len() per spec");
        assert_eq!(out[0].base_pa, 0);
        assert_eq!(out[1].base_pa, 0x1000);
    }

    #[test]
    fn populate_memmap_unknown_kind_falls_back_to_reserved() {
        let (_backing, ptrs) = fake_memmap(&[(0, 0x1000, 99)]);
        let resp = MemmapResponse {
            revision: 0, entry_count: 1, entries: ptrs.as_ptr(),
        };
        let mut out = [kernel::BootMemRegion {
            base_pa: 0, len: 0, kind: kernel::BootMemKind::Usable,
        }; 1];
        // SAFETY: hosted test; pointers live across the call.
        let n = unsafe { populate_memmap_into(&mut out, &resp) };
        assert_eq!(n, 1);
        assert_eq!(out[0].kind, kernel::BootMemKind::Reserved,
            "unknown kind must fall back to Reserved");
    }
}
