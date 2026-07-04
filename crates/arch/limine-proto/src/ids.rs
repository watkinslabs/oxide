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

/// `LIMINE_MP_REQUEST` — Limine v9+ renamed SMP→MP. v12 also
/// changed the second FEATURE magic word to
/// `0xa0b61b723b6a73e0` (was `0x3a7e3a8a18ab9168` in older
/// PROTOCOL.md drafts). Pinned against
/// `limine-protocol/include/limine.h` HEAD.
pub const SMP_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0x95a6_7b81_9a1b_857e, 0xa0b6_1b72_3b6a_73e0,
]);

/// `LIMINE_EXECUTABLE_FILE_REQUEST` (was LIMINE_KERNEL_FILE_REQUEST
/// pre-v9). The response carries the bootloader-loaded executable's
/// LimineFile descriptor whose `cmdline` field is the command line
/// the bootloader parsed (e.g. Limine config `cmdline` line).
/// Magic pinned against `limine-protocol/include/limine.h` HEAD.
pub const EXECUTABLE_FILE_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0xad97_e90e_8332_8329, 0xbafb_eef9_75c9_b6c9,
]);

/// Legacy `LIMINE_KERNEL_FILE_REQUEST` (pre-v9 naming). Some Limine
/// builds populate this and not EXECUTABLE_FILE; emit both and the
/// boot path consults whichever the bootloader filled.
pub const KERNEL_FILE_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0xad97_e90e_83f1_ed67, 0x31eb_5d1c_5ff2_3b69,
]);

/// `LIMINE_REQUESTS_START_MARKER` — Limine v9+ uses these markers to
/// bound the request-scanning region inside the kernel image.
/// Without them v12+ may skip requests it would otherwise see via
/// the legacy full-image scan. Place at start of `.limine_requests`
/// per `36§3`.
pub const REQUESTS_START_MARKER: [u64; 4] = [
    0xf6b8_f4b3_9de7_d1ae,
    0x14c3_68d3_cef7_a05a,
    0xcacc_fa6e_0f6c_b902,
    0x40b7_1fa9_aaad_7012,
];

/// `LIMINE_REQUESTS_END_MARKER` — counterpart to `REQUESTS_START_MARKER`.
pub const REQUESTS_END_MARKER: [u64; 2] = [
    0xadc0_e053_1bb1_0d03,
    0x9572_709f_3176_4c62,
];

// ---------------------------------------------------------------------------
// Request structs
// ---------------------------------------------------------------------------
