use core::sync::atomic::AtomicPtr;

use crate::limine::{ExecutableFileResponse, HhdmResponse, MemmapResponse, RequestHeader, RsdpResponse, SmpRequest, EXECUTABLE_FILE_ID, HHDM_ID, KERNEL_FILE_ID, MEMMAP_ID, REQUESTS_END_MARKER, REQUESTS_START_MARKER, REVISION_0, RSDP_ID, SMP_ID};

// ---------------------------------------------------------------------------
// Limine request slots — bootloader scans `.limine_requests` for these
// markers and writes responses before jumping to `_start`.
// ---------------------------------------------------------------------------

/// Base-revision marker per Limine v12 protocol. Required ≥ 6 on
/// modern Limine; older protocols reject revision 0. Values are
/// stable across Limine 9..12. MUST appear at the start of
/// `.limine_requests`; we land it via the `.start` subname which
/// the linker places before the rest.
#[used]
#[link_section = ".limine_requests.start"]
static LIMINE_BASE_REVISION: [u64; 3] = [
    0xf9562b2d5c95a6c8,
    0x6a7b384944536bdc,
    6,
];

/// Limine v9+ requires explicit markers around the request region;
/// v12 falls back to a slower full-image scan without them but our
/// SMP request was missed in that fallback path. The linker places
/// `.limine_requests.start` first and `.limine_requests.end` last
/// per the link script.
#[used]
#[link_section = ".limine_requests.start"]
static LIMINE_REQUESTS_START: [u64; 4] = REQUESTS_START_MARKER;

#[used]
#[link_section = ".limine_requests.end"]
static LIMINE_REQUESTS_END: [u64; 2] = REQUESTS_END_MARKER;

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_MEMMAP: RequestHeader<MemmapResponse> = RequestHeader {
    id:       MEMMAP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_HHDM: RequestHeader<HhdmResponse> = RequestHeader {
    id:       HHDM_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_RSDP: RequestHeader<RsdpResponse> = RequestHeader {
    id:       RSDP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

/// `EXECUTABLE_FILE` request — fetches the bootloader-loaded
/// kernel image descriptor, whose `cmdline` field holds whatever
/// the Limine config passed (e.g. `cmdline: root=/dev/oxide0 …`).
/// Without this, `/proc/cmdline` falls back to the arch-default
/// installed by `cmdline::install_arch_default`.
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_EXECUTABLE_FILE: RequestHeader<ExecutableFileResponse>
    = RequestHeader {
        id:       EXECUTABLE_FILE_ID,
        revision: REVISION_0,
        response: AtomicPtr::new(core::ptr::null_mut()),
    };

/// Legacy KERNEL_FILE_REQUEST shape. Same response layout
/// (a *const LimineFile carrying `cmdline`). Some Limine builds set
/// this and leave EXECUTABLE_FILE null; the cmdline capture path
/// consults whichever responded.
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_KERNEL_FILE: RequestHeader<ExecutableFileResponse>
    = RequestHeader {
        id:       KERNEL_FILE_ID,
        revision: REVISION_0,
        response: AtomicPtr::new(core::ptr::null_mut()),
    };

/// SMP enumeration request — Limine starts each AP, parks it
/// spinning on `SmpInfoX86::goto_address`, and gives us the
/// `[*mut SmpInfoX86; cpu_count]` table via the response.
/// `flags=0` keeps APs in xAPIC mode (sufficient for QEMU virt
/// CPU counts; X2APIC mode lands when we add x2APIC support).
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_SMP: SmpRequest = SmpRequest {
    id:       SMP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
    flags:    0,
};

