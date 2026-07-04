// Limine boot protocol request types per `36§3` (Limine >= 6.0).
// Shared across both arch boot crates (`boot-x86_64`, `boot-aarch64`).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(test)]
extern crate std;

mod ids;
mod memmap;
mod request;
mod smp;

pub use ids::{
    RequestId, EXECUTABLE_FILE_ID, HHDM_ID, KERNEL_FILE_ID, LIMINE_COMMON_MAGIC_0,
    LIMINE_COMMON_MAGIC_1, MEMMAP_ID, REQUESTS_END_MARKER, REQUESTS_START_MARKER, REVISION_0,
    RSDP_ID, SMP_ID,
};
pub use memmap::{
    populate_memmap_into, HhdmResponse, MemmapEntry, MemmapKind, MemmapResponse, RsdpResponse,
};
pub use request::{ExecutableFileResponse, LimineFile, RequestHeader};
pub use smp::{
    SmpInfoAArch64, SmpInfoX86, SmpRequest, SmpRequestAArch64, SmpResponse,
    SmpResponseAArch64, SMP_FLAG_X2APIC,
};

#[cfg(test)]
mod tests;
