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

pub const HHDM_ID: RequestId = RequestId([
    LIMINE_COMMON_MAGIC_0, LIMINE_COMMON_MAGIC_1,
    0x48dc_f1cb_8ad2_b852, 0x6342_8723_2167_8025,
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
