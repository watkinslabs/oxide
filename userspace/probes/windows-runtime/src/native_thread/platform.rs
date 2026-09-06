use syscall::{nt::NtService, nt_native_thread as abi};

pub(super) fn call(op: u64, a1: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    // SAFETY: each private operation owns validation of its pointed-to ABI record.
    let result = unsafe { libc::syscall(NtService::QueryVirtualMemory.entry() as libc::c_long,
        op, a1, abi::INFO_CLASS, a3, a4, a5) };
    if result == -1 { abi::INVALID } else { result as u64 }
}

#[cfg(target_arch = "x86_64")]
#[path = "x86_64.rs"]
mod arch;
#[cfg(target_arch = "aarch64")]
#[path = "aarch64.rs"]
mod arch;
pub(super) unsafe fn enter() -> u64 {
    // SAFETY: caller owns the prepared native child and its ENTER continuation.
    unsafe { arch::enter() }
}
pub(super) fn factory_address() -> u64 { arch::factory as *const () as u64 }
pub(super) fn factory_return_address() -> u64 { arch::factory_return as *const () as u64 }
pub(super) fn pe_return_address() -> u64 { arch::pe_return as *const () as u64 }
