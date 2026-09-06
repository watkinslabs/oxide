use super::{abi, NtService};

unsafe extern "C" fn factory_impl(request: *const abi::FactoryRequest) -> u64 {
    // SAFETY: kernel-owned callback request lives until factory completion.
    unsafe { super::super::native::factory(request) }
}
#[unsafe(naked)]
pub(super) unsafe extern "C" fn factory() -> u64 {
    core::arch::naked_asm!("stp x18, x30, [sp, #-16]!", "bl {factory}",
        "ldp x18, x30, [sp], #16", "ret", factory = sym factory_impl);
}
#[unsafe(naked)]
pub(super) unsafe extern "C" fn factory_return() -> ! {
    core::arch::naked_asm!("mov x1, x0", "mov x0, {op}", "mov x2, {class}",
        "mov x8, {nr_low}", "movk x8, {nr_high}, lsl #48", "svc #0", "brk #0",
        op = const abi::COMPLETE, class = const abi::INFO_CLASS,
        nr_low = const (NtService::QueryVirtualMemory.entry() & 0xffff), nr_high = const 0x4e54);
}
#[unsafe(naked)]
pub(super) unsafe extern "C" fn pe_return() -> ! {
    core::arch::naked_asm!("mov w1, w0", "mov x0, {op}", "mov x2, {class}",
        "mov x8, {nr_low}", "movk x8, {nr_high}, lsl #48", "svc #0", "brk #0",
        op = const abi::RETURN, class = const abi::INFO_CLASS,
        nr_low = const (NtService::QueryVirtualMemory.entry() & 0xffff), nr_high = const 0x4e54);
}
#[unsafe(naked)]
pub(super) unsafe extern "C" fn enter() -> u64 {
    core::arch::naked_asm!("sub sp, sp, #96", "stp d8, d9, [sp]", "stp d10, d11, [sp, #16]",
        "stp d12, d13, [sp, #32]", "stp d14, d15, [sp, #48]", "stp x18, x30, [sp, #64]",
        "mrs x9, fpcr", "mrs x10, fpsr", "stp x9, x10, [sp, #80]",
        "mov x0, {op}", "mov x2, {class}", "mov x8, {nr_low}", "movk x8, {nr_high}, lsl #48", "svc #0",
        "ldp d8, d9, [sp]", "ldp d10, d11, [sp, #16]", "ldp d12, d13, [sp, #32]", "ldp d14, d15, [sp, #48]",
        "ldp x18, x30, [sp, #64]", "ldp x9, x10, [sp, #80]", "msr fpcr, x9", "msr fpsr, x10", "add sp, sp, #96", "ret",
        op = const abi::ENTER, class = const abi::INFO_CLASS,
        nr_low = const (NtService::QueryVirtualMemory.entry() & 0xffff), nr_high = const 0x4e54);
}
