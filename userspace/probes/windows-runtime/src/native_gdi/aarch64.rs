use syscall::{nt::NtService, nt_native_gdi as abi};

unsafe extern "C" fn invoke(request: *const abi::TextRequest) -> u64 {
    // SAFETY: kernel supplies bounded copied request on current native thread's stack.
    unsafe { super::super::native::callback(request) }
}
#[unsafe(naked)]
pub(super) unsafe extern "C" fn callback() -> u64 {
    core::arch::naked_asm!("stp x18, x30, [sp, #-16]!", "bl {invoke}", "ldp x18, x30, [sp], #16", "ret", invoke = sym invoke);
}
#[unsafe(naked)]
pub(super) unsafe extern "C" fn complete() -> ! {
    core::arch::naked_asm!("mov x1, x0", "mov x0, {op}", "mov x2, {class}",
        "mov x8, {nr}", "movk x8, {tag}, lsl #48", "svc #0", "brk #0",
        op = const abi::COMPLETE, class = const abi::INFO_CLASS,
        nr = const (NtService::QueryVirtualMemory.entry() & 0xffff), tag = const 0x4e54);
}
