use syscall::{nt::NtService, nt_native_gdi as abi};

pub(super) unsafe extern "win64" fn callback(request: *const abi::TextRequest) -> u64 {
    // SAFETY: Windows ABI wrapper preserves nonvolatile GPR/XMM around native libc/fontdue.
    unsafe { super::super::native::callback(request) }
}
#[unsafe(naked)]
pub(super) unsafe extern "C" fn complete() -> ! {
    core::arch::naked_asm!("mov rsi, rax", "mov rdi, {op}", "mov rdx, {class}",
        "xor r10d, r10d", "xor r8d, r8d", "xor r9d, r9d", "mov rax, {nr}", "syscall", "ud2",
        op = const abi::COMPLETE, class = const abi::INFO_CLASS, nr = const NtService::QueryVirtualMemory.entry());
}
