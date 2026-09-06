use super::{abi, NtService};

pub(super) unsafe extern "win64" fn factory(request: *const abi::FactoryRequest) -> u64 {
    // SAFETY: native factory entry uses the Windows ABI and preserves its
    // nonvolatile GPR/XMM set around the native SysV libc implementation.
    unsafe { super::super::native::factory(request) }
}

#[unsafe(naked)]
pub(super) unsafe extern "C" fn factory_return() -> ! {
    core::arch::naked_asm!("mov rsi, rax", "mov rdi, {op}", "mov rdx, {class}",
        "xor r10d, r10d", "xor r8d, r8d", "xor r9d, r9d", "mov rax, {nr}", "syscall", "ud2",
        op = const abi::COMPLETE, class = const abi::INFO_CLASS, nr = const NtService::QueryVirtualMemory.entry());
}

#[unsafe(naked)]
pub(super) unsafe extern "C" fn pe_return() -> ! {
    core::arch::naked_asm!("mov esi, eax", "mov rdi, {op}", "mov rdx, {class}",
        "xor r10d, r10d", "xor r8d, r8d", "xor r9d, r9d", "mov rax, {nr}", "syscall", "ud2",
        op = const abi::RETURN, class = const abi::INFO_CLASS, nr = const NtService::QueryVirtualMemory.entry());
}

#[unsafe(naked)]
pub(super) unsafe extern "C" fn enter() -> u64 {
    core::arch::naked_asm!("sub rsp, 16", "stmxcsr [rsp]", "fnstcw [rsp + 4]",
        "mov rdi, {op}", "xor esi, esi", "mov rdx, {class}", "xor r10d, r10d",
        "xor r8d, r8d", "xor r9d, r9d", "mov rax, {nr}", "syscall",
        "cld", "ldmxcsr [rsp]", "fldcw [rsp + 4]", "add rsp, 16", "ret",
        op = const abi::ENTER, class = const abi::INFO_CLASS, nr = const NtService::QueryVirtualMemory.entry());
}
