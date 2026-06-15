// ucontext x86_64 register save/restore (docs/59§6, §54). Intel syntax.
// Naked #[no_mangle] fns (see setjmp/x86_64.rs: cdylib export — raw global_asm
// symbols get localized by the version script, naked fns are exported). gregs
// live at ucp+40; slot indices (×8 bytes) are glibc REG_*: R8=0 R9=1 R12=4
// R13=5 R14=6 R15=7 RDI=8 RSI=9 RBP=10 RBX=11 RDX=12 RCX=14 RSP=15 RIP=16.
use super::{regidx, ucontext_t};

const G: usize = 40; // uc_mcontext.gregs offset within ucontext_t
const fn slot(i: usize) -> usize { G + i * 8 }

// rdi = ucp. Save callee-saved regs + caller RSP + return RIP into gregs, then
// tail-call __getcontext_post (Rust) which fills uc_sigmask and returns 0.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn getcontext(_ucp: *mut ucontext_t) -> i32 {
    core::arch::naked_asm!(
        "mov [rdi+{rbx}], rbx",
        "mov [rdi+{rbp}], rbp",
        "mov [rdi+{r12}], r12",
        "mov [rdi+{r13}], r13",
        "mov [rdi+{r14}], r14",
        "mov [rdi+{r15}], r15",
        "lea rax, [rsp+8]",            // caller RSP (past our return addr)
        "mov [rdi+{rsp}], rax",
        "mov rax, [rsp]",             // return RIP
        "mov [rdi+{rip}], rax",
        "xor eax, eax",
        "mov [rdi+{rax}], rax",        // gregs[RAX]=0 → resumed getcontext returns 0
        "jmp __getcontext_post",
        rbx = const slot(regidx::RBX),
        rbp = const slot(regidx::RBP),
        r12 = const slot(regidx::R12),
        r13 = const slot(regidx::R13),
        r14 = const slot(regidx::R14),
        r15 = const slot(regidx::R15),
        rsp = const slot(regidx::RSP),
        rip = const slot(regidx::RIP),
        rax = const slot(13), // REG_RAX
    );
}

// rdi = ucp. Restore the full integer arg + callee set, then jump to gregs[RIP]
// with gregs[RSP] installed. Used by setcontext (after the sigmask is set) and
// to launch a makecontext'd context.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __setcontext_regs(_ucp: *const ucontext_t) -> ! {
    core::arch::naked_asm!(
        "mov rbx, [rdi+{rbx}]",
        "mov rbp, [rdi+{rbp}]",
        "mov r12, [rdi+{r12}]",
        "mov r13, [rdi+{r13}]",
        "mov r14, [rdi+{r14}]",
        "mov r15, [rdi+{r15}]",
        "mov rsi, [rdi+{rsi}]",
        "mov rdx, [rdi+{rdx}]",
        "mov rcx, [rdi+{rcx}]",
        "mov r8,  [rdi+{r8}]",
        "mov r9,  [rdi+{r9}]",
        "mov rax, [rdi+{rax}]",        // resumed-getcontext return value
        "mov rsp, [rdi+{rsp}]",        // switch stack
        "push qword ptr [rdi+{rip}]",  // saved RIP onto the new stack
        "mov rdi, [rdi+{rdi}]",        // arg-1 register (last, frees rdi)
        "ret",                          // jump to RIP
        rbx = const slot(regidx::RBX),
        rbp = const slot(regidx::RBP),
        r12 = const slot(regidx::R12),
        r13 = const slot(regidx::R13),
        r14 = const slot(regidx::R14),
        r15 = const slot(regidx::R15),
        rsi = const slot(regidx::RSI),
        rdx = const slot(regidx::RDX),
        rcx = const slot(regidx::RCX),
        r8  = const slot(regidx::R8),
        r9  = const slot(regidx::R9),
        rax = const slot(13),
        rsp = const slot(regidx::RSP),
        rip = const slot(regidx::RIP),
        rdi = const slot(regidx::RDI),
    );
}

// makecontext trampoline: func returns here. uc_link was planted in r15 by
// arch_makecontext (callee-saved, survives func). If non-NULL, setcontext into
// it; else exit_group(0).
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __makecontext_ret() -> ! {
    core::arch::naked_asm!(
        "test r15, r15",
        "jz 2f",
        "mov rdi, r15",
        "call setcontext",
        "2:",
        "mov edi, 0",
        "mov eax, 231",                // __NR_exit_group
        "syscall",
    );
}

/// Lay out the new stack for makecontext (x86_64 SysV: 6 integer args in
/// registers). Aligns the stack top so that after the implicit return-addr
/// push RSP%16==0 at func entry, plants __makecontext_ret as func's return
/// address, and stashes uc_link in the gregs[R15] slot for the trampoline.
pub(super) unsafe fn arch_makecontext(ucp: *mut ucontext_t, func: extern "C" fn(), args: [usize; 6]) {
    // SAFETY: ucp is a getcontext-initialised ucontext_t; uc_stack.ss_sp is a
    // writable region of ss_size bytes. Compute a 16-aligned top, reserve one
    // word for the trampoline return address, and write the entry registers
    // into gregs so __setcontext_regs launches func correctly.
    unsafe {
        let base = (*ucp).uc_stack.ss_sp as usize;
        let size = (*ucp).uc_stack.ss_size;
        // Top of stack, 16-aligned, then minus 8 so that the planted return
        // address makes RSP%16==8 entering func and the func's own prologue
        // re-aligns (SysV: RSP%16==8 at call site / entry).
        let mut top = (base + size) & !15usize;
        top -= 8;
        let ret_slot = top as *mut usize;
        *ret_slot = __makecontext_ret as *const () as usize;
        let g = core::ptr::addr_of_mut!((*ucp).uc_mcontext.gregs) as *mut i64;
        *g.add(regidx::RSP) = top as i64;
        *g.add(regidx::RIP) = func as *const () as i64;
        *g.add(regidx::RDI) = args[0] as i64;
        *g.add(regidx::RSI) = args[1] as i64;
        *g.add(regidx::RDX) = args[2] as i64;
        *g.add(regidx::RCX) = args[3] as i64;
        *g.add(regidx::R8) = args[4] as i64;
        *g.add(regidx::R9) = args[5] as i64;
        *g.add(regidx::R15) = (*ucp).uc_link as i64; // trampoline reads uc_link
    }
}
