// ucontext aarch64 register save/restore (docs/59§6, §54). Naked #[no_mangle]
// fns (see setjmp/aarch64.rs: cdylib export). Layout (host glibc): uc_mcontext
// @176; within it fault@0, regs[31]@8, sp@256, pc@264, pstate@272,
// __reserved@280 (fpsimd_context: head@0, fpsr@8, fpcr@12, vregs[32]@16, each
// 16 bytes — d8..d15 are the low halves of vregs[8..15]).
// Absolute byte offsets within ucontext_t:
//   regs[n] = 184 + 8n ; sp = 432 ; pc = 440 ; d_n low = 472 + 16n.
use super::ucontext_t;

const REGS: usize = 184; // ucontext + uc_mcontext(176) + regs(8)
const SP: usize = 432;
const PC: usize = 440;
const VREGS: usize = 472; // fpsimd_context.vregs[0] low half
const fn r(n: usize) -> usize { REGS + n * 8 }
const fn d(n: usize) -> usize { VREGS + n * 16 }

// x0 = ucp. Save callee-saved x19..x30, sp, the return pc (lr), and d8..d15
// into uc_mcontext, then tail-call __getcontext_post which fills uc_sigmask and
// returns 0. x0 (resumed-return value slot) is set so a resumed getcontext
// returns 0.
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn getcontext(_ucp: *mut ucontext_t) -> i32 {
    core::arch::naked_asm!(
        "stp x18, x19, [x0, #{r18}]",
        "stp x20, x21, [x0, #{r20}]",
        "stp x22, x23, [x0, #{r22}]",
        "stp x24, x25, [x0, #{r24}]",
        "stp x26, x27, [x0, #{r26}]",
        "stp x28, x29, [x0, #{r28}]",
        "str x30, [x0, #{r30}]",      // lr → regs[30] (resume pc)
        "str x30, [x0, #{pc}]",       // pc field = return address too
        "mov x2, sp",
        "str x2, [x0, #{sp}]",
        "str xzr, [x0, #{r0}]",        // regs[0]=0 → resumed getcontext returns 0
        // d8..d15 → vregs[8..15] (low halves, each 16 bytes apart). The base
        // offset (600) exceeds the ldp/stp imm range [-512,504], so address
        // via a scratch base (x1, caller-saved — not preserved by getcontext)
        // and `str` each at its true 16-spaced offset (stp would pack them 8
        // apart, corrupting the odd vregs).
        "add x1, x0, #{vd8}",
        "str d8,  [x1]",
        "str d9,  [x1, #16]",
        "str d10, [x1, #32]",
        "str d11, [x1, #48]",
        "str d12, [x1, #64]",
        "str d13, [x1, #80]",
        "str d14, [x1, #96]",
        "str d15, [x1, #112]",
        "b __getcontext_post",
        r18 = const r(18),
        r20 = const r(20),
        r22 = const r(22),
        r24 = const r(24),
        r26 = const r(26),
        r28 = const r(28),
        r30 = const r(30),
        pc  = const PC,
        sp  = const SP,
        r0  = const r(0),
        vd8 = const d(8),
    );
}

// x0 = ucp. Restore the integer arg + callee set, sp, fp regs, then branch to
// regs[30] (pc). Used by setcontext and to launch a makecontext'd context
// (args in x0..x5, entry pc in regs[30], uc_link trampoline target prearmed).
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __setcontext_regs(_ucp: *const ucontext_t) -> ! {
    core::arch::naked_asm!(
        "ldp x18, x19, [x0, #{r18}]",
        "ldp x20, x21, [x0, #{r20}]",
        "ldp x22, x23, [x0, #{r22}]",
        "ldp x24, x25, [x0, #{r24}]",
        "ldp x26, x27, [x0, #{r26}]",
        "ldp x28, x29, [x0, #{r28}]",
        "ldr x30, [x0, #{r30}]",       // lr (return target / makecontext trampoline)
        "ldr x16, [x0, #{pc}]",        // branch target pc (== lr on resume)
        "ldr x2, [x0, #{sp}]",
        "mov sp, x2",
        // d8..d15 ← vregs[8..15] (16-spaced); base offset > ldp imm range, so
        // address via x1 scratch + `ldr` each (x1 is reloaded from r1 below).
        "add x1, x0, #{vd8}",
        "ldr d8,  [x1]",
        "ldr d9,  [x1, #16]",
        "ldr d10, [x1, #32]",
        "ldr d11, [x1, #48]",
        "ldr d12, [x1, #64]",
        "ldr d13, [x1, #80]",
        "ldr d14, [x1, #96]",
        "ldr d15, [x1, #112]",
        "ldp x2, x3, [x0, #{r2}]",
        "ldp x4, x5, [x0, #{r4}]",
        "ldr x1, [x0, #{r1}]",
        "ldr x0, [x0, #{r0}]",          // arg-0 / resumed return value (last)
        "br x16",
        r18 = const r(18),
        r20 = const r(20),
        r22 = const r(22),
        r24 = const r(24),
        r26 = const r(26),
        r28 = const r(28),
        r30 = const r(30),
        pc  = const PC,
        sp  = const SP,
        vd8 = const d(8),
        r2  = const r(2),
        r4  = const r(4),
        r1  = const r(1),
        r0  = const r(0),
    );
}

// makecontext trampoline: func returns here via lr. uc_link was placed in x28
// (callee-saved) by arch_makecontext. If non-NULL, setcontext into it; else
// exit_group(0).
#[unsafe(naked)]
#[no_mangle]
pub unsafe extern "C" fn __makecontext_ret() -> ! {
    core::arch::naked_asm!(
        "cbz x28, 2f",
        "mov x0, x28",
        "bl setcontext",
        "2:",
        "mov x0, #0",
        "mov x8, #94",                 // __NR_exit_group
        "svc #0",
    );
}

/// Lay out the new stack for makecontext (aarch64 AAPCS: first 8 integer args
/// in x0..x7; we pass up to 6). 16-aligned SP; entry pc in regs[30]; lr (the
/// return target after func) set so func returns into __makecontext_ret; uc_link
/// stashed in regs[28] (callee-saved) for the trampoline.
pub(super) unsafe fn arch_makecontext(ucp: *mut ucontext_t, func: extern "C" fn(), args: [usize; 6]) {
    // SAFETY: ucp is a getcontext-initialised ucontext_t; uc_stack.ss_sp is a
    // writable region of ss_size bytes. Compute a 16-aligned SP and write the
    // entry registers into uc_mcontext so __setcontext_regs launches func.
    unsafe {
        let base = (*ucp).uc_stack.ss_sp as usize;
        let size = (*ucp).uc_stack.ss_size;
        let top = (base + size) & !15usize;
        let regs = core::ptr::addr_of_mut!((*ucp).uc_mcontext.regs) as *mut u64;
        *regs.add(0) = args[0] as u64;
        *regs.add(1) = args[1] as u64;
        *regs.add(2) = args[2] as u64;
        *regs.add(3) = args[3] as u64;
        *regs.add(4) = args[4] as u64;
        *regs.add(5) = args[5] as u64;
        *regs.add(28) = (*ucp).uc_link as u64;          // trampoline reads x28
        *regs.add(30) = __makecontext_ret as *const () as u64; // lr → trampoline
        (*ucp).uc_mcontext.sp = top as u64;
        (*ucp).uc_mcontext.pc = func as *const () as u64;
    }
}
