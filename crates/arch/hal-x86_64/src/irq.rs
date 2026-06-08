// Per-vector IRQ entry stubs per `22§4` + IRQ-exit preemption epilogue
// per `14§R07`.
//
// Distinct from the fault stubs (`fault.rs`): IRQ stubs save the
// scratch registers, call the Rust dispatcher, optionally switch
// tasks at the tail, then `iretq` back to whatever task we end up
// resuming. The dispatcher does the EOI dance.
//
// The IRQ epilogue (pop scratch + drop synthetic vec/err + iretq)
// is factored into a dedicated symbol `oxide_irq_resume_user` so a
// freshly-built task built via `Context::new_kernel_with_irq_frame`
// can store its address as the saved-RIP at the bottom of the
// scaffold; `oxide_context_switch`'s `ret` then lands in the
// epilogue continuation.
//
// Phase-1 scope: a single timer vector (0x40). Wider IRQ table
// rides alongside scheduler bring-up.

// F410 (Stage B): the per-vector stub body is written ONCE via a GAS
// `.macro`. Each stub = `oxide_irq_stub <vec>, <local-id>`. The stub:
//   1. pushes synthetic err(0) + vec tag,
//   2. pushes the 9 scratch GPRs (rax,rcx,rdx,rsi,rdi,r8,r9,r10,r11),
//   3. pushes the 6 callee-saved GPRs (rbx,rbp,r12,r13,r14,r15) so the
//      full interrupted GP set is captured for a future signal mcontext,
//   4. calls the Rust dispatcher with rdi = &frame,
//   5. runs the `14§R07` schedule-on-exit switch dance,
//   6. jmps the shared epilogue which pops in reverse + iretq.
//
// Stack frame at `mov rdi,rsp` (offsets from rsp, low→high):
//   +0x00 r15  +0x08 r14  +0x10 r13  +0x18 r12  +0x20 rbp  +0x28 rbx
//   +0x30 r11  +0x38 r10  +0x40 r9   +0x48 r8   +0x50 rdi  +0x58 rsi
//   +0x60 rdx  +0x68 rcx  +0x70 rax  +0x78 vec  +0x80 err
//   +0x88 RIP  +0x90 CS   +0x98 RFLAGS  +0xA0 RSP  +0xA8 SS
// (vec tag moved from +0x48 to +0x78 vs pre-F410 — see oxide_irq_dispatch.)
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text",

    // ----- shared per-vector stub macro -----------------------------------
    ".macro oxide_irq_stub vec, id",
    "    push 0",                  // synthetic err code (IRQs don't push one)
    "    push \\vec",               // vector tag
    // 9 scratch GPRs.
    "    push rax", "    push rcx", "    push rdx",
    "    push rsi", "    push rdi",
    "    push r8",  "    push r9",  "    push r10", "    push r11",
    // 6 callee-saved GPRs (closest to rsp) — full GP set for Stage C/E.
    "    push rbx", "    push rbp",
    "    push r12", "    push r13", "    push r14", "    push r15",
    "    cld",
    "    mov rdi, rsp",            // arg 0 = pointer to saved frame
    "    call oxide_irq_dispatch",
    // schedule-on-exit per `14§R07`. Rust dispatcher writes
    // `oxide_preempt_next_ctx` if a switch is wanted; null = stay.
    "    mov  rax, gs:[8]",        // per-CPU NEXT-ctx staging slot
    "    test rax, rax",
    "    jz   90\\id\\()f",
    "    mov  rdi, gs:[16]",       // per-CPU CUR-ctx staging slot (prev)
    "    mov  rsi, rax",
    "    mov  gs:[16], rax",       // CUR := NEXT (commit)
    "    mov  qword ptr gs:[8], 0", // clear NEXT slot
    "    call oxide_context_switch",
    // shared resume label. Both no-switch (jz) and post-switch
    // (oxide_context_switch's `ret` on the new task's stack) drop here.
    "90\\id\\(): jmp oxide_irq_resume_user",
    ".endm",

    // ----- per-vector stubs (one macro expansion each) --------------------
    ".globl oxide_irq_vec_40", ".type oxide_irq_vec_40, @function",
    "oxide_irq_vec_40:", "    oxide_irq_stub 0x40, 40",
    ".size oxide_irq_vec_40, . - oxide_irq_vec_40",

    // vec 0x41 -- cross-CPU resched IPI per `13§9`. Dispatcher
    // differentiates by reading the saved vec tag.
    ".globl oxide_irq_vec_41", ".type oxide_irq_vec_41, @function",
    "oxide_irq_vec_41:", "    oxide_irq_stub 0x41, 41",
    ".size oxide_irq_vec_41, . - oxide_irq_vec_41",

    // vec 0x50 -- MSI vector (F57); dispatcher bumps MSI_FIRES.
    ".globl oxide_irq_vec_50", ".type oxide_irq_vec_50, @function",
    "oxide_irq_vec_50:", "    oxide_irq_stub 0x50, 50",
    ".size oxide_irq_vec_50, . - oxide_irq_vec_50",

    // vec 0x51..0x57 -- MSI pool (F58); routed by the saved vec tag.
    ".globl oxide_irq_vec_51", ".type oxide_irq_vec_51, @function",
    "oxide_irq_vec_51:", "    oxide_irq_stub 0x51, 51",
    ".size oxide_irq_vec_51, . - oxide_irq_vec_51",

    ".globl oxide_irq_vec_52", ".type oxide_irq_vec_52, @function",
    "oxide_irq_vec_52:", "    oxide_irq_stub 0x52, 52",
    ".size oxide_irq_vec_52, . - oxide_irq_vec_52",

    ".globl oxide_irq_vec_53", ".type oxide_irq_vec_53, @function",
    "oxide_irq_vec_53:", "    oxide_irq_stub 0x53, 53",
    ".size oxide_irq_vec_53, . - oxide_irq_vec_53",

    ".globl oxide_irq_vec_54", ".type oxide_irq_vec_54, @function",
    "oxide_irq_vec_54:", "    oxide_irq_stub 0x54, 54",
    ".size oxide_irq_vec_54, . - oxide_irq_vec_54",

    ".globl oxide_irq_vec_55", ".type oxide_irq_vec_55, @function",
    "oxide_irq_vec_55:", "    oxide_irq_stub 0x55, 55",
    ".size oxide_irq_vec_55, . - oxide_irq_vec_55",

    ".globl oxide_irq_vec_56", ".type oxide_irq_vec_56, @function",
    "oxide_irq_vec_56:", "    oxide_irq_stub 0x56, 56",
    ".size oxide_irq_vec_56, . - oxide_irq_vec_56",

    ".globl oxide_irq_vec_57", ".type oxide_irq_vec_57, @function",
    "oxide_irq_vec_57:", "    oxide_irq_stub 0x57, 57",
    ".size oxide_irq_vec_57, . - oxide_irq_vec_57",

    // ----- shared IRQ epilogue --------------------------------------------
    // Globally addressable so `Context::new_kernel_with_irq_frame`
    // can park its address as the saved-RIP at scaffold base. Pops in
    // exact reverse of the push order: callee-saved first, then scratch.
    ".globl oxide_irq_resume_user",
    ".type  oxide_irq_resume_user, @function",
    "oxide_irq_resume_user:",
    "    pop r15", "    pop r14", "    pop r13", "    pop r12",
    "    pop rbp", "    pop rbx",
    "    pop r11", "    pop r10", "    pop r9", "    pop r8",
    "    pop rdi", "    pop rsi",
    "    pop rdx", "    pop rcx", "    pop rax",
    "    add rsp, 16",              // drop our vec + err
    "    iretq",
    ".size oxide_irq_resume_user, . - oxide_irq_resume_user",
);

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_irq_vec_40();
    fn oxide_irq_vec_41();
    fn oxide_irq_vec_50();
    fn oxide_irq_vec_51();
    fn oxide_irq_vec_52();
    fn oxide_irq_vec_53();
    fn oxide_irq_vec_54();
    fn oxide_irq_vec_55();
    fn oxide_irq_vec_56();
    fn oxide_irq_vec_57();
    fn oxide_irq_resume_user() -> !;
}

/// LAPIC timer vector (`22§4`).
pub const VEC_TIMER:   u8 = 0x40;
/// Cross-CPU resched IPI vector per `13§9`.
pub const VEC_RESCHED: u8 = 0x41;
/// MSI delivery vector (F57). Legacy alias for the first slot in
/// the per-vector pool. Kept so existing callers compile; new code
/// should call `alloc_x86_vector` and use the returned vector.
pub const VEC_MSI:     u8 = 0x50;

/// First / last vector in the per-vector MSI pool (F58). Each
/// device's MSI-X table entry gets a distinct vector in this range;
/// the arch-irq dispatcher routes each vector to its registered
/// handler via the per-vector table.
pub const VEC_MSI_POOL_FIRST: u8 = 0x50;
pub const VEC_MSI_POOL_LAST:  u8 = 0x57;
pub const VEC_MSI_POOL_LEN: usize =
    (VEC_MSI_POOL_LAST as usize) - (VEC_MSI_POOL_FIRST as usize) + 1;

/// Address of the IRQ stub for `vec`, or `0` if no IRQ stub is
/// registered for that vector (caller falls back to fault stub).
/// # C: O(1)
pub fn irq_stub_addr(vec: u8) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        match vec {
            VEC_TIMER   => return oxide_irq_vec_40 as *const () as usize as u64,
            VEC_RESCHED => return oxide_irq_vec_41 as *const () as usize as u64,
            0x50 => return oxide_irq_vec_50 as *const () as usize as u64,
            0x51 => return oxide_irq_vec_51 as *const () as usize as u64,
            0x52 => return oxide_irq_vec_52 as *const () as usize as u64,
            0x53 => return oxide_irq_vec_53 as *const () as usize as u64,
            0x54 => return oxide_irq_vec_54 as *const () as usize as u64,
            0x55 => return oxide_irq_vec_55 as *const () as usize as u64,
            0x56 => return oxide_irq_vec_56 as *const () as usize as u64,
            0x57 => return oxide_irq_vec_57 as *const () as usize as u64,
            _ => {}
        }
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { let _ = vec; }
    0
}

/// Full general-purpose register set saved at IRQ entry (F410
/// Stage B). Field order MIRRORS the asm push order exactly: the
/// `.macro oxide_irq_stub` pushes (top→bottom of stack) err, vec,
/// then rax..r11 (scratch), then rbx,rbp,r12..r15 (callee-saved).
/// Since the stack grows DOWN, the LAST-pushed reg (r15) sits at the
/// lowest address = offset 0 from the frame pointer. The CPU's iretq
/// frame (rip/cs/rflags/rsp/ss) sits above err.
///
/// Stage C/E reads the interrupted GP set + `cs & 3 == 3` (user) to
/// build a signal mcontext from a timer-interrupted user thread.
#[repr(C)]
#[derive(Copy, Clone, Debug, Default)]
pub struct IrqFrameX86 {
    pub r15:    u64, // +0x00
    pub r14:    u64, // +0x08
    pub r13:    u64, // +0x10
    pub r12:    u64, // +0x18
    pub rbp:    u64, // +0x20
    pub rbx:    u64, // +0x28
    pub r11:    u64, // +0x30
    pub r10:    u64, // +0x38
    pub r9:     u64, // +0x40
    pub r8:     u64, // +0x48
    pub rdi:    u64, // +0x50
    pub rsi:    u64, // +0x58
    pub rdx:    u64, // +0x60
    pub rcx:    u64, // +0x68
    pub rax:    u64, // +0x70
    pub vec:    u64, // +0x78
    pub err:    u64, // +0x80
    pub rip:    u64, // +0x88  (CPU iretq frame)
    pub cs:     u64, // +0x90
    pub rflags: u64, // +0x98
    pub rsp:    u64, // +0xA0
    pub ss:     u64, // +0xA8
}

/// Pointer to the IRQ frame of the IRQ currently being dispatched.
/// Written by `oxide_irq_dispatch` on every IRQ (analogous to how
/// `OXIDE_SYSCALL_KSTACK` locates the syscall frame). UP v1 single
/// slot; per-CPU once SMP needs concurrent IRQ-frame reads.
#[no_mangle]
pub static OXIDE_IRQ_FRAME: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Pointer to the GP register set saved at entry of the IRQ currently
/// being serviced, or null if no IRQ is in flight. Analogous to
/// `current_user_frame()`. Stage C/E reads interrupted GPRs +
/// `(*frame).cs & 3 == 3` from this.
/// # SAFETY: caller runs inside the IRQ dispatch path (or with the
/// IRQ frame still live on the kernel stack); the pointer is stale the
/// moment `oxide_irq_resume_user` pops the frame.
/// # C: O(1)
pub unsafe fn current_irq_frame() -> *mut IrqFrameX86 {
    #[cfg(target_arch = "x86_64")]
    { OXIDE_IRQ_FRAME.load(core::sync::atomic::Ordering::Acquire) as *mut IrqFrameX86 }
    #[cfg(not(target_arch = "x86_64"))]
    { core::ptr::null_mut() }
}

/// Address of the shared IRQ epilogue (`oxide_irq_resume_user`),
/// the saved-RIP value `Context::new_kernel_with_irq_frame` parks
/// at scaffold base. Returns 0 on host (asm symbol absent).
/// # C: O(1)
pub fn irq_resume_user_addr() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    { oxide_irq_resume_user as *const () as usize as u64 }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    { 0 }
}
