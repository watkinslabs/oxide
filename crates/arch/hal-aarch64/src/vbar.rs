// aarch64 EL1 vector table install per `22§5`.
//
// VMSAv8 mandates a 16-entry table at `VBAR_EL1`; each entry is
// 0x80 bytes. Layout per ARM ARM D1.10 Tab. D1-7:
//   0x000 Sync           current EL with SP_EL0
//   0x080 IRQ            current EL with SP_EL0
//   0x100 FIQ            current EL with SP_EL0
//   0x180 SError         current EL with SP_EL0
//   0x200 Sync           current EL with SP_ELx
//   0x280 IRQ            current EL with SP_ELx
//   0x300 FIQ            current EL with SP_ELx
//   0x380 SError         current EL with SP_ELx
//   0x400 Sync           lower EL using AArch64
//   0x480 IRQ            lower EL using AArch64
//   0x500 FIQ            lower EL using AArch64
//   0x580 SError         lower EL using AArch64
//   0x600 Sync           lower EL using AArch32
//   0x680 IRQ            lower EL using AArch32
//   0x700 FIQ            lower EL using AArch32
//   0x780 SError         lower EL using AArch32
//
// v1 lands the data path: a default-vector handler that prints
// (ESR/FAR/ELR) + halts for unexpected synchronous/SError/FIQ paths,
// and an IRQ handler at slot 0x280 ("Current EL with SP_ELx, IRQ")
// that saves caller-save GP regs, calls a Rust dispatcher, and
// `eret`s. Per-cause sync dispatch (`ESR.EC` decode → SVC syscall /
// IABT/DABT page fault) rides alongside scheduler bring-up.

/// Vector table is exactly 16 × 0x80 = 0x800 bytes per ARM ARM.
pub const VECTOR_TABLE_SIZE: usize = 0x800;

/// Per-entry stride.
pub const VECTOR_ENTRY_BYTES: usize = 0x80;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
mod asm;

#[path = "vbar_sysreg.rs"]
mod sysreg;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    static oxide_vector_table: u8;
}

/// Saved-SVC-frame base, written by the lower-EL sync handler asm
/// before `bl oxide_syscall_dispatch`. `current_svc_frame()` reads
/// it to expose the saved x0..x29, ELR_EL1, SPSR_EL1, SP_EL0, x0
/// retval slots to syscall handlers that need to redirect post-eret
/// state (sys_execve overwrites ELR_EL1 + SP_EL0 to land at the new
/// program entry; sys_fork copies the parent's saved regs into the
/// child's iretq-equivalent frame).
///
/// Per-CPU SVC-frame base offset within the per-CPU area (the page
/// `TPIDR_EL1` points at). Must match the `[x9, #24]` stores in the SVC
/// save blocks above. Per-CPU area layout: `cpu_id@0`, preempt
/// `next@8`/`cur@16` (sched/live/preempt.rs), SVC frame `@24`. SMP-safe:
/// each CPU stores/reads its own slot, so concurrent syscalls on two CPUs
/// never clobber each other's frame pointer (the SP_EL0-poison bug).
const PERCPU_SVC_FRAME_OFF: usize = 24;
/// Per-CPU IRQ-stack top offset within the per-CPU area (F699). Next free slot
/// after `cpu_id@0`, preempt `next@8`/`cur@16`, SVC-frame`@24`. Must match the
/// `ldr x10, [x9, #32]` in `oxide_irq_vector_handler`. 0 = unarmed (pre-init) ⇒
/// the IRQ dispatcher runs on the interrupted stack (safe; only reached before
/// IRQs are unmasked at boot).
const PERCPU_IRQ_STACK_TOP_OFF: usize = 32;

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
core::arch::global_asm!(
    ".section .text.oxide_arm_call_on_irq_stack,\"ax\"",
    ".global oxide_arm_call_on_irq_stack",
    ".type oxide_arm_call_on_irq_stack, %function",
    "oxide_arm_call_on_irq_stack:",
    // Match Linux arm64's call_on_irq_stack(): only the frame record is
    // created on the interrupted stack before moving to the per-CPU IRQ
    // stack. Saving four callee-saved registers here used 48 bytes at the
    // worst possible point — after a deep task path had already consumed
    // nearly all of its 16 KiB — and the first store itself could cross the
    // guard page.
    "    stp  x29, x30, [sp, #-16]!",
    "    mov  x29, sp",
    // Keep hardware IRQs masked while the callback owns the shared IRQ stack.
    // x9 and x16/x17 are caller-saved scratch; the original DAIF and task SP
    // are saved on the stack that remains live across the callback.
    "    mrs  x9, daif",
    "    msr  daifset, #2",
    "    mrs  x16, tpidr_el1",
    "    cbz  x16, 2f",
    "    ldr  x17, [x16, #32]",
    "    cbz  x17, 2f",
    "    sub  x16, x17, #{stack_bytes}",
    "    cmp  sp, x16",
    "    b.lo 1f",
    "    cmp  sp, x17",
    "    b.lo 2f",
    "1:",
    "    mov  x16, sp",
    "    mov  sp, x17",
    "    sub  sp, sp, #16",
    "    stp  x9, x16, [sp]",
    "    blr  x0",
    "    ldp  x9, x16, [sp]",
    "    add  sp, sp, #16",
    "    mov  sp, x16",
    "    b    3f",
    "2:",
    "    sub  sp, sp, #16",
    "    str  x9, [sp]",
    "    blr  x0",
    "    ldr  x9, [sp]",
    "    add  sp, sp, #16",
    "3:",
    "    msr  daif, x9",
    "    ldp  x29, x30, [sp], #16",
    "    ret",
    ".size oxide_arm_call_on_irq_stack, . - oxide_arm_call_on_irq_stack",
    stack_bytes = const hal::KERNEL_STACK_BYTES,
);

/// Run one non-sleeping callback on this CPU's per-CPU IRQ stack.
///
/// Linux arm64 uses `call_on_irq_stack()` for process-context softirq drains.
/// Staying on the task stack would add the complete NET_RX tree to an already
/// deep syscall or fault frame. If early boot has not armed the stack, or the
/// caller is already on it, the callback runs in place.
/// # SAFETY: `callback` must not sleep and must preserve its C ABI contract.
/// # C: O(callback)
pub unsafe fn call_on_irq_stack(callback: unsafe extern "C" fn()) {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    // SAFETY: the caller guarantees a non-sleeping C callback; the trampoline
    // preserves callee-saved state, restores SP, and restores the saved DAIF.
    unsafe {
        unsafe extern "C" {
            fn oxide_arm_call_on_irq_stack(callback: unsafe extern "C" fn());
        }
        oxide_arm_call_on_irq_stack(callback);
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    // SAFETY: hosted builds have no IRQ stack, so forwarding preserves the
    // caller's callback contract without changing architectural state.
    unsafe {
        callback();
    }
}
/// Per-CPU bounds of the CURRENT task's kernel stack for the entry asm's
/// bad-stack check (Linux `kernel_ventry` → `__bad_stack`). Only the top is
/// stored; the low bound is `top - KSTACK_BYTES`. 0 = unarmed, disabling the
/// check — correct for boot/AP stacks and the idle task, none of which are slots.
/// Must match `[x0, #40]` in the entry asm.
const PERCPU_KSTACK_TOP_OFF: usize = 40;
/// Per-CPU scratch the entry asm stashes x1 in across the check (x0 goes to
/// `TPIDRRO_EL0`). Two scratch regs are needed to compare SP against a pair of
/// bounds, and nothing may be pushed — SP is the value in doubt.
/// Must match `[x0, #48]` in the entry asm.
// Per-CPU-area offset table: slot 48 is asm-private scratch, so unlike its
// neighbours it has no Rust accessor. Kept so the table stays complete and the
// next slot allocation does not silently reuse it.
#[allow(dead_code, reason = "per-CPU area offset table entry; slot 48 is written only by the entry asm (`str x1, [x0, #48]`), so no Rust caller exists by design")]
const PERCPU_BADSTK_SCRATCH_OFF: usize = 48;
/// Per-CPU overflow-stack top the bad-stack path switches to before reporting.
/// 0 = unarmed ⇒ the check falls through rather than jumping to a null SP.
/// Must match `[x1, #56]` in the entry asm.
const PERCPU_OVERFLOW_TOP_OFF: usize = 56;


/// Read this CPU's per-CPU area base (`TPIDR_EL1`).
/// # SAFETY: boot/ap_main set TPIDR_EL1 to a ≥4 KiB per-CPU page; EL1-only.
/// # C: O(1)
#[inline]
fn percpu_base() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let b: u64;
        // SAFETY: mrs tpidr_el1 reads this CPU's per-CPU area base.
        unsafe { core::arch::asm!("mrs {b}, tpidr_el1", b = out(reg) b, options(nomem, nostack, preserves_flags)); }
        b
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Layout of the saved SVC frame at `oxide_svc_frame_base` per the
/// asm in `oxide_lower_el_sync_handler`. Offsets in u64 words from
/// the base:
///   [0..30]   x0..x29 (with x18..x29 sharing slot 18..29 — the
///             stp pair stored x18,x29 at offset 0x90 = idx 18; we
///             treat x29 as idx 19 for accessor convenience by
///             splitting that pair when needed)
///   [20]      x30 (lr) at offset 0xa0
///   [22]      ELR_EL1 at offset 0xb0
///   [23]      SPSR_EL1 at offset 0xb8
///   [24]      SP_EL0 at offset 0xc0
///   [25]      retval (x0 after dispatch) at offset 0xc8
///
/// The frame is 36 x 8 = 288 bytes. Every field offset is pinned below because
/// the assembly addresses these slots directly.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct SvcFrame {
    pub gp:        [u64; 18],   // x0..x17                     (offsets 0x00..0x90)
    pub x18_x29:   [u64; 2],    // [x18, x29] — packed by stp  (offset 0x90..0xa0)
    pub x30:       u64,         //                              (offset 0xa0)
    pub _pad_x30:  u64,         //                              (offset 0xa8)
    pub elr_el1:   u64,         //                              (offset 0xb0)
    pub spsr_el1:  u64,         //                              (offset 0xb8)
    pub sp_el0:    u64,         //                              (offset 0xc0)
    pub retval:    u64,         //                              (offset 0xc8)
    pub x19_x28:   [u64; 10],   // x19..x28                     (offset 0xd0..0x120)
}

impl SvcFrame {
    /// Install the architecturally clean EL0 register state for exec.
    /// # C: O(1)
    pub fn install_exec_state(&mut self, pc: u64, sp: u64) {
        // Exec replaces the complete user register image; retaining syscall
        // arguments or callee-saved state crosses an image boundary and lets
        // the dynamic linker inherit invalid state.
        self.gp = [0; 18];
        self.x18_x29 = [0; 2];
        self.x30 = 0;
        self._pad_x30 = 0;
        self.elr_el1 = pc;
        self.spsr_el1 = 0;
        self.sp_el0 = sp;
        self.retval = 0;
        self.x19_x28 = [0; 10];
    }
}

const _: () = {
    assert!(core::mem::offset_of!(SvcFrame, gp) == 0x00);
    assert!(core::mem::offset_of!(SvcFrame, x18_x29) == 0x90);
    assert!(core::mem::offset_of!(SvcFrame, x30) == 0xa0);
    assert!(core::mem::offset_of!(SvcFrame, _pad_x30) == 0xa8);
    assert!(core::mem::offset_of!(SvcFrame, elr_el1) == 0xb0);
    assert!(core::mem::offset_of!(SvcFrame, spsr_el1) == 0xb8);
    assert!(core::mem::offset_of!(SvcFrame, sp_el0) == 0xc0);
    assert!(core::mem::offset_of!(SvcFrame, retval) == 0xc8);
    assert!(core::mem::offset_of!(SvcFrame, x19_x28) == 0xd0);
    assert!(core::mem::size_of::<SvcFrame>() == 0x120);
};

/// Pointer to the active task's saved SVC frame, or null pre-first-syscall.
/// # SAFETY: caller is `oxide_syscall_dispatch` running on the active
/// task's per-task kernel stack; the asm prologue stored sp into
/// `oxide_svc_frame_base` before the dispatcher's `bl`. Single-CPU UP.
/// # C: O(1)
pub fn current_svc_frame() -> *mut SvcFrame {
    let base = percpu_base();
    if base == 0 { return core::ptr::null_mut(); }
    // SAFETY: per-CPU area is ≥4 KiB; slot @24 holds this CPU's live SVC
    // frame base (stored by the SVC asm save block on entry).
    unsafe { core::ptr::read_volatile((base as usize + PERCPU_SVC_FRAME_OFF) as *const u64) as *mut SvcFrame }
}

/// F205: explicitly restore the per-CPU SVC-frame pointer. The
/// dispatch tail snapshots this at entry and re-installs before
/// signal delivery so a `schedule()`-driven race that updates the
/// global to another task's frame doesn't corrupt our handler
/// setup. Single-CPU UP only.
/// # SAFETY: caller is the dispatch tail; `frame_base` must equal
/// the live SP at our SVC save block (i.e. the value the asm
/// stored at entry).
/// # C: O(1)
pub fn set_current_svc_frame(frame_base: u64) {
    let base = percpu_base();
    if base == 0 { return; }
    // SAFETY: per-CPU area slot @24; sole writer is this CPU.
    unsafe { core::ptr::write_volatile((base as usize + PERCPU_SVC_FRAME_OFF) as *mut u64, frame_base); }
}

/// Publish this CPU's IRQ-stack top (F699) into its per-CPU area slot `@32`,
/// read by `oxide_irq_vector_handler` to relocate the IRQ dispatcher +
/// `do_softirq` re-entry off the interrupted task kstack. `top` = 16-aligned
/// high end of a guard-paged 16 KiB stack (`sched::kstack::alloc_leaked_top`).
/// Call during BSP/AP bring-up, after `set_percpu_base`, BEFORE unmasking IRQs.
/// # SAFETY: `TPIDR_EL1` set to this CPU's ≥4 KiB per-CPU page; sole writer is
/// this CPU during its own bring-up.
/// # C: O(1)
pub fn set_irq_stack_top(top: u64) {
    let base = percpu_base();
    if base == 0 { return; }
    // SAFETY: per-CPU area slot @32; sole writer is this CPU.
    unsafe { core::ptr::write_volatile((base as usize + PERCPU_IRQ_STACK_TOP_OFF) as *mut u64, top); }
}

/// Publish the current task's kernel-stack top for the entry asm's bad-stack
/// check. Called on every context switch; 0 when the incoming task has no slot
/// stack (the idle task), which disables the check for it.
/// # SAFETY: `TPIDR_EL1` set to this CPU's per-CPU page; sole writer is this CPU
/// while it owns the switch.
/// # C: O(1)
pub fn set_current_kstack_top(top: u64) {
    let base = percpu_base();
    if base == 0 { return; }
    // SAFETY: per-CPU area slot @40; sole writer is this CPU during its own switch.
    unsafe { core::ptr::write_volatile((base as usize + PERCPU_KSTACK_TOP_OFF) as *mut u64, top); }
}

/// Arm this CPU's bad-stack overflow stack: the unused tail of its own per-CPU
/// page (see `badstack`). Idempotent, and a no-op while `TPIDR_EL1` is unset.
///
/// The BSP installs its vector table long before `init_boot_percpu` sets
/// `TPIDR_EL1`, so `install_default`'s call is a no-op there and kmain must call
/// this again once the per-CPU area exists — otherwise the entry guard's bad
/// path finds slot 56 zero and silently proceeds onto the bad SP, i.e. the
/// detector is inert on CPU 0. APs are fine: `ap_main` sets the per-CPU base
/// before installing the vectors.
/// # C: O(1)
pub fn arm_overflow_stack() {
    let base = percpu_base();
    if base == 0 { return; }
    // Overflow stack = the unused tail of this CPU's own per-CPU page (see
    // `badstack`). 16-byte aligned because the page is page-aligned.
    let top = base as u64 + hal::PAGE_SIZE_BYTES as u64;
    // SAFETY: per-CPU area slot @56; sole writer is this CPU during its own bring-up.
    unsafe { core::ptr::write_volatile((base as usize + PERCPU_OVERFLOW_TOP_OFF) as *mut u64, top); }
}

/// Is the caller executing on this CPU's per-CPU hard-IRQ stack?
///
/// The IRQ entry asm switches SP to that shared stack before running the
/// dispatcher (`22§5`, F699). Anything reached from there is in interrupt
/// context and MUST NOT sleep: a task that parks with `Context.sp` pointing into
/// the shared stack has its frames overwritten by the next IRQ on this CPU, and
/// resumes on a corrupted stack — observed as an EL1 branch into `.data`. Linux
/// enforces the same rule via `in_interrupt()` / `might_sleep()`; this is the
/// primitive a `can_sleep()` predicate consults.
///
/// False when the per-CPU slot is unarmed (early boot) or the base is unset.
/// # C: O(1)
pub fn on_irq_stack() -> bool {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let base = percpu_base();
        if base == 0 { return false; }
        // SAFETY: per-CPU area slot @32, written only by set_irq_stack_top on this CPU.
        let top = unsafe { core::ptr::read_volatile((base as usize + PERCPU_IRQ_STACK_TOP_OFF) as *const u64) };
        if top == 0 { return false; }
        let sp: u64;
        // SAFETY: reads the architectural SP only; no memory or flag effects.
        unsafe { core::arch::asm!("mov {v}, sp", v = out(reg) sp, options(nomem, nostack, preserves_flags)); }
        sp < top && sp >= top - hal::KERNEL_STACK_BYTES as u64
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { false }
}

/// Read the current SP for stack diagnostics.
/// # C: O(1)
pub fn current_stack_pointer() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        let sp: u64;
        // SAFETY: reads SP only; no memory, flags, or control state change.
        unsafe { core::arch::asm!("mov {v}, sp", v = out(reg) sp, options(nomem, nostack, preserves_flags)); }
        sp
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}


/// Address of the vector table, or 0 on host where the asm symbol
/// doesn't exist.
fn vector_table_addr() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: taking the address of a `&'static` extern symbol;
        // no read of the bytes themselves at this site.
        unsafe { &oxide_vector_table as *const u8 as u64 }
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

/// Install the default vector table by writing `VBAR_EL1`. Single-
/// shot at boot.
///
/// # SAFETY: caller is the boot path; runs single-CPU with IRQs
/// masked. The table is stored in `.text` and is read-only from
/// kernel code; the CPU dereferences entries asynchronously on every
/// exception.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn install_default() {
    arm_overflow_stack();
    let base = vector_table_addr();
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `msr vbar_el1` is privileged at EL1; sets the
        // vector base. ARM ARM D13.2.111. `isb` ensures subsequent
        // exceptions vector to the new table.
        unsafe {
            core::arch::asm!(
                "msr vbar_el1, {b}",
                "isb",
                b = in(reg) base,
                options(nomem, nostack, preserves_flags),
            );
        }
    }
    let _ = base;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn vector_table_size_matches_arm_arm() {
        // ARM ARM D1.10: 16 entries × 0x80 bytes = 0x800.
        assert_eq!(VECTOR_TABLE_SIZE, 0x800);
        assert_eq!(VECTOR_ENTRY_BYTES, 0x80);
        assert_eq!(VECTOR_ENTRY_BYTES * 16, VECTOR_TABLE_SIZE);
    }

    #[test]
    fn install_default_compiles_on_host() {
        // SAFETY: hosted test; the asm path is cfg'd out, so install
        // exercises only the no-op fallback branch.
        unsafe { install_default() };
    }

    #[test]
    fn exec_state_discards_every_inherited_user_register() {
        let mut f = SvcFrame {
            gp: [0x11; 18], x18_x29: [0x22; 2], x30: 0x33,
            _pad_x30: 0x44, elr_el1: 0x55, spsr_el1: 0x66,
            sp_el0: 0x77, retval: 0x88, x19_x28: [0x99; 10],
        };
        f.install_exec_state(0x1234_5000, 0x7fff_f000);
        assert_eq!(f.gp, [0; 18]);
        assert_eq!(f.x18_x29, [0; 2]);
        assert_eq!(f.x30, 0);
        assert_eq!(f._pad_x30, 0);
        assert_eq!(f.x19_x28, [0; 10]);
        assert_eq!(f.elr_el1, 0x1234_5000);
        assert_eq!(f.spsr_el1, 0);
        assert_eq!(f.sp_el0, 0x7fff_f000);
        assert_eq!(f.retval, 0);
    }
}
