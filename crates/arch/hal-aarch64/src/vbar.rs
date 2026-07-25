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

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_irq_resume_user() -> !;
}

/// Address of the shared IRQ epilogue (`oxide_irq_resume_user`),
/// the saved-LR value `Context::new_kernel_with_irq_frame` parks
/// in `Context.lr`. Returns 0 on host (asm symbol absent).
/// # C: O(1)
pub fn irq_resume_user_addr() -> u64 {
    #[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
    { oxide_irq_resume_user as *const () as usize as u64 }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { 0 }
}

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
const AARCH64_INSN_BYTES: u64 = 4;
const ESR_EC_SHIFT: u64 = 26;
const ESR_EC_MASK: u64 = 0x3f;
const ESR_EC_SYSREG_TRAP: u64 = 0x18;
const SYSREG_ISS_DIR_READ: u64 = 1;
const SYSREG_ISS_DIR_SHIFT: u64 = 0;
const SYSREG_ISS_RT_SHIFT: u64 = 5;
const SYSREG_ISS_RT_MASK: u64 = 0x1f;
const SYSREG_ISS_CRN_SHIFT: u64 = 10;
const SYSREG_ISS_CRM_SHIFT: u64 = 1;
const SYSREG_ISS_OP1_SHIFT: u64 = 14;
const SYSREG_ISS_OP2_SHIFT: u64 = 17;
const SYSREG_ISS_OP0_SHIFT: u64 = 20;
const SYSREG_OP0_MASK: u64 = 0x3;
const SYSREG_OP_MASK: u64 = 0x7;
const SYSREG_CR_MASK: u64 = 0xf;
const SYSREG_XZR_RT: u64 = 31;

#[derive(Clone, Copy, Eq, PartialEq)]
struct SysReg {
    op0: u64,
    op1: u64,
    crn: u64,
    crm: u64,
    op2: u64,
}

const SYSREG_CNTFRQ_EL0: SysReg = SysReg { op0: 3, op1: 3, crn: 14, crm: 0, op2: 0 };
const SYSREG_CNTVCT_EL0: SysReg = SysReg { op0: 3, op1: 3, crn: 14, crm: 0, op2: 2 };

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
extern "C" {
    fn oxide_arm_undef_handler(frame_ptr: *mut u8) -> u64;
}

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
        sp < top && sp >= top - IRQ_STACK_BYTES
    }
    #[cfg(not(all(target_arch = "aarch64", target_os = "oxide-kernel")))]
    { false }
}

/// Per-CPU IRQ-stack size. Must track `sched::kstack::KSTACK_BYTES`, which the
/// IRQ entry asm also hardcodes as its range bound (`sub x11, x10, #16384`).
const IRQ_STACK_BYTES: u64 = 16384;

fn sysreg_ec(esr: u64) -> u64 {
    (esr >> ESR_EC_SHIFT) & ESR_EC_MASK
}

fn sysreg_iss_reg(esr: u64) -> SysReg {
    SysReg {
        op0: (esr >> SYSREG_ISS_OP0_SHIFT) & SYSREG_OP0_MASK,
        op1: (esr >> SYSREG_ISS_OP1_SHIFT) & SYSREG_OP_MASK,
        crn: (esr >> SYSREG_ISS_CRN_SHIFT) & SYSREG_CR_MASK,
        crm: (esr >> SYSREG_ISS_CRM_SHIFT) & SYSREG_CR_MASK,
        op2: (esr >> SYSREG_ISS_OP2_SHIFT) & SYSREG_OP_MASK,
    }
}

fn sysreg_iss_rt(esr: u64) -> u64 {
    (esr >> SYSREG_ISS_RT_SHIFT) & SYSREG_ISS_RT_MASK
}

fn sysreg_iss_is_read(esr: u64) -> bool {
    ((esr >> SYSREG_ISS_DIR_SHIFT) & SYSREG_ISS_DIR_READ) == SYSREG_ISS_DIR_READ
}

fn write_saved_rt(frame: &mut SvcFrame, rt: u64, value: u64) {
    match rt {
        0..=17 => frame.gp[rt as usize] = value,
        18 => frame.x18_x29[0] = value,
        19..=28 => frame.x19_x28[(rt - 19) as usize] = value,
        29 => frame.x18_x29[1] = value,
        30 => frame.x30 = value,
        SYSREG_XZR_RT => {}
        _ => {}
    }
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn read_cntfrq_el0() -> u64 {
    let v: u64;
    // SAFETY: `mrs CNTFRQ_EL0` reads the architected counter frequency and has no memory side effects.
    unsafe { core::arch::asm!("mrs {v}, cntfrq_el0", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
    v
}

#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
fn read_cntvct_el0() -> u64 {
    let v: u64;
    // SAFETY: `mrs CNTVCT_EL0` reads the architected virtual counter and has no memory side effects.
    unsafe { core::arch::asm!("mrs {v}, cntvct_el0", v = out(reg) v, options(nomem, nostack, preserves_flags)); }
    v
}

/// Handle EL0 trapped MRS/MSR instructions. Linux exposes the architected
/// counter registers to userspace; unsupported trapped sysregs stay SIGILL.
/// # SAFETY: `frame` is the live 288 B lower-EL sync frame owned by this CPU.
/// # C: O(1)
/// # Ctx: synchronous exception, IRQs masked
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
#[no_mangle]
pub unsafe extern "C" fn oxide_arm_sysreg_trap_handler(frame: *mut SvcFrame, esr: u64) -> u64 {
    // SAFETY: caller passed the live lower-EL sync frame for this exception.
    let f = unsafe { &mut *frame };
    if sysreg_ec(esr) != ESR_EC_SYSREG_TRAP || !sysreg_iss_is_read(esr) {
        // SAFETY: the frame is byte-identical to the undef frame expected by the SIGILL delivery path.
        return unsafe { oxide_arm_undef_handler(frame.cast::<u8>()) };
    }
    let reg = sysreg_iss_reg(esr);
    let value = if reg == SYSREG_CNTVCT_EL0 {
        read_cntvct_el0()
    } else if reg == SYSREG_CNTFRQ_EL0 {
        read_cntfrq_el0()
    } else {
        // SAFETY: the frame is byte-identical to the undef frame expected by the SIGILL delivery path.
        return unsafe { oxide_arm_undef_handler(frame.cast::<u8>()) };
    };
    let rt = sysreg_iss_rt(esr);
    let saved_x0 = f.gp[0];
    write_saved_rt(f, rt, value);
    f.elr_el1 = f.elr_el1.wrapping_add(AARCH64_INSN_BYTES);
    if rt == 0 { value } else { saved_x0 }
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
    fn sysreg_iss_decodes_cntvct_el0() {
        let esr = (ESR_EC_SYSREG_TRAP << ESR_EC_SHIFT) | 0x34f841;
        assert_eq!(sysreg_ec(esr), ESR_EC_SYSREG_TRAP);
        assert!(sysreg_iss_is_read(esr));
        assert_eq!(sysreg_iss_rt(esr), 2);
        assert!(sysreg_iss_reg(esr) == SYSREG_CNTVCT_EL0);
    }
}
