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
/// Note: the actual frame is 26 × 8 = 208 bytes per the asm. Only
/// the slots syscall handlers need to overwrite are exposed here.
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

const _: () = assert!(core::mem::size_of::<SvcFrame>() == 288,
    "SvcFrame must match the 288 B asm frame in oxide_lower_el_sync_handler");

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
}
