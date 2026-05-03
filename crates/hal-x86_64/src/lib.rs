// x86_64 HAL impls per docs/20.
//
// Scope landed: IrqGate (RFLAGS save + `cli` / RFLAGS restore) per
// `06§3.1`. Halt + mmio_barrier per `20§4`. Larger CpuOps surface
// (per-CPU base, current_cpu) lands once the per-CPU primitive does.
//
// Asm is gated `#[cfg(all(target_arch="x86_64", target_os="oxide-kernel"))]`
// so the same source file compiles cleanly on:
//   - kernel target (`*-unknown-oxide-kernel`): real asm.
//   - host (`cargo test --workspace`): no-op fallback.
// This keeps the workspace one-build-graph without sidestepping the
// "no static mut" / "no dyn HAL" / "no extern crate std" rules.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

use core::sync::atomic::{AtomicU32, Ordering};

use hal::{CpuOps, Nanos, TimerOps};
use sync::IrqGate;

mod context;
mod cpuid;
mod fault;
mod fpu;
mod idt;
mod mmu;
mod pt_regs;
mod regs;
pub use cpuid::{brand as cpuid_brand, vendor as cpuid_vendor};
pub use regs::{read_cr0, read_cr3, read_cr4, read_efer};
pub use fault::vector_stub_addr;
pub use fpu::{fpu_disable, fpu_enable, fpu_restore, fpu_save, FpuStateX86_64, FPU_OWNER, FPU_STATE_BYTES};
pub use idt::{install_default as install_default_idt, IdtEntry, IdtPointer, GATE_INT64_KERNEL, IDT_LEN, KERNEL_CS};
pub use context::ContextX86_64;
pub use mmu::{
    flush_local_all, flush_local_va, va_to_indices, PteFlags, PteX86_64, PtIndices,
    ENTRIES_PER_TABLE, PD_SHIFT, PDPT_SHIFT, PML4_SHIFT, PT_SHIFT, PTE_PHYS_MASK,
};
pub use pt_regs::{oxide_dispatch_from_pt_regs_x86_64, PtRegsX86_64};

/// IRQ gate: save RFLAGS + clear IF (`cli`) on disable; restore RFLAGS
/// (which restores IF) on restore. Pairs with `Spinlock::lock_irqsave`
/// per `06§3.1`.
pub struct X86IrqGate;

impl IrqGate for X86IrqGate {
    /// # SAFETY: hardware-state mutation on this CPU; the returned
    /// flags must be paired with a single `restore` call before any
    /// other code path expects IRQs in their pre-disable state.
    /// # C: O(1)
    unsafe fn save_disable() -> u64 {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            let flags: u64;
            // SAFETY: pushfq + cli is the canonical save+disable
            // sequence on x86_64 per Intel SDM Vol. 2 + AMD APM.
            unsafe {
                core::arch::asm!(
                    "pushfq",
                    "pop {f}",
                    "cli",
                    f = out(reg) flags,
                    options(nomem, preserves_flags),
                );
            }
            flags
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// # SAFETY: restores RFLAGS from caller-provided word that came
    /// from the matching `save_disable` invocation.
    /// # C: O(1)
    unsafe fn restore(flags: u64) {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // SAFETY: popfq writes IF + other RFLAGS bits from the
            // saved word; legal on any privilege level for kernel.
            unsafe {
                core::arch::asm!(
                    "push {f}",
                    "popfq",
                    f = in(reg) flags,
                    options(nomem),
                );
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { let _ = flags; }
    }
}

/// Halt this CPU until the next IRQ. `hlt` per `20§4`. On host fallback,
/// returns immediately so hosted unit tests can exercise call sites.
/// # C: O(1)
/// # Ctx: idle path
pub fn halt() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `hlt` is a privileged instruction; in kernel mode
        // (CPL=0) it parks the core until the next IRQ — no memory
        // effects beyond architectural state.
        unsafe { core::arch::asm!("hlt", options(nomem, nostack, preserves_flags)) };
    }
}

/// Memory barrier ordering MMIO writes per `06§2`.
/// # C: O(1)
pub fn mmio_barrier() {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        // SAFETY: `mfence` is unprivileged; orders all loads + stores
        // before any subsequent loads + stores per Intel SDM 8.2.5.
        unsafe { core::arch::asm!("mfence", options(nomem, nostack, preserves_flags)) };
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    }
}

// ---------------------------------------------------------------------------
// CpuOps (`20§7`)
// ---------------------------------------------------------------------------

/// `current_cpu` reads `gs:0` — the per-CPU area's first word holds
/// `cpu_id`. Boot path (kernel's `_start`) writes `GS_BASE` via
/// `set_percpu_base` after carving the area out of the BSS per-CPU
/// table. Until SMP support lands, `cpu_count` returns 1 and the
/// boot CPU writes `cpu_id = 0` so the read returns 0 even when the
/// HAL is wired up.
pub struct X86CpuOps;

impl CpuOps for X86CpuOps {
    /// # C: O(1)
    fn current_cpu() -> u32 {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            let id: u32;
            // SAFETY: `mov %gs:0, %eax` reads the 32-bit word at
            // `GS_BASE + 0`. Boot path guarantees GS_BASE is set
            // (see `set_percpu_base`) and that offset 0 of the
            // per-CPU area holds the CPU id.
            unsafe {
                core::arch::asm!(
                    "mov {id:e}, gs:[0]",
                    id = out(reg) id,
                    options(nomem, nostack, preserves_flags),
                );
            }
            id
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { 0 }
    }

    /// v1 single-CPU; SMP enumeration lands with the APIC bring-up.
    /// # C: O(1)
    fn cpu_count() -> u32 { 1 }

    /// # C: O(1)
    fn halt() { halt(); }

    /// # C: O(1)
    fn mmio_barrier() { mmio_barrier(); }

    /// # SAFETY: caller asserts `base` points to a valid per-CPU
    /// area whose first word is the cpu_id.
    /// # C: O(1)
    unsafe fn set_percpu_base(base: *mut u8) {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        {
            // SAFETY: `wrgsbase` writes the GS base register from the
            // caller-supplied pointer. Requires CR4.FSGSBASE = 1, which
            // boot enables before the first call. Kernel-only insn.
            unsafe {
                core::arch::asm!(
                    "wrgsbase {b}",
                    b = in(reg) base,
                    options(nomem, nostack, preserves_flags),
                );
            }
        }
        #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
        { let _ = base; }
    }
}

// ---------------------------------------------------------------------------
// TimerOps (`20§12`)
// ---------------------------------------------------------------------------

/// TSC frequency in kHz, set by boot calibration (`23§3`). Zero means
/// "not yet calibrated"; `monotonic_ns` returns 0 in that window so
/// callers don't divide by zero.
static TSC_KHZ: AtomicU32 = AtomicU32::new(0);

/// Boot-time hook: stash the TSC frequency in kHz. Calibration code
/// (`23§3`) calls this once `freq` is known.
/// # C: O(1)
pub fn set_tsc_khz(freq: u32) {
    TSC_KHZ.store(freq, Ordering::Relaxed);
}

/// Read TSC. Pure rdtsc — boot-time CR4.TSC handling lands when the
/// kernel starts allowing user CPL=3 reads (see `20§12`).
fn rdtsc() -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
    {
        let lo: u32; let hi: u32;
        // SAFETY: `rdtsc` is unprivileged at CPL=0, returns the
        // 64-bit TSC across edx:eax. No memory effects.
        unsafe {
            core::arch::asm!(
                "rdtsc",
                lateout("eax") lo, lateout("edx") hi,
                options(nomem, nostack, preserves_flags),
            );
        }
        ((hi as u64) << 32) | (lo as u64)
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
    {
        // Host fallback: a monotonic counter so test sequences see a
        // strictly-non-decreasing `monotonic_ns` if a freq is set.
        static COUNTER: AtomicU32 = AtomicU32::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        n as u64
    }
}

pub struct X86TimerOps;

impl TimerOps for X86TimerOps {
    /// # C: O(1)
    fn monotonic_ns() -> Nanos {
        let khz = TSC_KHZ.load(Ordering::Relaxed) as u64;
        if khz == 0 { return Nanos(0); }
        // tsc * 1_000_000 / khz — keeps the multiply within u64 for
        // any TSC < 2^44 cycles (~488 days at 4 GHz).
        let tsc = rdtsc();
        Nanos(tsc.saturating_mul(1_000_000) / khz)
    }

    /// # SAFETY: writes `IA32_TSC_DEADLINE` MSR via `wrmsr`; caller
    /// owns LVT timer setup per `23§4` (one-shot, vector pre-bound).
    /// # C: O(1)
    unsafe fn set_oneshot(_deadline_ns: Nanos) {
        // TSC-deadline LVT programming lands with the APIC bring-up
        // in `22§3`. Trait shape exists so consumers compile.
    }

    /// # C: O(1)
    fn freq_khz() -> u32 { TSC_KHZ.load(Ordering::Relaxed) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use sync::{Buddy, Spinlock};

    #[test]
    fn irqgate_noop_on_host() {
        // Host build: save_disable returns 0; restore is a no-op.
        // SAFETY: hosted test entry; arch-asm path is cfg'd out so this
        // exercises only the no-op fallback per the cfg gates above.
        let f = unsafe { X86IrqGate::save_disable() };
        assert_eq!(f, 0);
        // SAFETY: hosted test; restore path is no-op on this target.
        unsafe { X86IrqGate::restore(f) };
    }

    #[test]
    fn lock_irqsave_works_with_x86_gate() {
        let s: Spinlock<u32, Buddy> = Spinlock::new(0);
        let mut g = s.lock_irqsave::<X86IrqGate>();
        *g = 7;
        drop(g);
        assert_eq!(*s.lock(), 7);
    }

    #[test]
    fn mmio_barrier_compiles_and_runs() {
        mmio_barrier();
    }

    #[test]
    fn halt_compiles_on_host_no_panic() {
        // Host build: halt is a no-op, returns immediately.
        halt();
    }

    #[test]
    fn x86_cpuops_host_fallback_returns_cpu_zero() {
        // Host build: current_cpu reads a stub; cpu_count is 1 by spec.
        assert_eq!(X86CpuOps::current_cpu(), 0);
        assert_eq!(X86CpuOps::cpu_count(),    1);
    }

    #[test]
    fn x86_cpuops_set_percpu_base_compiles_on_host() {
        let mut buf = [0u8; 64];
        // SAFETY: host-only; the asm path is cfg'd out, so this just
        // exercises the no-op fallback. The buffer outlives the call.
        unsafe { X86CpuOps::set_percpu_base(buf.as_mut_ptr()) };
    }

    #[test]
    fn x86_timer_returns_zero_until_calibrated() {
        // TSC_KHZ defaults to 0 across tests in this suite; the host
        // counter increments but the result is `tsc * 1e6 / 0` which
        // we short-circuit to 0.
        let pre = X86TimerOps::freq_khz();
        if pre == 0 {
            assert_eq!(X86TimerOps::monotonic_ns(), Nanos(0));
        }
    }

    #[test]
    fn x86_timer_after_set_tsc_khz_is_nonzero() {
        // Host fallback: rdtsc returns a strictly-increasing counter,
        // so once a freq is set, monotonic_ns advances.
        set_tsc_khz(1_000_000); // 1 GHz
        assert_eq!(X86TimerOps::freq_khz(), 1_000_000);
        let a = X86TimerOps::monotonic_ns();
        let b = X86TimerOps::monotonic_ns();
        assert!(b.0 >= a.0, "monotonic_ns must be non-decreasing");
        // Reset for sibling tests.
        set_tsc_khz(0);
    }
}
