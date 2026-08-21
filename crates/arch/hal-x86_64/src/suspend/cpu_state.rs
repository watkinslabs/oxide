// Read the live CPU state into the record, and write it back after a resume.
//
// The restore ORDER is the contract, and it is not the save order reversed:
//
//   1. EFER before CR4 — a CR4 write that assumes long-mode features while
//      EFER still holds firmware's value faults.
//   2. CR4, CR3, CR2, CR0 — paging structures before anything dereferences a
//      kernel address that only the kernel tables map.
//   3. The GDT, and the CS/SS/DS reload that makes it live, before the IDT,
//      the task register or the LDT: every one of those names a selector the
//      GDT has to describe first.
//   4. The TSS descriptor's busy bit is cleared before `ltr`. A descriptor
//      the CPU was running on is marked busy, and `ltr` on a busy TSS `#GP`s.
//   5. The segment BASES last. Loading a selector into FS or GS clobbers the
//      corresponding base MSR, so a base restored before its selector is
//      thrown away (`54§8.5`).
//
// The whole restore runs before any `gs:`-relative access is legal, so it
// touches no per-CPU state and calls nothing that logs or locks.

use super::state::SavedCpuState;

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use super::state::DescPtr;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
use crate::msr::{IA32_CR_PAT, IA32_EFER, IA32_FS_BASE, IA32_GS_BASE, IA32_KERNEL_GS_BASE};

#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
const CR4_OSXSAVE: u64 = 1 << 18;

/// XGETBV/XSETBV are legal only after CR4.OSXSAVE is live. Keeping this
/// predicate pure gives hosted tests a positive control for the faulting case.
/// # C: O(1)
#[cfg(any(test, all(target_arch = "x86_64", target_os = "oxide-kernel")))]
const fn xcr0_accessible(cr4: u64) -> bool { cr4 & CR4_OSXSAVE != 0 }

/// Capture everything a deep sleep does not preserve.
///
/// The callee-saved general registers, the stack pointer and the instruction
/// pointer are NOT captured here — the resume must land at a known point in
/// the sleep path, which only the asm in `lowlevel.rs` can name.
///
/// # SAFETY: CPL=0, interrupts disabled, one CPU online. Reads privileged
/// registers and MSRs; writes only `s`.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn save_processor_state(s: &mut SavedCpuState) {
    s.cr0 = crate::regs::read_cr0();
    s.cr2 = read_cr2();
    s.cr3 = crate::regs::read_cr3();
    s.cr4 = crate::regs::read_cr4();
    // SAFETY: `rdmsr` is privileged but legal at CPL=0 and has no memory effect; every selector below is architectural.
    unsafe {
        s.efer = crate::cpu::rdmsr(IA32_EFER);
        s.xcr0 = if xcr0_accessible(s.cr4) { read_xcr0() } else { 0 };
        s.pat = if crate::pat::enabled() { crate::cpu::rdmsr(IA32_CR_PAT) } else { 0 };
        s.cpuid_faulting = u64::from(crate::cpuid_faulting_enabled());
        s.fs_base = crate::cpu::rdmsr(IA32_FS_BASE);
        s.gs_base = crate::cpu::rdmsr(IA32_GS_BASE);
        s.kernel_gs_base = crate::cpu::rdmsr(IA32_KERNEL_GS_BASE);
    }
    // SAFETY: `sgdt`/`sidt`/`str`/`sldt` and the segment reads are legal at CPL=0 and write only the named locals.
    unsafe {
        s.gdt = store_gdt();
        s.idt = store_idt();
        s.tr = store_tr();
        s.ldt = store_ldt();
        s.ds = read_ds();
        s.es = read_es();
        s.fs = read_fs();
        s.gs = read_gs();
    }
}

/// Put the machine back the way `save_processor_state` found it.
///
/// # SAFETY: entered on the resume path at CPL=0 with interrupts disabled,
/// one CPU online, and `s` holding a record this CPU armed. Writes every
/// control register, descriptor-table register and segment MSR named in the
/// module header; the CPU is unusable until it returns.
/// # C: O(1)
/// # Ctx: IRQ-off, single-CPU, no per-CPU state live
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub unsafe fn restore_processor_state(s: &SavedCpuState) {
    // SAFETY: every write below is a privileged register write legal at CPL=0, from a value this CPU itself saved.
    unsafe {
        crate::cpu::wrmsr(IA32_EFER, s.efer);
        write_cr4(s.cr4);
        if xcr0_accessible(s.cr4) { write_xcr0(s.xcr0); }
        if s.pat != 0 { crate::cpu::wrmsr(IA32_CR_PAT, s.pat); }
        write_cr3(s.cr3);
        write_cr2(s.cr2);
        write_cr0(s.cr0);
        load_gdt(&s.gdt);
        reload_kernel_selectors();
        load_idt(&s.idt);
        // Linux calls syscall_init() while repairing the processor context:
        // entry addresses and selector policy belong to this kernel, not to
        // whatever values happened to be saved before the sleep.
        crate::syscall::install_syscall_msrs();
        crate::tss::reload_saved_tr(s.tr);
        load_ldt(s.ldt);
        load_data_selectors(s.ds, s.es);
        // Bases last: a selector load clobbers the matching base MSR.
        crate::cpu::wrmsr(IA32_FS_BASE, s.fs_base);
        crate::cpu::wrmsr(IA32_GS_BASE, s.gs_base);
        crate::cpu::wrmsr(IA32_KERNEL_GS_BASE, s.kernel_gs_base);
        crate::set_cpuid_faulting(s.cpuid_faulting != 0);
    }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn read_xcr0() -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: the caller proved CR4.OSXSAVE; ECX=0 names XCR0.
    unsafe { core::arch::asm!("xgetbv", in("ecx") 0u32, out("eax") lo, out("edx") hi,
                              options(nomem, nostack, preserves_flags)); }
    (u64::from(hi) << 32) | u64::from(lo)
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn write_xcr0(value: u64) {
    // SAFETY: the value was captured from this admitted CPU and CR4.OSXSAVE
    // was restored first; ECX=0 names XCR0.
    unsafe { core::arch::asm!("xsetbv", in("ecx") 0u32, in("eax") value as u32,
                              in("edx") (value >> 32) as u32,
                              options(nostack, preserves_flags)); }
}

#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
fn read_cr2() -> u64 {
    let v: u64;
    // SAFETY: reading CR2 is privileged but legal at CPL=0 and has no side effect.
    unsafe { core::arch::asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)); }
    v
}

macro_rules! privileged_write {
    ($name:ident, $insn:literal) => {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        /// # SAFETY: caller owns the value; the write is legal at CPL=0 only.
        unsafe fn $name(v: u64) {
            // SAFETY: per fn contract — a privileged control-register write on the resume path at CPL=0.
            unsafe { core::arch::asm!($insn, in(reg) v, options(nostack, preserves_flags)); }
        }
    };
}

privileged_write!(write_cr0, "mov cr0, {}");
privileged_write!(write_cr2, "mov cr2, {}");
privileged_write!(write_cr3, "mov cr3, {}");
privileged_write!(write_cr4, "mov cr4, {}");

macro_rules! store_desc {
    ($name:ident, $insn:literal) => {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        /// # SAFETY: legal at CPL=0; writes only the returned operand.
        unsafe fn $name() -> DescPtr {
            let mut p = DescPtr { limit: 0, base: 0 };
            // SAFETY: per fn contract — the instruction stores ten bytes into a stack local the asm owns for the call.
            unsafe { core::arch::asm!($insn, p = in(reg) &mut p, options(nostack, preserves_flags)); }
            p
        }
    };
}

store_desc!(store_gdt, "sgdt [{p}]");
store_desc!(store_idt, "sidt [{p}]");

macro_rules! load_desc {
    ($name:ident, $insn:literal) => {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        /// # SAFETY: `p` describes a live descriptor table; loading a bogus
        /// one makes the next selector reference fault unrecoverably.
        unsafe fn $name(p: &DescPtr) {
            // SAFETY: per fn contract — the instruction reads ten bytes from a caller-owned operand at CPL=0.
            unsafe { core::arch::asm!($insn, p = in(reg) p, options(readonly, nostack, preserves_flags)); }
        }
    };
}

load_desc!(load_gdt, "lgdt [{p}]");
load_desc!(load_idt, "lidt [{p}]");

macro_rules! read_selector {
    ($name:ident, $insn:literal) => {
        #[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
        /// # SAFETY: reads a segment register; no side effect.
        unsafe fn $name() -> u16 {
            let v: u16;
            // SAFETY: per fn contract — a segment-register read with no memory effect.
            unsafe { core::arch::asm!($insn, out(reg) v, options(nomem, nostack, preserves_flags)); }
            v
        }
    };
}

read_selector!(read_ds, "mov {:x}, ds");
read_selector!(read_es, "mov {:x}, es");
read_selector!(read_fs, "mov {:x}, fs");
read_selector!(read_gs, "mov {:x}, gs");
read_selector!(store_tr, "str {:x}");
read_selector!(store_ldt, "sldt {:x}");

/// # SAFETY: `sel` is zero or names an LDT descriptor in the loaded GDT.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn load_ldt(sel: u16) {
    // SAFETY: per fn contract — `lldt` is legal at CPL=0; selector 0 means "no LDT", which is the common case.
    unsafe { core::arch::asm!("lldt {:x}", in(reg) sel, options(nostack, preserves_flags)); }
}

/// Reload CS/SS and the kernel data selectors against the freshly loaded GDT.
/// # SAFETY: the kernel GDT is loaded and describes the kernel selectors.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn reload_kernel_selectors() {
    // SAFETY: per fn contract — this is the same lgdt-plus-far-return reload an AP performs at bring-up, against the same shared GDT.
    unsafe { crate::gdt::load_kernel_gdt_for_ap(); }
}

/// Restore the DS/ES selectors the interrupted kernel was running with.
/// FS and GS are deliberately left on the kernel reload's values: their
/// bases are restored by MSR immediately afterwards, and a selector load
/// would clobber those bases again.
/// # SAFETY: both selectors are described by the loaded GDT.
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
unsafe fn load_data_selectors(ds: u16, es: u16) {
    // SAFETY: per fn contract — segment loads of GDT-described data selectors at CPL=0.
    unsafe {
        core::arch::asm!("mov ds, {:x}", in(reg) ds, options(nostack, preserves_flags));
        core::arch::asm!("mov es, {:x}", in(reg) es, options(nostack, preserves_flags));
    }
}

/// Hosted build: the record exists and round-trips, but no privileged
/// register can be read or written, so both halves are no-ops.
/// # SAFETY: no-op. # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub unsafe fn save_processor_state(_s: &mut SavedCpuState) {}

/// Hosted build counterpart of the restore. # SAFETY: no-op. # C: O(1)
#[cfg(not(all(target_arch = "x86_64", target_os = "oxide-kernel")))]
pub unsafe fn restore_processor_state(_s: &SavedCpuState) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xcr0_access_requires_osxsave() {
        assert!(!xcr0_accessible(0));
        assert!(!xcr0_accessible(CR4_OSXSAVE - 1));
        assert!(xcr0_accessible(CR4_OSXSAVE));
        assert!(xcr0_accessible(CR4_OSXSAVE | (1 << 7)));
    }
}
