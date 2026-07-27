// x86_64 HAL impls per docs/20.
//
// Crate root is the manifest/export surface. Architecture code lives in
// submodules grouped by CPU, IRQ, timer, descriptor, and memory-management role.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

mod context;
mod cpu;
mod cpuid;
mod fault;
mod exception_table;
mod fpu;
mod gdt;
mod idt;
pub mod ioapic;
mod irq;
mod irq_gate;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub mod linux_retpoline;
mod mmu;
pub mod mmu_ops;
pub mod pci;
mod pt_regs;
mod regs;
mod signal;
mod syscall;
mod timer;
mod tss;
mod uaccess;
pub mod vmm;

pub use context::{ContextX86_64, ForkRegs};
pub use cpu::{get_user_fs_base, halt, mmio_barrier, set_user_fs_base, X86CpuOps};
pub use cpuid::{brand as cpuid_brand, family_model as cpuid_family_model, vendor as cpuid_vendor};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use cpuid::tsc_khz_from_cpuid;
pub use fault::{
    current_fault_frame, current_fault_gprs, install_fault_handler, install_user_trap_hook,
    vector_stub_addr, FaultFrame, FaultGprs, FaultHandler, UserTrapHook,
};
pub use fpu::{
    fpu_disable, fpu_enable, fpu_restore, fpu_save, xsave_active, xsave_area_bytes, xstate_init,
    FpuStateX86_64, FPU_OWNER, FPU_STATE_BYTES,
};
pub use gdt::{install_kernel_gdt, load_kernel_gdt_for_ap, GdtPointer, GDT_LEN, USER_CS, USER_DS};
pub use idt::{
    install_default as install_default_idt, install_ist_gates, load_idtr_for_ap, IdtEntry,
    IdtPointer, GATE_INT64_KERNEL, IDT_LEN, KERNEL_CS,
};
pub use irq::{
    on_irq_stack,
    init_percpu_hardirq_stack,
    irq_stub_addr, VEC_MSI, VEC_MSI_POOL_FIRST, VEC_MSI_POOL_LAST, VEC_MSI_POOL_LEN,
    VEC_RESCHED, VEC_TIMER, VEC_TLB_SHOOTDOWN,
};
pub use irq_gate::X86IrqGate;
pub use mmu::{
    flush_local_all, flush_local_va, va_to_indices, PteFlags, PteX86_64, PtIndices,
    ENTRIES_PER_TABLE, PD_SHIFT, PDPT_SHIFT, PML4_SHIFT, PT_SHIFT, PTE_PHYS_MASK,
};
pub use pt_regs::PtRegsX86_64;
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use regs::{read_clear_dr6, set_data_watchpoint};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel", feature = "debug-hw-watchpoint"))]
pub use regs::{arm_hole_watchpoint, disarm_hole_watchpoint, read_dr0_dr1};
pub use regs::{enable_sse, read_cr0, read_cr3, read_cr4, read_efer};
pub use signal::{build_signal_frame, current_user_sp, restart_ignored_syscall, restart_via_restart_syscall, restore_signal_frame, rt_sigreturn_frame_range};
pub use syscall::{
    boot_syscall_kstack_top, current_kstack_top, current_user_frame, current_user_full_frame,
    init_percpu_syscall_kstack, install_syscall_msrs, set_syscall_kstack,
};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use timer::{calibrate_tsc_khz, read_rtc_unix_secs};
pub use timer::{set_tsc_khz, X86TimerOps};
pub use tss::{
    install_tss, install_tss_for_cpu, set_rsp0, setup_ist_stacks, tss_base_addr, Tss64,
    TSS_SEL, IST_STACK_BYTES,
};
pub use uaccess::{raw_copy_from_user, raw_copy_to_user};

#[cfg(test)]
mod tests;
