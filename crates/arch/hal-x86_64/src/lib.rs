// x86_64 HAL impls per docs/20.
//
// Crate root is the manifest/export surface. Architecture code lives in
// submodules grouped by CPU, IRQ, timer, descriptor, and memory-management role.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

mod context;
mod cpu;
mod cpuid;
mod cpuid_fault;
pub mod pkru;
pub mod debugreg;
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
pub mod msr;
pub mod pci;
mod pt_regs;
mod regs;
mod signal;
mod syscall;
mod timer;
mod tsd;
mod tss;
mod uaccess;
pub mod vmm;

pub use context::{ContextX86_64, ForkRegs};
pub use cpu::{get_user_fs_base, get_user_gs_base, halt, mmio_barrier, set_user_fs_base, set_user_gs_base, X86CpuOps};
pub use cpuid_fault::{cpuid_fault_kind, cpuid_fault_supported, set_cpuid_faulting,
    CPUID_FAULT_AMD, CPUID_FAULT_INTEL, CPUID_FAULT_NONE};
pub use cpuid::{brand as cpuid_brand, family_model as cpuid_family_model, initial_apic_id, vendor as cpuid_vendor};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use cpuid::tsc_khz_from_cpuid;
pub use pkru::{arch_max_pkey, ospke_enabled, pkru_init_value, pkru_write_default, read_pkru, setup_pku, write_pkru};
pub use debugreg::{validate_addr as validate_dr_addr, validate_dr7, DebugRegs, Dr6Status,
    Dr7Error, HBP_NUM};
pub use fault::{
    fixup_eligible, VEC_GP, VEC_PF,
    current_fault_frame, install_fault_handler, install_stack_name_hook, StackReport, install_user_trap_hook,
    vector_stub_addr, FaultHandler, UserTrapHook,
};
pub use fpu::{
    fpu_disable, fpu_enable, fpu_restore, fpu_save, mxcsr_feature_mask, mxcsr_mask_init,
    xsave_active, xsave_area_bytes, xsave_xcr0, xstate_init,
    FpuStateX86_64, FPU_OWNER, FPU_STATE_BYTES,
};
pub use gdt::{install_kernel_gdt, load_kernel_gdt_for_ap, GdtPointer, GDT_LEN, KERNEL_DS,
    USER_CS, USER_CS_SELECTOR, USER_DS, USER_SS_SELECTOR};
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
pub use pt_regs::{PtRegs, PT_REGS_BYTES, PT_REGS_VECTOR_NMI, PT_REGS_VECTOR_SYSCALL};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use regs::{read_clear_dr6, set_data_watchpoint};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel", feature = "debug-hw-watchpoint"))]
pub use regs::{arm_hole_watchpoint, disarm_hole_watchpoint, read_dr0_dr1};
pub use regs::{clear_cr4_fsgsbase, enable_cpu_features, enable_sse, read_cr0, read_cr3, read_cr4, read_efer};
pub use signal::{build_signal_frame, min_sigstksz, current_user_sp, sigframe_base, sigframe_range, restart_ignored_syscall, restart_via_restart_syscall, restore_signal_frame, rt_sigreturn_frame_range};
pub use syscall::{
    boot_syscall_kstack_top, current_kstack_top, current_pt_regs,
    init_percpu_syscall_kstack, install_syscall_msrs, set_syscall_kstack,
};
#[cfg(all(target_arch = "x86_64", target_os = "oxide-kernel"))]
pub use timer::{calibrate_tsc_khz, read_rtc_unix_secs};
pub use timer::{set_tsc_khz, X86TimerOps};
pub use tsd::{cr4_with_tsd, set_tsd, CR4_TSD};
pub use tss::{
    install_tss, install_tss_for_cpu, set_rsp0, setup_ist_stacks, tss_base_addr, Tss64,
    TSS_SEL, IST_STACK_BYTES,
};
pub use uaccess::{raw_copy_from_user, raw_copy_to_user};

#[cfg(test)]
mod tests;
