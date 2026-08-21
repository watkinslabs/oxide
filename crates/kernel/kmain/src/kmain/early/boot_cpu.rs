//! Boot CPU per-CPU storage installation.

#[repr(align(16))]
struct PerCpuBootPage(core::cell::UnsafeCell<[u8; 4096]>);
// SAFETY: BSS-resident; sole writer is the boot CPU before publication.
unsafe impl Sync for PerCpuBootPage {}
static BOOT_PERCPU: PerCpuBootPage = PerCpuBootPage(core::cell::UnsafeCell::new([0u8; 4096]));

pub(super) fn init() {
    let p = BOOT_PERCPU.0.get() as *mut u8;
    // SAFETY: boot CPU is the sole writer; loaded modules read these slots only
    // after the architecture per-CPU base is published below.
    unsafe {
        core::ptr::write_volatile(p as *mut u32, 0);
        core::ptr::write_volatile(p.add(cpu::LINUX_MODULE_PERCPU_OFFSET) as *mut usize, 0);
        core::ptr::write_volatile(p.add(cpu::LINUX_NUMA_NODE_OFFSET) as *mut i32, 0);
    }
    #[cfg(target_arch = "x86_64")]
    // SAFETY: the boot CPU is the sole early per-CPU-base owner and firmware
    // state is normalized before any user or secondary CPU can execute.
    unsafe {
        use hal::CpuOps;
        // Firmware may leave FSGSBASE enabled, which would let userspace
        // replace the kernel's GS-based per-CPU owner.
        hal_x86_64::clear_cr4_fsgsbase();
        hal_x86_64::X86CpuOps::set_percpu_base(p);
        hal_x86_64::init_percpu_syscall_kstack(hal_x86_64::boot_syscall_kstack_top());
    }
    #[cfg(target_arch = "aarch64")]
    // SAFETY: boot CPU only, before an AP or IRQ observes TPIDR_EL1.
    unsafe { use hal::CpuOps; hal_aarch64::ArmCpuOps::set_percpu_base(p); }
}
