use crate::BootInfo;

/// Kernel entry. Called by per-arch boot stub after low-level setup.
/// # SAFETY: caller set up a valid kernel stack, mapped the kernel image
/// upper-half per the linker script, set the per-CPU base, disabled IRQs;
/// `info` is a valid `BootInfo` with `memmap_count` entries at `memmap_ptr`.
/// # C: not measured (one-shot init)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
pub unsafe fn kernel_main(info: &BootInfo) -> ! {
    unsafe { super::early::init(info); }
    unsafe { super::runtime::init(info); }
    unsafe { super::rootfs::init(info); }
    sched::live::spawn_timer_driver();
    sched::live::spawn_ksoftirqd();
    sched::halt_forever()
}
