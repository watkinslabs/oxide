#[cfg(target_os = "oxide-kernel")]
use crate::{boot_debug, boot_info_build, pl011};
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
use crate::selfboot;
/// Rust-side boot continuation. Runs on the kernel stack we
/// installed in `_start`; reads the DTB pointer stashed in
/// `DTB_PHYS_ADDR`, builds a `BootInfo`, tail-calls `kernel_main`.
///
/// # SAFETY: called only from the asm `_start` after `sp` has been
/// swapped to `KERNEL_STACK`'s top. Single-CPU, IRQ-off.
/// # C: O(1)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
unsafe extern "C" fn _start_rust() -> ! {
    // selfboot breadcrumb 'G': proves _start -> _start_rust transition.
    // Raw HHDM PL011 write — gated under debug-boot per `04§4.0`.
    debug_boot! {
        if selfboot::is_selfboot() {
            // SAFETY: selfboot trampoline mapped HHDM (0xFFFF_8000…) device
            // block over phys 0; UART DR is at HHDM + 0x0900_0000.
            unsafe { core::ptr::write_volatile((selfboot::ARM_SELFBOOT_HHDM + 0x0900_0000) as *mut u32, 0x47); }
        }
    }
    // Install the EL1 vector table so any synchronous fault halts
    // at our default handler instead of looping on lost exceptions.
    // SAFETY: single-CPU boot, IRQs masked; install_default_vbar
    // writes VBAR_EL1 to a kernel-owned 0x800-aligned vector table.
    unsafe { hal_aarch64::install_default_vbar(); }

    // Enable FP/SIMD at EL0/EL1 globally. v1 doesn't do lazy
    // FP context switch (the per-task FpuStateAArch64 + trap-on-
    // first-use machinery in hal_aarch64::fpu exists but is unused);
    // enable unconditionally so user binaries built with NEON
    // intrinsics (memcpy, glibc strxx, etc.) don't trap.
    hal_aarch64::fpu_enable();
    // Stage-1 permission overlay (protection keys). The BSP is the CPU that
    // decides: it reads the ID registers and latches the answer, and every
    // secondary CPU then follows that latch instead of re-deciding, so a
    // big.LITTLE package cannot end up applying the overlay on some cores and
    // ignoring it on others. Must follow fpu_enable — both write CPACR_EL1.
    // SAFETY: BSP bring-up at EL1 before EL0 starts; TCR2_EL1/CPACR_EL1 are per-CPU and this CPU is their sole writer.
    unsafe { hal_aarch64::setup_poe(true); }
    // SAFETY: BSP bring-up before EL0 starts; enables architected counter reads for userspace.
    unsafe { hal_aarch64::timer::enable_el0_counter_access(); }
    // Latch how many hardware breakpoint / watchpoint slots this CPU actually
    // implements, from its own feature register. A tracer is told the real
    // number through the debug regsets, and the count varies by implementation
    // — hard-coding it would arm slots that do not exist.
    // SAFETY: BSP bring-up at EL1 before any task runs; the debug feature register is read-only with no side effects.
    unsafe { hal_aarch64::hw_breakpoint::idreg::init(); }

    // The self-bootstrap Image trampoline installs the HHDM; hand its
    // offset to the PL011 driver so the UART is reachable after the MMU
    // is on. (A non-selfboot fallback keeps offset 0.)
    let hhdm = if selfboot::is_selfboot() {
        selfboot::ARM_SELFBOOT_HHDM
    } else {
        0
    };
    pl011::set_hhdm_offset(hhdm);

    // Sink registration is gated behind `debug-boot` per
    // `04§4.0` (R06): default builds emit zero klog bytes. Self-boot
    // routes klog through the real PL011 over HHDM; the fallback uses
    // the paging-agnostic semihosting sink.
    debug_boot! {
        if selfboot::is_selfboot() {
            klog::set_byte_sink(boot_debug::boot_emit_pl011);
        } else {
            klog::set_byte_sink(boot_debug::boot_emit);
        }
    }

    // Generic-timer calibration: read CNTFRQ_EL0 (programmed by
    // firmware) and stash kHz so `ArmTimerOps::monotonic_ns` works.
    let cntfrq_hz: u64;
    // SAFETY: `mrs cntfrq_el0` is unprivileged at any EL with no memory effects per ARM ARM D11.2.4; the output is the firmware-programmed counter frequency in Hz.
    unsafe {
        core::arch::asm!(
            "mrs {f}, cntfrq_el0",
            f = out(reg) cntfrq_hz,
            options(nomem, nostack, preserves_flags),
        );
    }
    hal_aarch64::set_cntfrq_khz((cntfrq_hz / 1000) as u32);
    klog::set_clock_fn(boot_debug::now_ns_aarch64);
    debug_boot! {
        if selfboot::is_selfboot() {
            // SAFETY: HHDM device block over UART; selfboot breadcrumb 'H'.
            unsafe { core::ptr::write_volatile((selfboot::ARM_SELFBOOT_HHDM + 0x0900_0000) as *mut u32, 0x48); }
        }
        boot_debug::log_cpu_info();
    }

    // Boot command line, in bootloader-transport priority order. The EFI
    // path's load options come first because the firmware behind GRUB
    // publishes no device tree, so `/chosen/bootargs` does not exist there
    // and only the load options carry the line. Each is a no-op once the
    // slot is filled, and an empty slot falls through to
    // install_arch_default.
    // SAFETY: boot-only single-writer; both read bootloader-owned state
    // captured before ExitBootServices and publish via cmdline::set.
    unsafe { boot_info_build::capture_cmdline_from_efi(); }
    // SAFETY: boot-only single-writer; capture_cmdline_from_dtb reads
    // the DTB /chosen/bootargs and publishes it via cmdline::set, or
    // no-ops if the DTB lacks bootargs.
    unsafe { boot_info_build::capture_cmdline_from_dtb(); }
    // SAFETY: boot path, pre-SMP; publishes the PSCI AP-startup params (page
    // table phys + DTB /cpus MPIDRs) for the kernel's bring_up_aps_psci.
    unsafe { boot_info_build::publish_psci_ap_params(); }
    // SAFETY: boot path; build_boot_info reads bootloader-owned
    // static state and produces an owned BootInfo.
    let info = unsafe { boot_info_build::build_boot_info() };
    // SAFETY: kernel_main's contract is satisfied by the boot env
    // we just established (kernel stack installed, IRQs masked).
    unsafe { kmain::kernel_main(&info) }
}

/// Entry. The shared bootloader-agnostic entry the trampoline tail-calls
/// (`b _start`) with `x0` = DTB phys. We save x0 to `DTB_PHYS_ADDR`,
/// swap to `KERNEL_STACK`, and tail-call `_start_rust`.
///
/// # SAFETY: trampoline contract — MMU on with HHDM + kernel high map,
/// IRQs off, single-CPU.
///
/// # C: not measured
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start(dtb_phys: u64) -> ! {
    // Save x0 before any function call clobbers it.
    boot_info_build::DTB_PHYS_ADDR.store(dtb_phys, core::sync::atomic::Ordering::Release);
    // SAFETY: KERNEL_STACK is BSS-resident, owned by us, single-CPU.
    let stack_top = unsafe { boot_info_build::kernel_stack_top() };
    // SAFETY: stack_top is one past KERNEL_STACK; we force SPSel=1 so SP_EL1 (auto-selected on EL1 exception entry) points at our kernel stack — the boot handoff may arrive with SPSel=0; `_start_rust` is extern "C" + noreturn; `brk` hard-guards accidental return.
    unsafe {
        core::arch::asm!(
            "msr spsel, #1",
            "mov sp, {sp}",
            "isb",
            "bl  {next}",
            "brk #0",
            sp   = in(reg) stack_top,
            next = sym _start_rust,
            options(noreturn),
        );
    }
}
