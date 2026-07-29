#[cfg(target_os = "oxide-kernel")]
use crate::{boot_debug, boot_info_build};

/// Rust-side boot continuation. Runs on the kernel stack we
/// installed in `_start`. Reads Limine responses, builds a
/// `BootInfo`, and tail-calls `kernel_main`.
///
/// # SAFETY: called only from the asm `_start` after `rsp` has
/// been swapped to `KERNEL_STACK`'s top. Single-CPU, IRQ-off.
/// # C: O(memmap entries)
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
unsafe extern "C" fn _start_rust() -> ! {
    // UART init + klog sink registration gated behind `debug-boot`
    // per `04§4.0` (R06): default builds emit zero klog bytes, so
    // the sink is never installed.
    debug_boot! {
        // SAFETY: COM1 owned by us pre-init; no other CPU alive yet; `init` programs the UART for 115200-8N1 + FIFO. After this call any klog emit will land on the serial port.
        unsafe { boot_debug::init_boot_uart(); }
        klog::set_byte_sink(boot_debug::boot_emit);
    }
    // SAFETY: single-CPU boot, IRQs masked; install_kernel_gdt populates a kernel-owned GDT (mirroring Limine's selector offsets so KERNEL_CS=0x28 / KERNEL_DS=0x30 stay valid) and reloads CS via far return + DS/ES/SS/FS/GS via mov. Replaces the bootloader's GDT before any IDT entry could fire.
    unsafe { hal_x86_64::install_kernel_gdt(); }
    // SAFETY: single-CPU boot, IRQs masked; GDT just installed with TSS descriptor populated at TSS_SEL=0x48 (avail 64-bit TSS, type=9). install_tss issues `ltr 0x48` which marks the descriptor busy and binds CR0.TR to the kernel-wide TSS. RSP0 stays zero until first userspace task; pre-userspace IRQs (Phase 1 path) ignore RSP0 since they take from CPL=0.
    unsafe { hal_x86_64::install_tss(); }
    // SAFETY: single-CPU boot, IRQs masked; install_default populates a kernel-owned IDT and `lidt`s it. Subsequent exceptions vector to oxide_idt_default_handler which halts.
    unsafe { hal_x86_64::install_default_idt(); }
    // Remap+mask the legacy 8259 PIC away from the exception vectors.
    // Bootloader-agnostic: Limine masks the PIC for us, GRUB/multiboot2
    // does not — leaving IRQ0 (PIT) at vector 0x08 (the #DF slot), so the
    // first STI vectors a PIT tick into the double-fault handler. The
    // kernel drives the APIC, so all legacy IRQs stay masked.
    // SAFETY: boot-only, single-CPU, IRQs masked; writes only the always-present legacy 8259 PIC ports (0x20/0x21/0xA0/0xA1) on the q35 target.
    unsafe { boot_debug::remap_and_mask_pic(); }
    // SAFETY: single-CPU boot, IRQs masked; GDT in place so STAR's kernel CS=0x28 / SS=0x30 selectors are valid; sets IA32_LSTAR to oxide_syscall_entry, EFER.SCE=1, FMASK clears IF/DF/AC on entry. User-side `syscall` becomes legal but no user task exists pre-userspace_smoke.
    unsafe { hal_x86_64::install_syscall_msrs(); }
    // SAFETY: single-CPU boot; CR0/CR4 writes legal at CPL=0; enables CR0.MP + clears CR0.EM + sets CR4.OSFXSR/OSXMMEXCPT so user-mode SSE/SSE2 instructions execute (musl libc startup uses SSE2 movq/punpcklqdq).
    unsafe { hal_x86_64::enable_sse(); }
    // TSC calibration (`23§3`): measure the real TSC rate against PIT
    // channel 2 so CLOCK_MONOTONIC tracks wall-clock (the hard-coded
    // 2.4 GHz guess broke systemd's deadline math — its 5 s netlink
    // timeouts misfired). Fall back to 2.4 GHz only if the PIT never
    // counts (so monotonic_ns is never 0 = "no time").
    // SAFETY: boot-only, single-CPU, IRQs masked; legacy PIT/port-61h
    // I/O is always present on the q35 machine we target.
    // TSC frequency, Linux order (`native_calibrate_tsc`): authoritative
    // CPUID source first (hypervisor leaf 0x4000_0010 / crystal 0x15 /
    // base 0x16 — the x86 analogue of arm's CNTFRQ_EL0), else PIT
    // calibration, else the 2.4 GHz fallback. Sanity-clamp to a plausible
    // 0.1–10 GHz so a bad TCG calibration can't poison the clock.
    let cpuid_khz = hal_x86_64::tsc_khz_from_cpuid();
    // SAFETY: boot-only, single-CPU, IRQs masked; calibrate_tsc_khz does
    // legacy PIT/port-61h I/O that is always valid on the q35 target.
    let cal_khz = if cpuid_khz != 0 { 0 } else { unsafe { hal_x86_64::calibrate_tsc_khz() } };
    let mut tsc_khz = if cpuid_khz != 0 { cpuid_khz } else { cal_khz };
    if !(100_000..=10_000_000).contains(&tsc_khz) { tsc_khz = 2_400_000; }
    hal_x86_64::set_tsc_khz(tsc_khz);
    klog::set_clock_fn(boot_debug::now_ns_x86);
    debug_boot! { boot_debug::log_cpu_info(); }
    // SAFETY: capture_cmdline is boot-only, single-CPU, runs before any reader of cmdline can race; reads bootloader-owned EXECUTABLE_FILE response then publishes the captured bytes through the AtomicPtr-backed slot.
    unsafe { boot_info_build::capture_cmdline(); }
    // SAFETY: boot path per fn contract; build_boot_info reads
    // bootloader-owned static state and produces an owned BootInfo.
    let info = unsafe { boot_info_build::build_boot_info() };
    // SAFETY: kernel_main's safety contract is satisfied by the
    // boot environment we just established (kernel stack installed,
    // IRQs masked, single CPU, `info` valid).
    unsafe { kmain::kernel_main(&info) }
}

/// Entry point invoked by Limine. Swaps to `KERNEL_STACK` and tail-calls
/// `_start_rust`.
///
/// # SAFETY: caller is the bootloader; runs single-CPU with IRQs
/// masked, paging on, kernel image mapped at upper-half linker base,
/// bootloader's stack still active.
/// # C: not measured
/// # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
#[no_mangle]
#[link_section = ".text.boot"]
pub unsafe extern "C" fn _start() -> ! {
    // SAFETY: KERNEL_STACK is BSS-resident, owned by us, no other
    // CPU alive yet. The pointer arithmetic stays within the static
    // array; the asm `mov rsp, _; call _` then `ud2` swaps the
    // stack and tail-calls _start_rust which never returns.
    let stack_top = unsafe { boot_info_build::kernel_stack_top() };
    // SAFETY: stack_top is one past the last byte of KERNEL_STACK; install via `mov rsp` before any call gives a valid kernel stack of STACK_SIZE bytes growing down. `_start_rust` is extern "C" + noreturn; `ud2` after the call hard-guards accidental return.
    unsafe {
        core::arch::asm!(
            "mov rsp, {sp}",
            "call {next}",
            "ud2",
            sp   = in(reg) stack_top,
            next = sym _start_rust,
            options(noreturn),
        );
    }
}

// On host-test builds (target_os != oxide-kernel) we leave _start out so
// the crate compiles for `cargo test` without linker headaches.
