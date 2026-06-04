// x86_64 bootloader handoff per docs/36 + docs/20.
//
// GRUB loads the kernel ELF directly via multiboot2: it scans the
// first 32 KiB of the file for the MB2 header (`mb2.rs`), copies each
// PT_LOAD by physical address, and jumps to the MB2 entry. The MB2
// trampoline sets up long mode + paging itself, swaps to
// `KERNEL_STACK`, and tail-calls `_start_rust`, which parses the MB2
// info struct into our `BootInfo` and tail-calls `kernel::kernel_main`.
// UART driver (16550A on QEMU `-serial stdio`) lands here so klog has
// a sink.

#![no_std]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod mb2;
pub mod uart;

use core::cell::UnsafeCell;
use kernel::{BootInfo, BootMemRegion};
#[cfg(feature = "debug-boot")]
use klog::Uart;
#[cfg(feature = "debug-boot")]
use sync::{Spinlock, Tty as UartClass};

#[cfg(feature = "debug-boot")]
use uart::{Uart16550, COM1};

// Per `04§4.0` (R06): every klog::* call site in this crate sits
// behind `debug-boot` — UART sink install, CPU/MMU dump, byte
// emit. Default builds emit zero log bytes; the call sites are
// absent from the binary, not "filtered at runtime".
#[cfg(feature = "debug-boot")]
macro_rules! debug_boot { ($($t:tt)*) => { $($t)* } }
#[cfg(not(feature = "debug-boot"))]
macro_rules! debug_boot { ($($t:tt)*) => {} }

// ---------------------------------------------------------------------------
// Boot-time UART sink for klog. Single instance behind `Spinlock` so the
// `klog::LogSink` thunk can drive it without `static mut` (`07§5`).
// ---------------------------------------------------------------------------

#[cfg(feature = "debug-boot")]
static BOOT_UART: Spinlock<Uart16550, UartClass>
    = Spinlock::new(Uart16550::new(COM1));

/// klog `LogSink` adapter — drives `BOOT_UART` for every byte slice
/// klog emits. Registered via `klog::set_byte_sink` from
/// `_start_rust` after `BOOT_UART::init()`.
///
/// Uses `lock_irqsave` per `06§3.1` because klog can be called from
/// IRQ context (timer ISR's `tick_poll_uart`, fault handlers, panic
/// path). A plain `lock()` would deadlock if a kernel-mode klog
/// holder were preempted by an IRQ that itself klogs.
/// # C: O(len)
#[cfg(feature = "debug-boot")]
fn boot_emit(bytes: &[u8]) {
    let mut g = BOOT_UART.lock_irqsave::<hal_x86_64::X86IrqGate>();
    g.write_bytes(bytes);
}

/// klog clock thunk — surfaces `X86TimerOps::monotonic_ns` as the
/// `klog::ClockFn` after `set_tsc_khz` calibration.
/// # C: O(1)
fn now_ns_x86() -> u64 {
    use hal::TimerOps;
    hal_x86_64::X86TimerOps::monotonic_ns().0
}

/// Remap the legacy 8259A PIC pair to vectors 0x20–0x2F and mask every
/// line. The kernel routes interrupts through the LAPIC/IOAPIC, so the
/// 8259 must not deliver: its default IRQ0–7 land on vectors 0x08–0x0F
/// which alias the CPU exception vectors (0x08 = #DF). A bootloader
/// that leaves the PIC live + a free-running PIT then vectors a timer
/// tick into the double-fault handler at the first `sti`. Linux does
/// the same ICW1–4 remap + mask before switching to the APIC.
///
/// # SAFETY: boot-only, single-CPU, IRQs masked; ports 0x20/0x21/
/// 0xA0/0xA1 are the always-present legacy PIC registers on the q35
/// target. # C: O(1) # Ctx: pre-init, IRQ-off, single-CPU
#[cfg(target_os = "oxide-kernel")]
unsafe fn remap_and_mask_pic() {
    // # SAFETY: single byte `out` to a legacy PIC port; no memory effect.
    unsafe fn outb(port: u16, val: u8) {
        // SAFETY: port-mapped I/O to the legacy 8259 PIC during single-CPU boot with IRQs masked; the q35 machine always wires these ports.
        unsafe { core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags)); }
    }
    // SAFETY: ICW1-4 init the PIC pair, ICW2 sets vector bases 0x20
    // (master) / 0x28 (slave) away from exceptions, then 0xFF masks
    // every line. All writes are to the always-present legacy ports.
    unsafe {
        outb(0x20, 0x11); // master ICW1: init + ICW4 to follow
        outb(0xA0, 0x11); // slave  ICW1
        outb(0x21, 0x20); // master ICW2: IRQ0-7 -> 0x20-0x27
        outb(0xA1, 0x28); // slave  ICW2: IRQ8-15 -> 0x28-0x2F
        outb(0x21, 0x04); // master ICW3: slave on IRQ2
        outb(0xA1, 0x02); // slave  ICW3: cascade identity
        outb(0x21, 0x01); // master ICW4: 8086 mode
        outb(0xA1, 0x01); // slave  ICW4
        outb(0x21, 0xFF); // mask all master IRQs
        outb(0xA1, 0xFF); // mask all slave IRQs
    }
}

/// Boot-time CPU identification log. Reads CPUID leaves 0 (vendor)
/// and 0x80000002..0x80000004 (brand) and emits both via klog.
/// # C: O(1)
#[cfg(feature = "debug-boot")]
fn log_cpu_info() {
    let v = hal_x86_64::cpuid_vendor();
    klog::write_raw(b"[INFO]  cpu vendor: ");
    klog::write_raw(&v);
    let b = hal_x86_64::cpuid_brand();
    let brand_len = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    klog::write_raw(b"\n[INFO]  cpu brand: ");
    klog::write_raw(&b[..brand_len]);
    klog::write_raw(b"\n[INFO]  mmu cr0=");
    klog::write_hex_u64(hal_x86_64::read_cr0());
    klog::write_raw(b" cr3=");
    klog::write_hex_u64(hal_x86_64::read_cr3());
    klog::write_raw(b" cr4=");
    klog::write_hex_u64(hal_x86_64::read_cr4());
    klog::write_raw(b" efer=");
    klog::write_hex_u64(hal_x86_64::read_efer());
    klog::write_raw(b"\n");
}

/// Build a hard-coded minimal `BootInfo` for the not-MB2 safety
/// fallback (e.g. host-test builds). The live x86 boot path is GRUB
/// multiboot2, which fills `BootInfo` from the MB2 info struct.
///
/// # SAFETY: caller must own the returned `BootInfo`'s pointed-to
/// regions (currently a static empty slice; safe).
/// # C: O(1)
#[doc(hidden)]
pub unsafe fn stub_boot_info() -> BootInfo {
    static EMPTY: [BootMemRegion; 0] = [];
    BootInfo {
        memmap_count: 0,
        memmap_ptr: EMPTY.as_ptr(),
        seed: [0; 32],
        boot_ns: 0,
        hhdm_offset: 0,
        rsdp_pa: 0,
        smp_info_array: 0,
        smp_count: 0,
        bsp_lapic_id: 0,
        _pad: 0,
    }
}

/// Initial kernel stack (16 KiB, BSS-resident, page-aligned). Wrapped
/// in `UnsafeCell` so we can take the asm-side write reference without
/// `static mut` (per `06§11` + `07§5`). `Sync` is sound: only the
/// boot path touches it, single-CPU, before scheduler init.
#[cfg(target_os = "oxide-kernel")]
const STACK_SIZE: usize = 128 * 1024;
#[cfg(target_os = "oxide-kernel")]
#[repr(align(4096))]
struct KernelStack(UnsafeCell<[u8; STACK_SIZE]>);
#[cfg(target_os = "oxide-kernel")]
unsafe impl Sync for KernelStack {}
#[cfg(target_os = "oxide-kernel")]
static KERNEL_STACK: KernelStack = KernelStack(UnsafeCell::new([0; STACK_SIZE]));

/// Storage for `BootInfo`'s memmap slice — populated from the MB2
/// memory-map tag by `_start_rust` before `kernel_main` runs.
/// `MemmapStorage` lives in `.bss` so the cost is N entries × 24 B
/// = ~6 KiB; QEMU rarely exceeds 32 entries.
const MAX_BOOT_REGIONS: usize = 256;
#[repr(C, align(8))]
struct MemmapStorage(UnsafeCell<[BootMemRegion; MAX_BOOT_REGIONS]>);
unsafe impl Sync for MemmapStorage {}
static MEMMAP_STORAGE: MemmapStorage = MemmapStorage(UnsafeCell::new([
    BootMemRegion {
        base_pa: 0,
        len:     0,
        kind:    kernel::BootMemKind::Reserved,
    };
    MAX_BOOT_REGIONS
]));

/// Bootloader cmdline storage. Sized for a generous Linux-style
/// cmdline (CONFIG_CMDLINE_BOOT_MAX=2048); cmdlines that exceed
/// this get truncated at copy time. NUL-terminated for human
/// reading.
const CMDLINE_BUF_LEN: usize = 4096;
#[repr(C, align(8))]
struct CmdlineStorage(UnsafeCell<[u8; CMDLINE_BUF_LEN]>);
unsafe impl Sync for CmdlineStorage {}
static CMDLINE_STORAGE: CmdlineStorage =
    CmdlineStorage(UnsafeCell::new([0u8; CMDLINE_BUF_LEN]));

/// Read the GRUB multiboot2 boot-command-line tag, copy into
/// kernel-owned `CMDLINE_STORAGE`, and publish via
/// `kernel::boot_cmdline::set`. No-op if the cmdline is empty or this
/// is not an MB2 boot — the kernel then falls back to
/// `install_arch_default`.
///
/// # SAFETY: called once from the boot path before any procfs read
/// can race; `CMDLINE_STORAGE` is a 'static slot.
/// # C: O(cmdline_len)
unsafe fn capture_cmdline() {
    // GRUB/multiboot2 path: copy the cmdline from the MB2 boot-command-
    // line tag (type 1) instead of the Limine executable-file response.
    #[cfg(target_os = "oxide-kernel")]
    {
        if mb2::info::is_mb2_boot() {
            // SAFETY: cmdline_va returns an HHDM-mapped pointer into the
            // MB2 info struct (NUL-terminated); copy bounded by the buf.
            if let Some(src) = unsafe { mb2::info::cmdline_va() } {
                // SAFETY: CMDLINE_STORAGE is the 'static boot-only slot;
                // sole writer before any reader exists.
                let dst = unsafe { &mut *CMDLINE_STORAGE.0.get() };
                let mut n = 0usize;
                while n < CMDLINE_BUF_LEN - 1 {
                    // SAFETY: src[..] is a NUL-terminated C string in the
                    // HHDM-mapped MB2 region; read one byte at a time.
                    let b = unsafe { core::ptr::read_volatile(src.add(n)) };
                    if b == 0 { break; }
                    dst[n] = b;
                    n += 1;
                }
                if n > 0 {
                    if n < CMDLINE_BUF_LEN - 1 { dst[n] = b'\n'; n += 1; }
                    // SAFETY: dst[..n] initialised above; 'static lifetime.
                    let bytes: &'static [u8] = unsafe {
                        core::slice::from_raw_parts(dst.as_ptr(), n)
                    };
                    // SAFETY: boot_cmdline::set is single-writer / boot-only.
                    unsafe { kernel::boot_cmdline::set(bytes); }
                }
            }
            return;
        }
    }
    // No MB2 boot (e.g. host-test build): nothing to capture. The only
    // x86 boot path is GRUB multiboot2; the kernel falls back to
    // `install_arch_default` for `/proc/cmdline`.
}

/// Build a `BootInfo` by parsing the GRUB multiboot2 info struct.
/// Falls back to an empty memmap on the not-MB2 path (host-test build).
///
/// # SAFETY: caller is the boot path; the MB2 trampoline saved a valid
/// info-struct pointer; the `seed` slot is zero until ACPI / RTC
/// bring-up populates it.
/// # C: O(min(entry_count, MAX_BOOT_REGIONS))
unsafe fn build_boot_info() -> BootInfo {
    // GRUB/multiboot2 path: parse the MB2 info struct instead of Limine
    // responses. Keyed on the bootloader magic the trampoline saved.
    #[cfg(target_os = "oxide-kernel")]
    {
        if mb2::info::is_mb2_boot() {
            use hal::TimerOps;
            // SAFETY: MEMMAP_STORAGE is boot-owned; build_memmap fills it
            // from the MB2 info struct (HHDM-mapped, parsed pre-PMM).
            let storage = unsafe { &mut *MEMMAP_STORAGE.0.get() };
            // SAFETY: trampoline wrote a valid MB2-info ptr; build_memmap
            // parses the HHDM-mapped struct, filling boot-owned storage.
            let (n, rsdp_pa) = unsafe { mb2::info::build_memmap(storage) };
            let boot_ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
            return BootInfo {
                memmap_count: n as u32,
                memmap_ptr:   storage.as_ptr(),
                seed:         [0; 32],
                boot_ns,
                hhdm_offset:  mb2::info::MB2_HHDM,
                rsdp_pa,
                smp_info_array: 0,
                smp_count:      0,
                bsp_lapic_id:   0,
                _pad: 0,
            };
        }
    }
    // No Limine: the only x86 boot path is GRUB multiboot2.
    // SAFETY: returns an owned BootInfo whose `memmap_ptr` references a
    // `&'static` empty slice; reached only on the not-MB2 fallback.
    unsafe { stub_boot_info() }
}

/// Rust-side boot continuation. Runs on the kernel stack we
/// installed in `_start`. Parses the MB2 info struct, builds a
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
        unsafe { BOOT_UART.lock().init(); }
        klog::set_byte_sink(boot_emit);
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
    unsafe { remap_and_mask_pic(); }
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
    klog::set_clock_fn(now_ns_x86);
    debug_boot! { log_cpu_info(); }
    // SAFETY: capture_cmdline is boot-only, single-CPU, runs before any reader of kernel::boot_cmdline can race; reads bootloader-owned EXECUTABLE_FILE response then publishes the captured bytes through the AtomicPtr-backed slot.
    unsafe { capture_cmdline(); }
    // SAFETY: boot path per fn contract; build_boot_info reads
    // bootloader-owned static state and produces an owned BootInfo.
    let info = unsafe { build_boot_info() };
    // SAFETY: kernel_main's safety contract is satisfied by the
    // boot environment we just established (kernel stack installed,
    // IRQs masked, single CPU, `info` valid).
    unsafe { kernel::kernel_main(&info) }
}

/// Entry point invoked by the MB2 trampoline (`mb2.rs`) after it has
/// set up long mode + paging. Swaps to `KERNEL_STACK` and tail-calls
/// `_start_rust`.
///
/// # SAFETY: caller is the MB2 trampoline; runs single-CPU with IRQs
/// masked, paging on, kernel image mapped at upper-half linker base.
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
    let stack_top = unsafe {
        (KERNEL_STACK.0.get() as *mut u8).add(STACK_SIZE)
    };
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

#[cfg(test)]
mod tests {
    use super::*;
    use kernel::BootMemKind;

    #[test]
    fn stub_boot_info_is_empty() {
        // SAFETY: stub_boot_info returns a value owned by the caller;
        // pointed-to slice is &'static empty.
        let info = unsafe { stub_boot_info() };
        assert_eq!(info.memmap_count, 0);
        let _ = BootMemKind::Usable;
    }
}
