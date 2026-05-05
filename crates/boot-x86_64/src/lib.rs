// x86_64 bootloader handoff per docs/36 + docs/20.
//
// Limine bootloader reads request markers from `.limine_reqs` (custom
// linker section) and writes responses, then jumps to the kernel
// entry. Our `_start` lives in `.text.boot` (per linker script
// 07§6), runs with paging set up by Limine to identity-map the
// kernel image at the upper-half virtual address.
//
// Phase 0 scope: get a `_start` symbol that runs cleanly in QEMU under
// Limine, sets up the kernel stack, parses Limine memmap into our
// `BootInfo`, and tail-calls `kernel::kernel_main`. UART driver
// (16550A on QEMU `-serial stdio`) lands here so klog has a sink.
//
// Real Limine integration + 16550 driver land in P0-07 follow-ups;
// this is the typed shell.

#![no_std]
#![cfg_attr(target_os = "oxide-kernel", no_main)]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))]
extern crate std;

pub mod limine;
pub mod uart;

use core::cell::UnsafeCell;
use core::sync::atomic::AtomicPtr;
use kernel::{BootInfo, BootMemRegion};
#[cfg(feature = "debug-boot")]
use klog::Uart;
#[cfg(feature = "debug-boot")]
use sync::{Spinlock, Tty as UartClass};

use limine::{
    HhdmResponse, MemmapResponse, RequestHeader, RsdpResponse,
    SmpRequest, HHDM_ID, MEMMAP_ID, REQUESTS_END_MARKER,
    REQUESTS_START_MARKER, REVISION_0, RSDP_ID, SMP_ID,
};
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
/// # C: O(len)
#[cfg(feature = "debug-boot")]
fn boot_emit(bytes: &[u8]) {
    let mut g = BOOT_UART.lock();
    g.write_bytes(bytes);
}

/// klog clock thunk — surfaces `X86TimerOps::monotonic_ns` as the
/// `klog::ClockFn` after `set_tsc_khz` calibration.
/// # C: O(1)
fn now_ns_x86() -> u64 {
    use hal::TimerOps;
    hal_x86_64::X86TimerOps::monotonic_ns().0
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

// ---------------------------------------------------------------------------
// Limine request slots — bootloader scans `.limine_requests` for these
// markers and writes responses before jumping to `_start`.
// ---------------------------------------------------------------------------

/// Base-revision marker per Limine v12 protocol. Required ≥ 6 on
/// modern Limine; older protocols reject revision 0. Values are
/// stable across Limine 9..12. MUST appear at the start of
/// `.limine_requests`; we land it via the `.start` subname which
/// the linker places before the rest.
#[used]
#[link_section = ".limine_requests.start"]
static LIMINE_BASE_REVISION: [u64; 3] = [
    0xf9562b2d5c95a6c8,
    0x6a7b384944536bdc,
    6,
];

/// Limine v9+ requires explicit markers around the request region;
/// v12 falls back to a slower full-image scan without them but our
/// SMP request was missed in that fallback path. The linker places
/// `.limine_requests.start` first and `.limine_requests.end` last
/// per the link script.
#[used]
#[link_section = ".limine_requests.start"]
static LIMINE_REQUESTS_START: [u64; 4] = REQUESTS_START_MARKER;

#[used]
#[link_section = ".limine_requests.end"]
static LIMINE_REQUESTS_END: [u64; 2] = REQUESTS_END_MARKER;

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_MEMMAP: RequestHeader<MemmapResponse> = RequestHeader {
    id:       MEMMAP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_HHDM: RequestHeader<HhdmResponse> = RequestHeader {
    id:       HHDM_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_RSDP: RequestHeader<RsdpResponse> = RequestHeader {
    id:       RSDP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
};

/// SMP enumeration request — Limine starts each AP, parks it
/// spinning on `SmpInfoX86::goto_address`, and gives us the
/// `[*mut SmpInfoX86; cpu_count]` table via the response.
/// `flags=0` keeps APs in xAPIC mode (sufficient for QEMU virt
/// CPU counts; X2APIC mode lands when we add x2APIC support).
#[used]
#[link_section = ".limine_requests"]
pub static LIMINE_SMP: SmpRequest = SmpRequest {
    id:       SMP_ID,
    revision: REVISION_0,
    response: AtomicPtr::new(core::ptr::null_mut()),
    flags:    0,
};

/// Build a hard-coded minimal `BootInfo` for compile-test purposes.
/// Real impl reads Limine's memmap + module list.
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

/// Storage for `BootInfo`'s memmap slice — populated from Limine's
/// memmap response by `_start_rust` before `kernel_main` runs.
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

/// Build a `BootInfo` by reading the bootloader-populated Limine
/// responses. Falls back to an empty memmap if the bootloader didn't
/// fill the response slot (e.g. running outside Limine).
///
/// # SAFETY: caller is the boot path; the bootloader has either
/// written real response pointers or left them null; the `seed` /
/// `boot_ns` slots are zero until ACPI / RTC bring-up populates them.
/// # C: O(min(entry_count, MAX_BOOT_REGIONS))
unsafe fn build_boot_info() -> BootInfo {
    let resp_ptr = LIMINE_MEMMAP.response.load(core::sync::atomic::Ordering::Acquire);
    if resp_ptr.is_null() {
        // SAFETY: returns an owned BootInfo whose `memmap_ptr`
        // references a `&'static` empty slice.
        return unsafe { stub_boot_info() };
    }
    // SAFETY: bootloader wrote a non-null response pointer; the
    // backing struct lives for the rest of boot per Limine's
    // memory-map ownership contract (`36§3`).
    let resp = unsafe { &*resp_ptr };
    // SAFETY: MEMMAP_STORAGE is owned by this CPU during boot; no
    // other path mutates it before kernel_main returns.
    let storage = unsafe { &mut *MEMMAP_STORAGE.0.get() };
    use hal::TimerOps;
    // SAFETY: limine::populate_memmap_into expects a valid response
    // table per its own contract, which the bootloader guarantees.
    let n = unsafe { limine::populate_memmap_into(storage, resp) };
    let boot_ns = hal_x86_64::X86TimerOps::monotonic_ns().0;
    let hhdm = {
        let p = LIMINE_HHDM.response.load(core::sync::atomic::Ordering::Acquire);
        if p.is_null() {
            0
        } else {
            // SAFETY: Limine wrote a non-null response pointer; backing
            // struct lives for the rest of boot per `36§3`.
            unsafe { (*p).offset }
        }
    };
    let rsdp_pa = {
        let p = LIMINE_RSDP.response.load(core::sync::atomic::Ordering::Acquire);
        if p.is_null() {
            0
        } else {
            // SAFETY: Limine wrote a non-null response pointer; backing
            // struct lives for the rest of boot per `36§3`.
            unsafe { (*p).address }
        }
    };
    let (smp_info_array, smp_count, bsp_lapic_id) = {
        let p = LIMINE_SMP.response.load(core::sync::atomic::Ordering::Acquire);
        if p.is_null() {
            (0u64, 0u64, 0u32)
        } else {
            // SAFETY: Limine wrote a non-null response pointer; backing
            // struct + cpus array live for the rest of boot per `36§3`.
            let r = unsafe { &*p };
            (r.cpus as u64, r.cpu_count, r.bsp_lapic_id)
        }
    };
    BootInfo {
        memmap_count: n as u32,
        memmap_ptr:   storage.as_ptr(),
        seed:         [0; 32],
        boot_ns:      boot_ns,
        hhdm_offset:  hhdm,
        rsdp_pa:      rsdp_pa,
        smp_info_array,
        smp_count,
        bsp_lapic_id,
        _pad: 0,
    }
}

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
        unsafe { BOOT_UART.lock().init(); }
        klog::set_byte_sink(boot_emit);
    }
    // SAFETY: single-CPU boot, IRQs masked; install_kernel_gdt populates a kernel-owned GDT (mirroring Limine's selector offsets so KERNEL_CS=0x28 / KERNEL_DS=0x30 stay valid) and reloads CS via far return + DS/ES/SS/FS/GS via mov. Replaces the bootloader's GDT before any IDT entry could fire.
    unsafe { hal_x86_64::install_kernel_gdt(); }
    // SAFETY: single-CPU boot, IRQs masked; GDT just installed with TSS descriptor populated at TSS_SEL=0x48 (avail 64-bit TSS, type=9). install_tss issues `ltr 0x48` which marks the descriptor busy and binds CR0.TR to the kernel-wide TSS. RSP0 stays zero until first userspace task; pre-userspace IRQs (Phase 1 path) ignore RSP0 since they take from CPL=0.
    unsafe { hal_x86_64::install_tss(); }
    // SAFETY: single-CPU boot, IRQs masked; install_default populates a kernel-owned IDT and `lidt`s it. Subsequent exceptions vector to oxide_idt_default_handler which halts.
    unsafe { hal_x86_64::install_default_idt(); }
    // SAFETY: single-CPU boot, IRQs masked; GDT in place so STAR's kernel CS=0x28 / SS=0x30 selectors are valid; sets IA32_LSTAR to oxide_syscall_entry, EFER.SCE=1, FMASK clears IF/DF/AC on entry. User-side `syscall` becomes legal but no user task exists pre-userspace_smoke.
    unsafe { hal_x86_64::install_syscall_msrs(); }
    // SAFETY: single-CPU boot; CR0/CR4 writes legal at CPL=0; enables CR0.MP + clears CR0.EM + sets CR4.OSFXSR/OSXMMEXCPT so user-mode SSE/SSE2 instructions execute (musl libc startup uses SSE2 movq/punpcklqdq).
    unsafe { hal_x86_64::enable_sse(); }
    // TSC calibration: v1 hardcodes 2.4 GHz, the steady QEMU TSC
    // rate when running with `-cpu Haswell-v4`. Real PIT/HPET-based
    // calibration lands with `23§3` once we have a usable HPET MMIO
    // mapping. monotonic_ns degenerates to 0 if not set, so this is
    // strictly an upgrade from "no time" to "approximate time".
    hal_x86_64::set_tsc_khz(2_400_000);
    klog::set_clock_fn(now_ns_x86);
    debug_boot! { log_cpu_info(); }
    // SAFETY: boot path per fn contract; build_boot_info reads
    // bootloader-owned static state and produces an owned BootInfo.
    let info = unsafe { build_boot_info() };
    // SAFETY: kernel_main's safety contract is satisfied by the
    // boot environment we just established (kernel stack installed,
    // IRQs masked, single CPU, `info` valid).
    unsafe { kernel::kernel_main(&info) }
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
