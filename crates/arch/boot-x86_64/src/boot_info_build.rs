use core::cell::UnsafeCell;

use boot_info::{BootInfo, BootMemRegion};

// MB2 tag parsing is reached only from the `oxide-kernel` arms below.
#[cfg(target_os = "oxide-kernel")]
use crate::mb2;

/// Build a hard-coded minimal `BootInfo` for compile-test purposes and
/// for the unsupported-loader path (`36§3`: an entry that did not come
/// through the multiboot2 trampoline hands us no memory map).
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
        framebuffer: boot_info::BootFramebuffer::EMPTY,
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

/// One-past-the-end pointer for the boot stack installed by `_start`.
/// # SAFETY: caller must run on the single-CPU boot path before scheduler init.
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn kernel_stack_top() -> *mut u8 {
    // SAFETY: KERNEL_STACK is boot-owned and STACK_SIZE is exactly its byte length.
    unsafe { (KERNEL_STACK.0.get() as *mut u8).add(STACK_SIZE) }
}

/// Storage for `BootInfo`'s memmap slice — populated from the
/// multiboot2 memory-map tag by `_start_rust` before `kernel_main` runs.
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
        kind:    boot_info::BootMemKind::Reserved,
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

/// Copy the multiboot2 boot-command-line tag (type 1) into
/// kernel-owned `CMDLINE_STORAGE` and publish via `cmdline::set`.
/// No-op when the loader supplied no cmdline — the kernel then falls
/// back to `install_arch_default`.
///
/// # SAFETY: called once from the boot path before any procfs read
/// can race; `CMDLINE_STORAGE` is a 'static slot.
/// # C: O(cmdline_len)
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn capture_cmdline() {
    if !mb2::info::is_mb2_boot() { return; }
    // SAFETY: cmdline_va returns an HHDM-mapped pointer into the MB2
    // info struct (NUL-terminated); the copy below is buffer-bounded.
    let Some(src) = (unsafe { mb2::info::cmdline_va() }) else { return };
    // SAFETY: CMDLINE_STORAGE is the 'static boot-only slot; this is
    // the sole writer and it runs before any reader exists.
    let dst = unsafe { &mut *CMDLINE_STORAGE.0.get() };
    let mut n = 0usize;
    while n < CMDLINE_BUF_LEN - 1 {
        // SAFETY: src[..] is a NUL-terminated C string in the HHDM-mapped
        // MB2 info region; read one byte at a time, bounded by the buffer.
        let b = unsafe { core::ptr::read_volatile(src.add(n)) };
        if b == 0 { break; }
        dst[n] = b;
        n += 1;
    }
    if n == 0 { return; }
    // Linux convention: /proc/cmdline ends with '\n'. The arch-default
    // does the same; mirror it here for round-trip parity.
    if n < CMDLINE_BUF_LEN - 1 { dst[n] = b'\n'; n += 1; }
    // SAFETY: dst[..n] initialised above; CMDLINE_STORAGE is 'static.
    let bytes: &'static [u8] = unsafe {
        core::slice::from_raw_parts(dst.as_ptr(), n)
    };
    // SAFETY: cmdline::set is single-writer / boot-only.
    unsafe { cmdline::set(bytes); }
}

/// Build a `BootInfo` from the multiboot2 info struct the trampoline
/// stashed (`36§3`). Falls back to an empty memmap when the entry did
/// not come through the multiboot2 trampoline (no supported loader).
///
/// # SAFETY: caller is the boot path; the trampoline has either saved a
/// valid multiboot2 magic + info pointer or left both zero; the `seed`
/// slot stays zero until CRNG bring-up populates it.
/// # C: O(min(entry_count, MAX_BOOT_REGIONS))
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn build_boot_info() -> BootInfo {
    use hal::TimerOps;
    if !mb2::info::is_mb2_boot() {
        // SAFETY: returns an owned BootInfo whose `memmap_ptr`
        // references a `&'static` empty slice.
        return unsafe { stub_boot_info() };
    }
    // SAFETY: MEMMAP_STORAGE is boot-owned; build_memmap fills it from
    // the MB2 info struct (HHDM-mapped, parsed pre-PMM).
    let storage = unsafe { &mut *MEMMAP_STORAGE.0.get() };
    // SAFETY: trampoline wrote a valid MB2-info ptr; build_memmap parses
    // the HHDM-mapped struct, filling boot-owned storage.
    let (n, rsdp_pa, framebuffer) = unsafe { mb2::info::build_memmap(storage) };
    BootInfo {
        memmap_count: n as u32,
        memmap_ptr:   storage.as_ptr(),
        seed:         [0; 32],
        boot_ns:      hal_x86_64::X86TimerOps::monotonic_ns().0,
        hhdm_offset:  mb2::info::MB2_HHDM,
        rsdp_pa,
        framebuffer,
        // The handoff has no CPU identity. Read the architectural initial
        // APIC id before the LAPIC mapping exists; ACPI supplies the rest.
        bsp_lapic_id: hal_x86_64::initial_apic_id(),
        _pad: 0,
    }
}
