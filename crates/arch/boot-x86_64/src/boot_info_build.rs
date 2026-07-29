use core::cell::UnsafeCell;

use boot_info::{BootInfo, BootMemRegion};

// MB2 tag parsing is reached only from the `oxide-kernel` arms below.
#[cfg(target_os = "oxide-kernel")]
use crate::mb2;
use crate::{
    limine,
    requests::{
        LIMINE_EXECUTABLE_FILE, LIMINE_HHDM, LIMINE_KERNEL_FILE, LIMINE_MEMMAP, LIMINE_RSDP,
        LIMINE_SMP,
    },
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

/// One-past-the-end pointer for the boot stack installed by `_start`.
/// # SAFETY: caller must run on the single-CPU boot path before scheduler init.
#[cfg(target_os = "oxide-kernel")]
pub(crate) unsafe fn kernel_stack_top() -> *mut u8 {
    // SAFETY: KERNEL_STACK is boot-owned and STACK_SIZE is exactly its byte length.
    unsafe { (KERNEL_STACK.0.get() as *mut u8).add(STACK_SIZE) }
}

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

/// Read the bootloader's executable-file cmdline (Limine config
/// `cmdline: …`), copy into kernel-owned `CMDLINE_STORAGE`, and
/// publish via `cmdline::set`. No-op if the bootloader
/// didn't fill the response or the cmdline is empty — the kernel
/// then falls back to `install_arch_default`.
///
/// # SAFETY: called once from the boot path before any procfs read
/// can race; `CMDLINE_STORAGE` is a 'static slot.
/// # C: O(cmdline_len)
pub(crate) unsafe fn capture_cmdline() {
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
                    unsafe { cmdline::set(bytes); }
                }
            }
            return;
        }
    }
    let mut resp_ptr = LIMINE_EXECUTABLE_FILE
        .response.load(core::sync::atomic::Ordering::Acquire);
    if resp_ptr.is_null() {
        resp_ptr = LIMINE_KERNEL_FILE
            .response.load(core::sync::atomic::Ordering::Acquire);
    }
    if resp_ptr.is_null() { return; }
    // SAFETY: bootloader wrote a valid &ExecutableFileResponse before
    // handing control to the kernel; pointer in HHDM-mapped region.
    let resp = unsafe { &*resp_ptr };
    if resp.executable_file.is_null() { return; }
    // SAFETY: bootloader-allocated LimineFile valid for the boot
    // window (until BootloaderReclaimable pages are recycled — which
    // happens long after we've copied the cmdline out).
    let file = unsafe { &*resp.executable_file };
    if file.cmdline.is_null() { return; }
    // Copy NUL-terminated bytes (bounded by CMDLINE_BUF_LEN-1, leaves
    // a final NUL so the slice can be safely passed to anyone treating
    // it as a C string).
    // SAFETY: dst is the 'static CMDLINE_STORAGE; we are the sole
    // writer before any reader exists.
    let dst = unsafe { &mut *CMDLINE_STORAGE.0.get() };
    let mut n = 0usize;
    while n < CMDLINE_BUF_LEN - 1 {
        // SAFETY: bootloader-owned C string; read one byte at a time
        // until NUL or our cap.
        let b = unsafe { core::ptr::read_volatile(file.cmdline.add(n)) };
        if b == 0 { break; }
        dst[n] = b;
        n += 1;
    }
    if n == 0 { return; }
    // Linux convention: /proc/cmdline ends with '\n'. The arch-default
    // does the same; mirror it here for round-trip parity.
    if n < CMDLINE_BUF_LEN - 1 { dst[n] = b'\n'; n += 1; }
    // SAFETY: dst[..n] is initialised above; 'static lifetime.
    let bytes: &'static [u8] = unsafe {
        core::slice::from_raw_parts(dst.as_ptr(), n)
    };
    // Kernel-only: `cmdline` is
    // `#[cfg(target_os = "oxide-kernel")]`, so the host
    // (`cargo test --workspace`) build must not reference it.
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: cmdline::set is single-writer / boot-only; bytes is a 'static slice with the captured cmdline.
    unsafe { cmdline::set(bytes); }
    #[cfg(not(target_os = "oxide-kernel"))]
    let _ = bytes;
}

/// Build a `BootInfo` by reading the bootloader-populated Limine
/// responses. Falls back to an empty memmap if the bootloader didn't
/// fill the response slot (e.g. running outside Limine).
///
/// # SAFETY: caller is the boot path; the bootloader has either
/// written real response pointers or left them null; the `seed` /
/// `boot_ns` slots are zero until ACPI / RTC bring-up populates them.
/// # C: O(min(entry_count, MAX_BOOT_REGIONS))
pub(crate) unsafe fn build_boot_info() -> BootInfo {
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
