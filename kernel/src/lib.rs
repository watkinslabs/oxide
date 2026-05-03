// Kernel library. The actual binary is the per-arch boot crate
// (`crates/boot-x86_64`, `crates/boot-aarch64`) which provides the
// arch `_start` symbol, sets up a minimal env, then tail-calls
// `kernel_main`.
//
// This library is `#![no_std]`; it compiles on host so hosted unit
// tests can exercise everything that doesn't require asm.
//
// Phase 0 exit goal per `00§3`: hello-world boots both arches via
// QEMU, prints "init started" on UART, exits cleanly. The string is
// emitted here; the UART backend is wired by the per-arch boot
// crate.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;

pub mod pmm_setup;

/// Kernel-wide heap allocator per `12§2`. Fixed-size BSS heap for v1;
/// replaced by PMM-backed slab routing once a binary stage exists.
/// Hosts the `BTreeMap` / `Vec` machinery used by `vmm::VmaTree` and
/// later subsystems.
///
/// Gated `cfg(target_os = "oxide-kernel")` so the declaration is
/// active only when building for the kernel targets in `targets/`.
/// Host builds (used by hosted tests in this and downstream crates)
/// keep `std`'s default allocator.
#[cfg(target_os = "oxide-kernel")]
#[global_allocator]
static GLOBAL_ALLOC: kalloc::KAlloc = kalloc::KAlloc::new();

/// Boot info passed by the arch boot stub.
///
/// Layout is bootloader-defined per `36`; the stub parses the
/// bootloader-specific blob (Limine info on x86_64, DTB/EDK2 on
/// aarch64) and hands a uniform view to the kernel.
#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootInfo {
    /// Number of memory map entries.
    pub memmap_count: u32,
    /// Pointer to a `[BootMemRegion; memmap_count]`.
    pub memmap_ptr: *const BootMemRegion,
    /// Bootloader-provided initial entropy (RDRAND on x86; RNDR on
    /// arm; bootloader-collected jitter as fallback).
    pub seed: [u8; 32],
    /// Boot-time monotonic counter snapshot in nanoseconds.
    pub boot_ns: u64,
    /// Higher-half direct-map offset (Limine HHDM, `36§3`). For any
    /// physical address `pa` covered by HHDM, the kernel-VA mirror
    /// is `hhdm_offset + pa`. `0` means the bootloader did not
    /// populate the HHDM response (early-boot diagnostics, hosted
    /// tests, or stub paths).
    pub hhdm_offset: u64,
}

#[repr(C)]
#[derive(Copy, Clone, Debug)]
pub struct BootMemRegion {
    pub base_pa: u64,
    pub len: u64,
    pub kind: BootMemKind,
}

#[repr(u8)]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum BootMemKind {
    Usable = 0,
    Reserved = 1,
    AcpiReclaim = 2,
    AcpiNvs = 3,
    BadMem = 4,
    BootloaderUsed = 5,
    KernelImage = 6,
    Initramfs = 7,
}

/// Kernel entry. Called by per-arch boot stub after low-level setup.
///
/// # SAFETY: caller has set up a valid kernel stack, mapped the kernel
/// image at the upper-half virtual address per the linker script, set
/// per-CPU base register, and disabled interrupts. `info` points to a
/// valid `BootInfo` whose `memmap_ptr` references valid memory for at
/// least `memmap_count` entries.
///
/// # C: not measured (one-shot init)
/// # Ctx: pre-init, IRQ-off, single-CPU
pub unsafe fn kernel_main(info: &BootInfo) -> ! {
    // Bring up the kernel heap before any subsystem that allocates.
    // SAFETY: kernel_main is called once per boot from a single CPU
    // with IRQs off; `STATIC_HEAP` is BSS-resident, exclusively owned
    // by `kalloc`, and not yet referenced by anything else.
    #[cfg(target_os = "oxide-kernel")]
    unsafe { GLOBAL_ALLOC.init_static() };

    klog::kinfo!("init started");
    if info.hhdm_offset != 0 {
        klog::kinfo!("hhdm: present");
    } else {
        klog::kinfo!("hhdm: absent");
    }
    if info.memmap_count != 0 {
        klog::kinfo!("memmap: present");
    } else {
        klog::kinfo!("memmap: absent");
    }

    // Bring up the physical memory manager.
    // SAFETY: kernel_main fn-contract; single-CPU, IRQs off, info
    // outlives the call.
    let pmm = unsafe { pmm_setup::init_from_boot_info(info) };
    match &pmm {
        Ok(_)                                       => klog::kinfo!("pmm: ready"),
        Err(pmm_setup::SetupError::NoMemmap)        => klog::kinfo!("pmm: skip (no memmap)"),
        Err(pmm_setup::SetupError::NoHhdm)          => klog::kinfo!("pmm: skip (no hhdm)"),
        Err(pmm_setup::SetupError::NoUsableRegion)  => klog::kerror!("pmm: no usable region"),
        Err(pmm_setup::SetupError::NoSpaceForBitmaps) => klog::kerror!("pmm: pool too big"),
        Err(pmm_setup::SetupError::TooManyRegions)  => klog::kerror!("pmm: too many regions"),
        Err(pmm_setup::SetupError::PmmInit(_))      => klog::kerror!("pmm: Pmm::init refused"),
        Err(pmm_setup::SetupError::AlreadyInit)     => klog::kerror!("pmm: already init"),
    }
    // Runtime smoke: alloc/free at order 0 to prove the buddy
    // machinery works after init. Removed once a real consumer
    // (slab) wires in.
    if let Ok(p) = pmm {
        match p.alloc(pmm::Order(0)) {
            Ok(pfn) => {
                klog::kinfo!("pmm-smoke: alloc(0) ok");
                // SAFETY: pfn was just returned by alloc(0); free is
                // the matching counterpart and is single-threaded
                // here per pre-init contract.
                unsafe { p.free(pfn, pmm::Order(0)); }
                klog::kinfo!("pmm-smoke: free(0) ok");
            }
            Err(_) => klog::kerror!("pmm-smoke: alloc(0) failed"),
        }
    }


    // Smoke test: round-trip a `vmm::VmaTree` through the heap so a
    // boot trace surfaces any allocator-vs-BTreeMap incompatibility
    // before further subsystems wire up.
    #[cfg(target_os = "oxide-kernel")]
    {
        let mut tree = vmm::VmaTree::new();
        // SAFETY: addresses are within the user-VA range (0x1000 < USER_VA_END).
        let start = hal::UserVirtAddr::new(0x1000).expect("test addr in user range");
        let end   = hal::UserVirtAddr::new(0x2000).expect("test addr in user range");
        let _ = tree.insert(vmm::Vma::new(
            start, end,
            vmm::VmaProt::READ,
            vmm::VmaFlags::PRIVATE | vmm::VmaFlags::ANONYMOUS,
            vmm::VmaBacking::Anonymous,
        ));
        let _ = core::hint::black_box(tree.len());
    }

    halt_forever()
}

/// Spin forever. Used by `kernel_main` and the panic flow until a
/// real HAL `halt()` is wired in by the boot crate.
///
/// # C: O(∞)
pub fn halt_forever() -> ! {
    loop {
        core::hint::spin_loop();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_info_layout_is_repr_c() {
        // Sanity check: BootInfo size is determinist on a 64-bit host.
        // u32 + ptr + [u8;32] + u64 + u64 with natural alignment.
        assert!(core::mem::size_of::<BootInfo>() >= 60);
    }

    #[test]
    fn boot_mem_kind_distinct() {
        assert_ne!(BootMemKind::Usable as u8, BootMemKind::BadMem as u8);
    }
}
