// Architecture-neutral MSI vector allocator for virtio + future PCI
// drivers. Today this hands out SPI numbers from the GICv2m frame's
// allocatable range on aarch64; x86 MSI-vector allocation rides
// alongside the LAPIC vector allocator and is wired in F38+.
//
// Per `34§*`. Allocation is monotonic — frees + reuse will be added
// when virtio drivers learn to release vectors at shutdown (no
// shutdown path exists in v1).

#![no_std]

extern crate alloc;

use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

/// Kernel VA the GICv2m frame is device-mapped at. Published by
/// `device_map_smoke_arm` after mapping. Zero = unmapped.
/// SETSPI_NS register lives at `+0x040`.
pub static GICV2M_VA: AtomicU64 = AtomicU64::new(0);

/// First SPI the GICv2m frame can trigger. Published by F36's TYPER
/// read at boot. Zero = no GICv2m discovered (e.g. pre-init or x86).
pub static GICV2M_SPI_FIRST: AtomicU32 = AtomicU32::new(0);
/// Number of consecutive SPIs the GICv2m frame supports.
pub static GICV2M_SPI_COUNT: AtomicU32 = AtomicU32::new(0);
/// Bump cursor for SPI allocation. Initialised lazily from
/// `GICV2M_SPI_FIRST` on the first call.
#[cfg(target_arch = "aarch64")]
static SPI_NEXT: AtomicU32 = AtomicU32::new(0);

/// Count of MSI deliveries observed by the IRQ dispatcher, per arch.
/// Bumped every time `oxide_arm_irq_dispatch` (or x86 equivalent)
/// sees an INTID in the GICv2m SPI range. Diagnostic only — once
/// virtio drivers learn to dispatch by SPI to a specific completion
/// callback, this counter goes away.
pub static MSI_FIRES: AtomicU32 = AtomicU32::new(0);

/// True iff `intid` falls inside the published v2m SPI range. Cheap
/// check used by the per-arch IRQ dispatcher.
/// # C: O(1) — two atomic loads.
pub fn intid_is_v2m(intid: u32) -> bool {
    let first = GICV2M_SPI_FIRST.load(Ordering::Acquire);
    let count = GICV2M_SPI_COUNT.load(Ordering::Acquire);
    first != 0 && count != 0 && intid >= first && intid < first + count
}

/// Bump-allocator over the MSI vector pool (`VEC_MSI_POOL_FIRST..=
/// VEC_MSI_POOL_LAST`). Each MSI-X-capable device on the boot scan
/// gets a distinct vector; the arch-irq dispatcher routes each one
/// to its registered handler (see `register_msi_handler`).
/// Returns `None` once the pool is exhausted — caller falls back to
/// the polling kthread path.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn alloc_x86_vector() -> Option<u8> {
    let cur = MSI_VEC_NEXT.fetch_add(1, Ordering::AcqRel);
    if cur > hal_x86_64::VEC_MSI_POOL_LAST { return None; }
    Some(cur)
}

#[cfg(target_arch = "x86_64")]
static MSI_VEC_NEXT: core::sync::atomic::AtomicU8 =
    core::sync::atomic::AtomicU8::new(hal_x86_64::VEC_MSI_POOL_FIRST);

/// Per-vector MSI handler table. Indexed by `vector -
/// VEC_MSI_POOL_FIRST`. Drivers register at boot via
/// `register_msi_handler`; the LAPIC dispatcher looks up + calls
/// each fired vector's handler. Null = no handler installed
/// (dispatcher falls back to the legacy shared-vector softirq raise).
#[cfg(target_arch = "x86_64")]
pub(crate) static MSI_HANDLERS: [core::sync::atomic::AtomicPtr<()>;
    hal_x86_64::VEC_MSI_POOL_LEN] = {
    [
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
        core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    ]
};

/// Install `handler` as the per-vector dispatch target for IDT vector
/// `vector` (must be in `VEC_MSI_POOL_FIRST..=VEC_MSI_POOL_LAST`).
/// Idempotent; later calls overwrite. Returns Ok on success, Err if
/// the vector is outside the pool.
/// # C: O(1) atomic store
#[cfg(target_arch = "x86_64")]
pub fn register_msi_handler(vector: u8, handler: fn()) -> Result<(), ()> {
    if vector < hal_x86_64::VEC_MSI_POOL_FIRST
        || vector > hal_x86_64::VEC_MSI_POOL_LAST
    {
        return Err(());
    }
    let idx = (vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    MSI_HANDLERS[idx].store(
        handler as *mut (), Ordering::Release,
    );
    Ok(())
}

/// Per-SPI handler table for the GICv2m / LPI MSI range. Two
/// parallel atomic arrays so the storage stays Send+Sync without
/// a lock: SPIs[i] holds the INTID for slot i (0 = empty), HANDS[i]
/// holds the fn pointer cast through `*mut ()`. Lookup scans the
/// 8-slot table — v1 has ≤ 4 MSI devices, so the scan is cheap.
#[cfg(target_arch = "aarch64")]
const ARM_MSI_SLOTS: usize = 8;

#[cfg(target_arch = "aarch64")]
pub(crate) static ARM_MSI_SPIS: [core::sync::atomic::AtomicU32; ARM_MSI_SLOTS] = [
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
];
#[cfg(target_arch = "aarch64")]
pub(crate) static ARM_MSI_HANDS: [core::sync::atomic::AtomicPtr<()>; ARM_MSI_SLOTS] = [
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
];

/// Install `handler` for INTID `spi`. Idempotent — re-registers
/// overwrite. Returns Err if the table is full (all 8 slots used
/// by other SPIs).
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn register_msi_handler(spi: u32, handler: fn()) -> Result<(), ()> {
    // First pass: replace an existing entry for this SPI.
    for i in 0..ARM_MSI_SLOTS {
        if ARM_MSI_SPIS[i].load(Ordering::Acquire) == spi {
            ARM_MSI_HANDS[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    // Second pass: claim the first empty slot via CAS on the SPI cell.
    for i in 0..ARM_MSI_SLOTS {
        if ARM_MSI_SPIS[i]
            .compare_exchange(0, spi, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            ARM_MSI_HANDS[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

/// Dispatch path. Returns true iff a handler was found + invoked.
/// Called by the GIC dispatcher on every recognised MSI INTID.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_spi_handler(intid: u32) -> bool {
    for i in 0..ARM_MSI_SLOTS {
        if ARM_MSI_SPIS[i].load(Ordering::Acquire) == intid {
            let raw = ARM_MSI_HANDS[i].load(Ordering::Acquire);
            if !raw.is_null() {
                // SAFETY: raw was installed via `register_msi_handler` with the documented `fn()` signature; reverse cast restores the ABI-compatible fn pointer.
                let f: fn() = unsafe { core::mem::transmute(raw) };
                f();
                return true;
            }
            return false;
        }
    }
    false
}

// Stub for non-aarch64 builds so unconditional callers compile.
/// # C: O(1)
#[cfg(not(target_arch = "aarch64"))]
pub fn invoke_arm_spi_handler(_intid: u32) -> bool { false }

/// Allocate one SPI from the GICv2m frame's range. Returns `None`
/// when the range is unconfigured or exhausted.
/// # C: O(1) — atomic CAS bump.
#[cfg(target_arch = "aarch64")]
pub fn alloc_arm_spi() -> Option<u32> {
    let first = GICV2M_SPI_FIRST.load(Ordering::Acquire);
    let count = GICV2M_SPI_COUNT.load(Ordering::Acquire);
    if first == 0 || count == 0 { return None; }
    // Lazy cursor init.
    let _ = SPI_NEXT.compare_exchange(0, first, Ordering::AcqRel, Ordering::Relaxed);
    let cur = SPI_NEXT.fetch_add(1, Ordering::AcqRel);
    if cur >= first + count { return None; }
    Some(cur)
}


#[cfg(target_os = "oxide-kernel")] pub mod gic;
#[cfg(target_os = "oxide-kernel")] pub mod its;
#[cfg(target_os = "oxide-kernel")] pub mod lapic;

/// Hook for "poll the UART for input on each timer tick". Kernel
/// installs this from `kernel/src/tty.rs::tick_poll_uart` at boot.
/// gic / lapic call through here instead of hard-linking to tty —
/// keeps arch-irq free of kernel-side tty integration.
pub type TickPollFn = unsafe fn();
static TICK_POLL_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1) — atomic store.
pub fn set_tick_poll_hook(f: TickPollFn) {
    TICK_POLL_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// # SAFETY: caller is timer-ISR ctx; hook installed by kernel boot.
/// # C: O(1) — atomic load + indirect call.
pub unsafe fn tick_poll() {
    let p = TICK_POLL_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook ptr installed at boot from a fn matching TickPollFn ABI; load Acquire-paired with Release store in set_tick_poll_hook.
    unsafe {
        let f: TickPollFn = core::mem::transmute(p);
        f()
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod smp_x86;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod ap_tramp_x86;
