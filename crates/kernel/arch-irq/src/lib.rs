// Architecture-neutral MSI vector allocator for virtio + future PCI
// drivers. Device drivers own allocation at probe and release at
// remove, matching the rest of the driver-core lifecycle.

#![no_std]

extern crate alloc;

pub mod cache;
mod line;

pub use line::LineHandler;
#[cfg(target_arch = "x86_64")]
pub use line::{free_irq_line_handler, invoke_x86_line_handler, register_irq_line_handler};
#[cfg(target_arch = "aarch64")]
pub use line::{
    free_arm_irq_line_handler, free_msi_line_handler, invoke_arm_irq_line_handler,
    invoke_arm_spi_line_handler, register_msi_line_handler, request_arm_irq_line_handler,
};

#[cfg(target_arch = "x86_64")]
use core::sync::atomic::AtomicBool;
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

/// Allocate one vector from the x86 MSI pool. Returns `None` once the
/// pool is exhausted.
/// # C: O(N) where N is the small MSI vector pool.
#[cfg(target_arch = "x86_64")]
pub fn alloc_x86_vector() -> Option<u8> {
    for idx in 0..hal_x86_64::VEC_MSI_POOL_LEN {
        if MSI_VEC_USED[idx]
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(hal_x86_64::VEC_MSI_POOL_FIRST + idx as u8);
        }
    }
    None
}

#[cfg(target_arch = "x86_64")]
static MSI_VEC_USED: [AtomicBool; hal_x86_64::VEC_MSI_POOL_LEN] = [
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

/// Per-vector MSI handler table. Indexed by `vector -
/// VEC_MSI_POOL_FIRST`. Drivers register at boot via
/// `register_msi_handler`; the LAPIC dispatcher looks up + calls
/// each fired vector's handler. Null = no handler installed.
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

/// Remove the handler and release `vector` back to the x86 MSI pool.
/// # C: O(1)
#[cfg(target_arch = "x86_64")]
pub fn free_x86_vector(vector: u8) -> Result<(), ()> {
    if vector < hal_x86_64::VEC_MSI_POOL_FIRST
        || vector > hal_x86_64::VEC_MSI_POOL_LAST
    {
        return Err(());
    }
    let idx = (vector - hal_x86_64::VEC_MSI_POOL_FIRST) as usize;
    MSI_HANDLERS[idx].store(core::ptr::null_mut(), Ordering::Release);
    let _ = line::free_irq_line_handler(vector as u32);
    MSI_VEC_USED[idx].store(false, Ordering::Release);
    Ok(())
}

/// Per-SPI handler table for fixed ARM device lines. Drivers request
/// their owned INTID during probe and free it during remove; the GIC
/// dispatcher invokes only the installed owner.
#[cfg(target_arch = "aarch64")]
const ARM_IRQ_SLOTS: usize = 16;

#[cfg(target_arch = "aarch64")]
static ARM_IRQ_INTIDS: [core::sync::atomic::AtomicU32; ARM_IRQ_SLOTS] = [
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
    core::sync::atomic::AtomicU32::new(0),
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
static ARM_IRQ_HANDS: [core::sync::atomic::AtomicPtr<()>; ARM_IRQ_SLOTS] = [
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()),
];

/// Install `handler` for a fixed ARM INTID owned by a platform driver.
/// Returns Err if another driver already owns the line or the small table
/// is full.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn request_arm_irq_handler(intid: u32, handler: fn()) -> Result<(), ()> {
    if intid == 0 {
        return Err(());
    }
    for i in 0..ARM_IRQ_SLOTS {
        if ARM_IRQ_INTIDS[i].load(Ordering::Acquire) == intid {
            return Err(());
        }
    }
    for i in 0..ARM_IRQ_SLOTS {
        if ARM_IRQ_INTIDS[i]
            .compare_exchange(0, intid, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            ARM_IRQ_HANDS[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

/// Remove a fixed ARM INTID handler.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_arm_irq_handler(intid: u32) -> Result<(), ()> {
    for i in 0..ARM_IRQ_SLOTS {
        if ARM_IRQ_INTIDS[i].load(Ordering::Acquire) == intid {
            ARM_IRQ_HANDS[i].store(core::ptr::null_mut(), Ordering::Release);
            let _ = line::free_arm_irq_line_handler(intid);
            ARM_IRQ_INTIDS[i].store(0, Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

/// Dispatch path for fixed ARM device INTIDs.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn invoke_arm_irq_handler(intid: u32) -> bool {
    for i in 0..ARM_IRQ_SLOTS {
        if ARM_IRQ_INTIDS[i].load(Ordering::Acquire) == intid {
            let raw = ARM_IRQ_HANDS[i].load(Ordering::Acquire);
            if !raw.is_null() {
                // SAFETY: raw was installed via `request_arm_irq_handler`
                // with the documented `fn()` signature.
                let f: fn() = unsafe { core::mem::transmute(raw) };
                f();
                return true;
            }
            return false;
        }
    }
    false
}

/// Per-INTID handler table for the GICv2m SPI / GICv3 LPI MSI range. Two
/// parallel atomic arrays so the storage stays Send+Sync without
/// a lock: SPIS[i] holds the INTID for slot i (0 = empty), HANDS[i]
/// holds the fn pointer cast through `*mut ()`. Lookup scans the
/// fixed-size table: B002 boots enough MSI devices that eight slots is too
/// small; the scan stays cheap at this size.
#[cfg(target_arch = "aarch64")]
const ARM_MSI_SLOTS: usize = 32;

#[cfg(target_arch = "aarch64")]
pub(crate) static ARM_MSI_SPIS: [core::sync::atomic::AtomicU32; ARM_MSI_SLOTS] =
    [const { core::sync::atomic::AtomicU32::new(0) }; ARM_MSI_SLOTS];
#[cfg(target_arch = "aarch64")]
pub(crate) static ARM_MSI_HANDS: [core::sync::atomic::AtomicPtr<()>; ARM_MSI_SLOTS] =
    [const { core::sync::atomic::AtomicPtr::new(core::ptr::null_mut()) }; ARM_MSI_SLOTS];

/// Install `handler` for INTID `spi`. Idempotent for an allocated SPI.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn register_msi_handler(spi: u32, handler: fn()) -> Result<(), ()> {
    for i in 0..ARM_MSI_SLOTS {
        if ARM_MSI_SPIS[i].load(Ordering::Acquire) == spi {
            ARM_MSI_HANDS[i].store(handler as *mut (), Ordering::Release);
            return Ok(());
        }
    }
    Err(())
}

/// Remove the handler and release `spi` back to the aarch64 MSI pool.
/// # C: O(N) atomic scan
#[cfg(target_arch = "aarch64")]
pub fn free_arm_spi(spi: u32) -> Result<(), ()> {
    for i in 0..ARM_MSI_SLOTS {
        if ARM_MSI_SPIS[i].load(Ordering::Acquire) == spi {
            ARM_MSI_HANDS[i].store(core::ptr::null_mut(), Ordering::Release);
            let _ = line::free_msi_line_handler(spi);
            ARM_MSI_SPIS[i].store(0, Ordering::Release);
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
/// when the range is unconfigured or the driver's handler table is full.
/// # C: O(N²) over the small MSI table.
#[cfg(target_arch = "aarch64")]
pub fn alloc_arm_spi() -> Option<u32> {
    let first = GICV2M_SPI_FIRST.load(Ordering::Acquire);
    let count = GICV2M_SPI_COUNT.load(Ordering::Acquire);
    if first == 0 || count == 0 { return None; }
    let limit = if count as usize > ARM_MSI_SLOTS {
        ARM_MSI_SLOTS
    } else {
        count as usize
    };
    for off in 0..limit {
        let spi = first + off as u32;
        let mut seen = false;
        for i in 0..ARM_MSI_SLOTS {
            if ARM_MSI_SPIS[i].load(Ordering::Acquire) == spi {
                seen = true;
                break;
            }
        }
        if seen {
            continue;
        }
        for i in 0..ARM_MSI_SLOTS {
            if ARM_MSI_SPIS[i]
                .compare_exchange(0, spi, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(spi);
            }
        }
    }
    None
}

/// Allocate one LPI INTID for a GICv3 ITS-backed MSI/MSI-X vector.
/// LPI 8192 is reserved for the early ITS self-test mapping; runtime
/// drivers start at 8193.
/// # C: O(N²) over the small MSI table.
#[cfg(all(target_arch = "aarch64", target_os = "oxide-kernel"))]
pub fn alloc_arm_lpi() -> Option<u32> {
    let first = crate::gic::LPI_BASE + 1;
    let limit = first + ARM_MSI_SLOTS as u32;
    for lpi in first..limit {
        let mut seen = false;
        for i in 0..ARM_MSI_SLOTS {
            if ARM_MSI_SPIS[i].load(Ordering::Acquire) == lpi {
                seen = true;
                break;
            }
        }
        if seen {
            continue;
        }
        for i in 0..ARM_MSI_SLOTS {
            if ARM_MSI_SPIS[i]
                .compare_exchange(0, lpi, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(lpi);
            }
        }
    }
    None
}


#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))] pub mod gic;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))] pub mod its;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))] pub mod lapic;
mod deadline;
pub mod tick;
pub use deadline::install as install_timer_deadline_hook;
#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))] pub mod tlb;
pub mod irqstat;

/// Hook for BSP timer work that belongs above the arch IRQ layer.
/// gic / lapic call through here instead of hard-linking to kernel
/// subsystems, keeping arch-irq free of higher-level integration.
pub type TickPollFn = unsafe fn(from_user: bool);
static TICK_POLL_HOOK: core::sync::atomic::AtomicPtr<()> =
    core::sync::atomic::AtomicPtr::new(core::ptr::null_mut());

/// # C: O(1) — atomic store.
pub fn set_tick_poll_hook(f: TickPollFn) {
    TICK_POLL_HOOK.store(f as *mut (), core::sync::atomic::Ordering::Release);
}

/// Install the cross-CPU backtrace poke hook (NMI on x86, FIQ SGI on
/// arm) into `sched::diag::nmi`. Called once at boot so the hard-lockup
/// detector + sysrq backtrace can make a wedged CPU dump its own state.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn install_diag_nmi_hook() {
    #[cfg(target_arch = "x86_64")]
    lapic::install_diag_hooks();
    #[cfg(target_arch = "aarch64")]
    gic::install_diag_hooks();
}

/// `softirq` is a leaf crate; feed it the two scheduler/time inputs Linux's
/// `__do_softirq` restart gate reads — `need_resched()` (peek, not consumed)
/// and jiffies (this arch's timer-tick counter). The third input,
/// `wakeup_softirqd`, is installed by `sched::live::spawn_ksoftirqd` (it owns
/// the ksoftirqd thread). Without the gate the bottom-half drain has no
/// scheduler/time awareness and a self-re-raising softirq (virtio-net RX
/// under a flood) livelocks the CPU.
/// # C: O(1)
#[cfg(target_os = "oxide-kernel")]
pub fn install_softirq_hooks() {
    softirq::set_resched_hook(softirq_need_resched);
    softirq::set_jiffies_hook(softirq_jiffies);
}

/// Non-consuming `need_resched` peek for the softirq restart gate. Must NOT
/// consume the flag — the IRQ-exit slow path still owns the reschedule.
#[cfg(target_os = "oxide-kernel")]
fn softirq_need_resched() -> bool { sched::preempt::need_resched() }

/// This CPU's timer-tick counter as the softirq jiffies source.
#[cfg(target_os = "oxide-kernel")]
fn softirq_jiffies() -> u64 {
    #[cfg(target_arch = "x86_64")]
    { lapic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed) }
    #[cfg(target_arch = "aarch64")]
    { gic::TICK_COUNT.load(core::sync::atomic::Ordering::Relaxed) }
}

/// # SAFETY: caller is timer-ISR ctx; hook installed by kernel boot.
/// # C: O(1) — atomic load + indirect call.
pub unsafe fn tick_poll(from_user: bool) {
    let p = TICK_POLL_HOOK.load(core::sync::atomic::Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: hook ptr installed at boot from a fn matching TickPollFn ABI; load Acquire-paired with Release store in set_tick_poll_hook.
    unsafe {
        let f: TickPollFn = core::mem::transmute(p);
        f(from_user)
    }
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub mod smp_x86;
#[cfg(all(target_os = "oxide-kernel", target_arch = "aarch64"))] pub mod smp_arm;
