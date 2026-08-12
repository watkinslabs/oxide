// virtio-gpu modern display setup. Called by the virtio-gpu model driver's
// probe after virtio-pci transport init has produced queue0/config state.

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

struct ProbeCommandBuffer {
    pa: u64,
    dma: u64,
    bdf: pci::Bdf,
    va: *mut u8,
    owned: bool,
}

impl ProbeCommandBuffer {
    fn alloc(hhdm: u64, bdf: pci::Bdf) -> Option<Self> {
        let pa = pmm::setup::alloc_one_frame()?;
        let Some(dma) = iommu::map_dma(bdf, pa, hal::PAGE_SIZE_BYTES as usize) else {
            // SAFETY: no device mapping exists for this failed allocation.
            unsafe { pmm::setup::free_one_frame(pa); }
            return None;
        };
        Some(Self {
            pa,
            dma,
            bdf,
            va: hhdm.wrapping_add(pa) as *mut u8,
            owned: true,
        })
    }

    fn disarm(&mut self) {
        self.owned = false;
    }
}

impl Drop for ProbeCommandBuffer {
    fn drop(&mut self) {
        if self.owned {
            if !iommu::unmap_dma(self.bdf, self.dma, hal::PAGE_SIZE_BYTES as usize) {
                return;
            }
            // SAFETY: `owned` still set means this probe never handed the frame
            // to the device — every path that publishes a descriptor naming it,
            // or that times out with one outstanding, calls `disarm` first — so
            // the frame is this struct's alone and is freed exactly once.
            unsafe { pmm::setup::free_one_frame(self.pa); }
        }
    }
}

struct ProbeFramebufferRun {
    base_pa: u64,
    base_dma: u64,
    map_bytes: usize,
    bdf: pci::Bdf,
    order: pmm::Order,
    owned: bool,
}

impl ProbeFramebufferRun {
    fn alloc(bdf: pci::Bdf, order: pmm::Order) -> Option<Self> {
        let base_pa = pmm::setup::alloc_contig(order)?;
        let map_bytes = (hal::PAGE_SIZE_BYTES as usize).checked_shl(order.0 as u32)?;
        let Some(base_dma) = iommu::map_dma(bdf, base_pa, map_bytes) else {
            // SAFETY: no device mapping exists for this failed allocation.
            unsafe { pmm::setup::free_contig(base_pa, order); }
            return None;
        };
        Some(Self {
            base_pa,
            base_dma,
            map_bytes,
            bdf,
            order,
            owned: true,
        })
    }

    fn disarm(&mut self) {
        self.owned = false;
    }
}

impl Drop for ProbeFramebufferRun {
    fn drop(&mut self) {
        if self.owned {
            if !iommu::unmap_dma(self.bdf, self.base_dma, self.map_bytes) {
                return;
            }
            // SAFETY: `owned` still set means ATTACH_BACKING never succeeded, so
            // the device's resource table does not name this run; `setup_scanout`
            // calls `disarm` the moment it does. Same order it was allocated at,
            // freed exactly once.
            unsafe {
                pmm::setup::free_contig(self.base_pa, self.order);
            }
        }
    }
}

struct ScanoutCtx {
    device_key: virtio::VirtioChildDeviceKey,
    cfg_va: u64,
    w: u32,
    h: u32,
    fb_va: u64,
    fb_dma: u64,
    fb_map_bytes: usize,
    fb_bytes: u64,
    fb_order: pmm::Order,
    res_id: u32,
    ctrlq: Option<virtio::VirtioSplitQueue>,
    cursorq: Option<virtio::VirtioSplitQueue>,
    cmd_buf_va: u64,
    cmd_buf_pa: u64,
    cmd_buf_dma: u64,
    bdf: pci::Bdf,
    hhdm: u64,
    fbdev_idx: Option<u32>,
    quiesced: bool,
    /// What scanout 0 is currently bound to, or `None` before the first bind.
    /// Owning it here is what lets a redundant SET_SCANOUT be skipped.
    bound: Option<present::Binding>,
}

static CTX: Spinlock<Vec<ScanoutCtx>, DriverLockClass> = Spinlock::new(Vec::new());

/// Bottom-half gate for `CTX` holders: real softirq exclusion in the kernel,
/// a no-op under hosted tests, which have no softirqs to exclude.
#[cfg(target_os = "oxide-kernel")]
type CtxBh = sched::bh::SchedBh;
#[cfg(not(target_os = "oxide-kernel"))]
type CtxBh = sync::NoopBh;

/// Process-context `CTX` acquisition. `CTX` is shared with the `FbconFlush`
/// softirq (`scanout::fbcon_flush_pixels`), so every process-context hold must
/// exclude local bottom halves for its whole duration; a softirq arriving on
/// IRQ-exit over a bare holder spins forever on the lock whose owner it just
/// interrupted — a one-CPU deadlock that freezes the boot the moment the VT
/// becomes `/dev/console` and status output keeps the flush pending.
/// The softirq itself takes `CTX.lock()` bare: with every other holder gated,
/// it can no longer interrupt one, and cross-CPU contention is bounded.
/// # C: O(contention) # Lk: CTX; softirqs off on this CPU
fn ctx_lock() -> sync::LockBhGuard<'static, Vec<ScanoutCtx>, DriverLockClass, CtxBh> {
    CTX.lock_bh::<CtxBh>()
}
#[cfg(test)]
static TEST_LOCK: Spinlock<(), DriverLockClass> = Spinlock::new(());
const NO_CONSOLE_OWNER_KEY: u32 = u32::MAX;
static CONSOLE_OWNER_KEY: AtomicU32 = AtomicU32::new(NO_CONSOLE_OWNER_KEY);

/// Boot fbcon scanout resource id (set up by `setup_scanout`).
pub const BOOT_SCANOUT_RES_ID: u32 = 1;

/// Runtime resource-id allocator. Boot fb is res_id 1; runtime KMS
/// resources start at 2 so they never collide with the console fb.
static NEXT_RUNTIME_RES_ID: AtomicU32 = AtomicU32::new(2);

mod probe;
pub use probe::get_display_info;
use probe::submit_one;

mod limits;
use limits::SUBMIT_POLL_BUDGET;

mod damage;
mod edid;
/// When a removed scanout's DMA frames may go back to the PMM.
mod release;
pub mod present;

mod scanout;
pub use scanout::{
    blank_scanout_for_key,
    dimensions,
    dimensions_for_key,
    fbcon_flush_pixels,
    framebuffer,
    framebuffer_for_key,
    publish_console_scanout,
    scanout_ready,
    scanout_ready_for_key,
    shutdown_scanout,
    unblank_scanout_for_key,
    uninstall_scanout,
    uninstall_scanout_after_failed_probe,
    unpublish_console_scanout,
};
use scanout::install_scanout_ctx;

mod runtime;
pub use runtime::{
    boot_scanout_res_id_for_key,
    create_scanout_from_pa_for_key,
    flush_scanout_for_key,
    register_drm_hooks,
    restore_console_scanout_for_key,
    set_scanout_for_key,
    unregister_drm_hooks,
    unref_scanout_resource_for_key,
};

#[cfg(test)]
mod tests;
