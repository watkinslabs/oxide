// virtio-gpu modern display setup. Called by the virtio-gpu model driver's
// probe after virtio-pci transport init has produced queue0/config state.

use alloc::{string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, Ordering};

use sync::{Spinlock, TaskList as DriverLockClass};

struct ProbeCommandBuffer {
    pa: u64,
    va: *mut u8,
    owned: bool,
}

impl ProbeCommandBuffer {
    fn alloc(hhdm: u64) -> Option<Self> {
        let pa = pmm::setup::alloc_one_frame()?;
        Some(Self {
            pa,
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
            unsafe { pmm::setup::free_one_frame(self.pa); }
        }
    }
}

struct ProbeFramebufferRun {
    base_pa: u64,
    order: pmm::Order,
    owned: bool,
}

impl ProbeFramebufferRun {
    fn alloc(order: pmm::Order) -> Option<Self> {
        let base_pa = pmm::setup::alloc_contig(order)?;
        Some(Self {
            base_pa,
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
            unsafe {
                pmm::setup::free_contig(self.base_pa, self.order);
            }
        }
    }
}

struct ScanoutCtx {
    device_key: virtio::VirtioChildDeviceKey,
    bdf: u32,
    cfg_va: u64,
    w: u32,
    h: u32,
    fb_va: u64,
    fb_bytes: u64,
    fb_order: pmm::Order,
    res_id: u32,
    ctrlq: virtio::VirtQueueResource,
    cursorq: virtio::VirtQueueResource,
    cmd_buf_va: u64,
    cmd_buf_pa: u64,
    hhdm: u64,
    fbdev_idx: Option<u32>,
    quiesced: bool,
}

static CTX: Spinlock<Vec<ScanoutCtx>, DriverLockClass> = Spinlock::new(Vec::new());
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
