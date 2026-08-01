use alloc::vec::Vec;

use sync::{Spinlock, TaskList as OpsLockClass};

// Runtime scanout backend hook (filled by drv-virtio-gpu at install)
// ============================================================

/// Runtime scanout operations the DRM core calls for SETCRTC/PAGE_FLIP.
/// Filled by `drv-virtio-gpu::post_init::register_drm_hooks` per DRM card at
/// device install. The DRM crate cannot depend on the virtio-gpu crate, so the
/// binding is a function-pointer table plus an opaque driver key.
#[derive(Copy, Clone)]
pub struct ScanoutOps {
    /// Driver-owned runtime key for the owning GPU.
    pub driver_key: ScanoutDriverKey,
    /// Create a virtio-gpu resource over a contiguous PA; returns res_id.
    pub create_from_pa: fn(driver_key: ScanoutDriverKey, pa: u64, w: u32, h: u32, fmt_drm: u32) -> Option<u32>,
    /// Drop a previously-created runtime scanout resource.
    pub destroy_resource: fn(driver_key: ScanoutDriverKey, res_id: u32) -> bool,
    /// Present `damage` of `res_id` on scanout 0. The driver uploads the
    /// damaged region, binds the scanout when the binding changed, and
    /// flushes. A rebind widens the upload to the whole surface, so a caller
    /// with no damage information passes `DamageRect::full`.
    pub present: fn(driver_key: ScanoutDriverKey, res_id: u32, w: u32, h: u32,
                    damage: DamageRect) -> bool,
    /// Upload and publish a cursor resource on the driver's cursor queue.
    pub set_cursor: fn(driver_key: ScanoutDriverKey, res_id: u32, w: u32, h: u32,
                       x: i32, y: i32, hot_x: i32, hot_y: i32) -> bool,
    /// Move the currently published cursor without re-uploading it.
    pub move_cursor: fn(driver_key: ScanoutDriverKey, x: i32, y: i32) -> bool,
    /// Restore the boot fbcon scanout + repaint the console.
    pub restore_console: fn(driver_key: ScanoutDriverKey) -> bool,
    /// The boot fbcon scanout resource id.
    pub boot_res_id: fn(driver_key: ScanoutDriverKey) -> u32,
}

/// Region of a framebuffer a presentation actually changed, in pixels.
/// Userspace supplies it via DIRTYFB clips or the atomic damage-clips
/// property; a caller that has none presents the whole surface.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DamageRect {
    pub x: u32,
    pub y: u32,
    pub w: u32,
    pub h: u32,
}

impl DamageRect {
    /// Whole `w` x `h` surface. # C: O(1)
    pub fn full(w: u32, h: u32) -> Self { DamageRect { x: 0, y: 0, w, h } }

    /// Smallest rect covering both, so a multi-clip update becomes one
    /// upload instead of one round trip per clip. # C: O(1)
    pub fn union(self, o: DamageRect) -> DamageRect {
        if self.w == 0 || self.h == 0 { return o; }
        if o.w == 0 || o.h == 0 { return self; }
        let x = self.x.min(o.x);
        let y = self.y.min(o.y);
        let r = (self.x + self.w).max(o.x + o.w);
        let b = (self.y + self.h).max(o.y + o.h);
        DamageRect { x, y, w: r - x, h: b - y }
    }

    /// Nothing changed. # C: O(1)
    pub fn is_empty(&self) -> bool { self.w == 0 || self.h == 0 }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ScanoutDriverKey(u32);

impl ScanoutDriverKey {
    /// Build an opaque DRM scanout callback key from driver-owned identity. # C: O(1)
    pub fn from_raw(raw: u32) -> Option<Self> {
        if raw == 0 { None } else { Some(Self(raw)) }
    }

    /// Expose the key only to the installing driver's callback adapter. # C: O(1)
    pub fn raw(self) -> u32 { self.0 }
}

static SCANOUT_OPS: Spinlock<Vec<Option<ScanoutOps>>, OpsLockClass> = Spinlock::new(Vec::new());

/// Install the runtime scanout backend for a stable DRM card id.
/// # C: O(N) only when extending the sparse card table.
pub fn set_scanout_ops(card_id: u32, ops: ScanoutOps) {
    let mut g = SCANOUT_OPS.lock();
    let idx = card_id as usize;
    if g.len() <= idx {
        g.resize_with(idx + 1, || None);
    }
    g[idx] = Some(ops);
}

/// Remove the runtime scanout backend for a stable DRM card id.
/// # C: O(N) only when trimming trailing empty slots.
pub fn clear_scanout_ops(card_id: u32) {
    let mut g = SCANOUT_OPS.lock();
    if let Some(slot) = g.get_mut(card_id as usize) {
        *slot = None;
    }
    while matches!(g.last(), Some(None)) {
        g.pop();
    }
}

/// Snapshot the runtime scanout backend for a stable DRM card id.
/// # C: O(1)
pub fn scanout_ops(card_id: u32) -> Option<ScanoutOps> {
    SCANOUT_OPS.lock().get(card_id as usize).and_then(|slot| *slot)
}
