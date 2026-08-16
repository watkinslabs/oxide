//! Runtime request admission: encode ordered commands, workers submit them.

use super::*;
use super::runtime_queue::{self, RuntimeCmd};

fn key_from_raw(raw: u32) -> virtio::VirtioChildDeviceKey {
    virtio::VirtioChildDeviceKey::from_raw(raw)
}

fn key_from_scanout_driver(driver_key: drm::node::ScanoutDriverKey) -> virtio::VirtioChildDeviceKey {
    key_from_raw(driver_key.raw())
}

pub fn boot_scanout_res_id_for_key(_driver_key: drm::node::ScanoutDriverKey) -> u32 { BOOT_SCANOUT_RES_ID }

pub fn create_scanout_from_pa_for_key(driver_key: drm::node::ScanoutDriverKey, pa: u64,
    w: u32, h: u32, pitch: u32, fmt_drm: u32) -> Option<u32>
{
    let owner = key_from_scanout_driver(driver_key);
    let fmt = crate::drm_fourcc_to_virtio(fmt_drm)?;
    if w == 0 || h == 0 { return None; }
    const BYTES_PER_PIXEL: u64 = 4;
    if pitch as u64 != (w as u64).checked_mul(BYTES_PER_PIXEL)? { return None; }
    let bytes = (pitch as u64).checked_mul(h as u64)?;
    if bytes == 0 || bytes > u32::MAX as u64 { return None; }
    let res_id = NEXT_RUNTIME_RES_ID.fetch_add(1, Ordering::AcqRel);
    let ctxs = ctx_lock();
    let ctx = ctxs.iter().find(|ctx| ctx.device_key == owner)?;
    if ctx.quiesced { return None; }
    drop(ctxs);
    if !runtime_queue::enqueue_ctrl(owner, &[
        RuntimeCmd::Create2d { res_id, fmt, w, h },
        RuntimeCmd::AttachBacking { res_id, dma: pa, bytes: bytes as u32 },
    ]) { return None; }
    Some(res_id)
}

pub fn unref_scanout_resource_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32) -> bool {
    if res_id == 0 || res_id == BOOT_SCANOUT_RES_ID { return false; }
    let owner = key_from_scanout_driver(driver_key);
    let ctxs = ctx_lock();
    let Some(ctx) = ctxs.iter().find(|ctx| ctx.device_key == owner) else { return false };
    if ctx.quiesced { return false; }
    drop(ctxs);
    runtime_queue::enqueue_destroy(owner, res_id)
}

/// Present `rect` of `res_id` by atomically admitting the transfer/bind/flush
/// sequence to the one CTRLQ worker. # C: O(1)
pub fn present_rect_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32,
    w: u32, h: u32, rect: present::Rect) -> bool
{
    let owner = key_from_scanout_driver(driver_key);
    if w == 0 || h == 0 { return false; }
    let Some(rect) = present::clamp_rect(rect, w, h) else { return false };
    let ctxs = ctx_lock();
    let Some(ctx) = ctxs.iter().find(|ctx| ctx.device_key == owner) else { return false };
    if ctx.quiesced { return false; }
    drop(ctxs);
    runtime_queue::enqueue_present(owner, res_id, w, h, rect)
}

/// Bind a complete resource on scanout zero. # C: O(1)
pub fn set_scanout_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32, w: u32, h: u32) -> bool {
    present_rect_for_key(driver_key, res_id, w, h, present::Rect::full(w, h))
}

/// `ScanoutOps::present` — present the damaged region userspace reported.
/// # C: O(1)
pub fn present_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32, w: u32, h: u32,
    damage: drm::node::DamageRect) -> bool
{
    present_rect_for_key(driver_key, res_id, w, h,
        present::Rect { x: damage.x, y: damage.y, w: damage.w, h: damage.h })
}

/// Publish a cursor after its CTRLQ transfer/flush barrier has retired.
/// # C: O(1)
pub fn set_cursor_for_key(driver_key: drm::node::ScanoutDriverKey, res_id: u32,
    w: u32, h: u32, x: i32, y: i32, hot_x: i32, hot_y: i32) -> bool
{
    let owner = key_from_scanout_driver(driver_key);
    let ctxs = ctx_lock();
    let Some(ctx) = ctxs.iter().find(|ctx| ctx.device_key == owner) else { return false };
    if ctx.quiesced { return false; }
    drop(ctxs);
    if res_id == 0 {
        return runtime_queue::enqueue_cursor(owner, &[
            RuntimeCmd::UpdateCursor { res_id: 0, w: 0, h: 0, x: 0, y: 0, hot_x: 0, hot_y: 0 },
        ]);
    }
    if w == 0 || h == 0 || w > 64 || h > 64 || hot_x < 0 || hot_y < 0
        || hot_x as u32 >= w || hot_y as u32 >= h { return false; }
    runtime_queue::enqueue_ctrl(owner, &[
        RuntimeCmd::Transfer { res_id, x: 0, y: 0, w, h, off: 0 },
        RuntimeCmd::Flush { res_id, x: 0, y: 0, w, h },
        RuntimeCmd::QueueCursorUpdate { res_id, w, h, x, y, hot_x, hot_y },
    ])
}

/// Reposition the current cursor without re-uploading its resource. # C: O(1)
pub fn move_cursor_for_key(driver_key: drm::node::ScanoutDriverKey, x: i32, y: i32) -> bool {
    let owner = key_from_scanout_driver(driver_key);
    let ctxs = ctx_lock();
    let Some(ctx) = ctxs.iter().find(|ctx| ctx.device_key == owner) else { return false };
    if ctx.quiesced { return false; }
    drop(ctxs);
    runtime_queue::enqueue_cursor(owner, &[RuntimeCmd::MoveCursor { x, y }])
}

pub fn restore_console_scanout_for_key(driver_key: drm::node::ScanoutDriverKey) -> bool {
    let owner = key_from_scanout_driver(driver_key);
    let (w, h) = match dimensions_for_key(owner) { Some(d) => d, None => return false };
    let ok = set_scanout_for_key(driver_key, BOOT_SCANOUT_RES_ID, w, h);
    fbcon::kernel::force_repaint();
    ok
}

pub fn register_drm_hooks(card_id: u32, device_key: virtio::VirtioChildDeviceKey) {
    let Some(driver_key) = drm::node::ScanoutDriverKey::from_raw(device_key.raw()) else { return };
    drm::node::set_scanout_ops(card_id, drm::node::ScanoutOps {
        driver_key,
        create_from_pa: create_scanout_from_pa_for_key,
        destroy_resource: unref_scanout_resource_for_key,
        present: present_for_key,
        set_cursor: Some(set_cursor_for_key),
        move_cursor: Some(move_cursor_for_key),
        restore_console: restore_console_scanout_for_key,
        boot_res_id: boot_scanout_res_id_for_key,
    });
}

pub fn unregister_drm_hooks(card_id: u32) { drm::node::clear_scanout_ops(card_id); }

pub fn flush_scanout_for_key(driver_key: fbdev::FbDriverKey) {
    let owner = key_from_raw(driver_key.raw());
    let ctxs = ctx_lock();
    let Some(ctx) = ctxs.iter().find(|ctx| ctx.device_key == owner) else { return };
    if ctx.quiesced { return; }
    let (res_id, w, h) = (ctx.res_id, ctx.w, ctx.h);
    drop(ctxs);
    let _ = runtime_queue::enqueue_ctrl(owner, &[
        RuntimeCmd::Transfer { res_id, x: 0, y: 0, w, h, off: 0 },
        RuntimeCmd::Flush { res_id, x: 0, y: 0, w, h },
    ]);
}
