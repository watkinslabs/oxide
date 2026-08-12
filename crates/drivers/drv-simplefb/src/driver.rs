use alloc::{string::String, sync::Arc, vec::Vec};
use boot_info::BootFramebuffer;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use sync::{Spinlock, TaskList as DriverLockClass};

use crate::format;

const PLATFORM_BUS: &str = "platform";
const DEVICE_ADDR: &str = "simple-framebuffer.0";
const PAGE_BYTES: u64 = 4096;

struct Live {
    fb: BootFramebuffer,
    idx: u32,
    mapping: mmio_map::Mapping,
    fb_va: u64,
    bytes: u64,
    aperture: fbdev::ApertureKey,
    drm_card: u32,
}

struct Resource { id: u32, pa: u64, width: u32, height: u32, pitch: u32, format: u32 }
struct SimpleDrm { unique: String, width: u32, height: u32 }

const SIMPLEDRM_KEY: u32 = 1;
static RESOURCES: Spinlock<Vec<Resource>, DriverLockClass> = Spinlock::new(Vec::new());
static NEXT_RESOURCE: AtomicU32 = AtomicU32::new(1);

static CONFIG: Spinlock<BootFramebuffer, DriverLockClass> = Spinlock::new(BootFramebuffer::EMPTY);
static LIVE: Spinlock<Option<Live>, DriverLockClass> = Spinlock::new(None);
static PRESENT: AtomicBool = AtomicBool::new(false);

/// Publish bootloader platform data before registering the driver.
/// # C: O(1)
pub fn configure_probe(fb: BootFramebuffer) { *CONFIG.lock() = fb; }

/// True while the platform framebuffer owns its mapping and fbdev node.
/// # C: O(1)
pub fn present() -> bool { PRESENT.load(Ordering::Acquire) }

fn flush_pixels(pixels: &[u8], rect: fbcon::kernel::FlushRect) {
    let mut live = LIVE.lock();
    let Some(live) = live.as_mut() else { return };
    // SAFETY: Live owns the WC mapping for `bytes`; removal first excludes this
    // callback via LIVE, then unregisters fbcon, before Mapping::unmap runs.
    let dst = unsafe { core::slice::from_raw_parts_mut(live.fb_va as *mut u8, live.bytes as usize) };
    format::copy_damage(pixels, dst, rect, live.fb);
}

/// Present canonical XRGB8888 pixels from a DRM scanout buffer.
///
/// This reuses the framebuffer's validated native-format conversion and the
/// same WC mapping as fbcon. It is the common linear-scanout bridge for native
/// PCI display drivers; callers must supply a complete source surface.
/// # C: O(damage pixels)
pub fn present_xrgb(pixels: &[u8], stride_px: u32, width: u32, height: u32,
                    x: u32, y: u32, w: u32, h: u32) -> bool {
    let mut live = LIVE.lock();
    let Some(live) = live.as_mut() else { return false; };
    if stride_px < width || width > live.fb.width || height > live.fb.height { return false; }
    let bytes = match u64::from(stride_px).checked_mul(u64::from(height)).and_then(|n| n.checked_mul(4)) {
        Some(n) => n,
        None => return false,
    };
    if bytes > pixels.len() as u64 { return false; }
    // SAFETY: Live owns its complete WC mapping while present_xrgb holds LIVE.
    let dst = unsafe { core::slice::from_raw_parts_mut(live.fb_va as *mut u8, live.bytes as usize) };
    format::copy_damage(pixels, dst, fbcon::kernel::FlushRect { x, y, w, h, stride_px }, live.fb);
    true
}

fn detach() {
    let live = LIVE.lock().take();
    let Some(live) = live else { return };
    PRESENT.store(false, Ordering::Release);
    if live.drm_card != u32::MAX { let _ = drm::unregister(live.drm_card); }
    RESOURCES.lock().clear();
    unpublish_console();
    let _ = fbdev::unregister(live.idx);
    let _ = fbdev::release_aperture(live.aperture);
    drop(live.mapping);
}

fn detach_aperture(_key: fbdev::ApertureKey) { detach(); }

#[cfg(target_os = "oxide-kernel")]
fn unpublish_console() {
    klog::clear_aux_sink();
    tty::live::clear_vt_mode_queries();
    fbcon::kernel::kernel_unregister();
}

#[cfg(not(target_os = "oxide-kernel"))]
fn unpublish_console() {}

#[cfg(target_os = "oxide-kernel")]
fn publish_console(fb: BootFramebuffer) {
    fbcon::kernel::kernel_init(fb.width, fb.height, flush_pixels);
    if cmdline::console_classes().1 { klog::set_aux_sink(fbcon::kernel::vt_console_sink); }
    fbcon::kernel::set_reply_sink(console::vt_reply_sink);
    tty::live::set_app_cursor_query(fbcon::kernel::fg_app_cursor);
    tty::live::set_bracketed_paste_query(fbcon::kernel::fg_bracketed_paste);
}

#[cfg(not(target_os = "oxide-kernel"))]
fn publish_console(_fb: BootFramebuffer) {}

struct SimpleFbDriver;

impl drv::Driver for SimpleFbDriver {
    fn bus(&self) -> &'static str { PLATFORM_BUS }
    fn name(&self) -> &'static str { "simple-framebuffer" }
    fn matches(&self, dev: &drv::Device) -> bool {
        dev.bus == PLATFORM_BUS && dev.addr == DEVICE_ADDR
    }

    fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
        let fb = *CONFIG.lock();
        let bytes = fb.byte_len().ok_or(drv::Error::Invalid)?;
        let end = fb.base_pa.checked_add(bytes - 1).ok_or(drv::Error::Invalid)?;
        if !dev.resources.iter().any(|r| r.flags & drv::IORESOURCE_MEM != 0 && r.start <= fb.base_pa && r.end >= end) {
            return Err(drv::Error::Invalid);
        }
        attach_firmware_scanout(fb, dev)
    }

    fn remove(&self, _dev: &drv::Device) { detach(); }
    fn shutdown(&self, _dev: &drv::Device) {}
}

/// Claim, map, and publish a validated linear native scanout.
///
/// The caller owns hardware mode programming and must have evicted any
/// overlapping firmware aperture before returning control to its PCI driver.
/// # C: O(framebuffer pages)
pub fn attach_native_scanout(fb: BootFramebuffer) -> drv::KResult<()> {
    attach_scanout(fb, u32::MAX)
}

/// Attach the boot framebuffer as Linux simpledrm does: publish its one fixed
/// KMS pipeline while it owns the firmware aperture. Native PCI DRM drivers
/// evict this aperture before taking hardware ownership.
fn attach_firmware_scanout(fb: BootFramebuffer, parent: &Arc<drv::Device>) -> drv::KResult<()> {
    attach_scanout(fb, u32::MAX)?;
    let card = drm::register_with_parent(Arc::new(SimpleDrm {
        unique: String::from(DEVICE_ADDR), width: fb.width, height: fb.height,
    }), Some(parent));
    if card == u32::MAX { detach(); return Err(drv::Error::ProbeFailed); }
    let Some(key) = drm::node::ScanoutDriverKey::from_raw(SIMPLEDRM_KEY) else { unreachable!() };
    drm::node::set_scanout_ops(card, drm::node::ScanoutOps {
        driver_key: key, create_from_pa, destroy_resource, present: present_drm,
        set_cursor: unsupported_cursor, move_cursor: unsupported_move_cursor,
        restore_console, boot_res_id: no_boot_resource,
    });
    let mut live = LIVE.lock();
    let Some(live) = live.as_mut() else { let _ = drm::unregister(card); return Err(drv::Error::ProbeFailed) };
    live.drm_card = card;
    Ok(())
}

fn attach_scanout(fb: BootFramebuffer, drm_card: u32) -> drv::KResult<()> {
    if present() { return Err(drv::Error::Busy); }
    let bytes = fb.byte_len().ok_or(drv::Error::Invalid)?;
    let page_pa = fb.base_pa & !(PAGE_BYTES - 1);
    let page_off = fb.base_pa - page_pa;
    let span = page_off.checked_add(bytes).ok_or(drv::Error::Invalid)?;
    let pages = span.checked_add(PAGE_BYTES - 1).ok_or(drv::Error::Invalid)? / PAGE_BYTES;
    let var = format::fb_var(fb).ok_or(drv::Error::Invalid)?;
    let aperture = fbdev::acquire_aperture(fb.base_pa, bytes, detach_aperture).map_err(|err| match err {
        fbdev::ApertureError::Inval => drv::Error::Invalid,
        fbdev::ApertureError::Busy => drv::Error::Busy,
    })?;
        // SAFETY: the platform resource above contains the complete firmware
        // framebuffer; its lifetime is the bound device's lifetime and page_pa
        // is aligned. The driver owns the returned WC alias until detach.
    let mapping = unsafe { mmio_map::map_owned_wc(page_pa, pages) };
    let fb_va = mapping.base_va() + page_off;
    let idx = fbdev::init_scanout_configured(
        fb.base_pa, fb_va, bytes, fb.pitch, var, vmm::PhysCacheMode::WriteCombine,
    );
    if idx == fbdev::INVALID_FB_INDEX {
        let _ = fbdev::release_aperture(aperture);
        return Err(drv::Error::ProbeFailed);
    }
    *LIVE.lock() = Some(Live { fb, idx, mapping, fb_va, bytes, aperture, drm_card });
    PRESENT.store(true, Ordering::Release);
    publish_console(fb);
    #[cfg(feature = "debug-boot")]
    {
        klog::write_raw(b"[INFO]  simplefb: registered WC framebuffer\n");
    }
    Ok(())
}

impl drm::DrmDriver for SimpleDrm {
    fn name(&self) -> &'static str { "simpledrm" }
    fn version(&self) -> (u32, u32, u32) { (1, 0, 0) }
    fn date(&self) -> &'static str { "20260812" }
    fn desc(&self) -> &'static str { "DRM driver for firmware framebuffers" }
    fn unique(&self) -> &str { self.unique.as_str() }
    fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
    fn dim_bounds(&self) -> (u32, u32, u32, u32) { (self.width, self.width, self.height, self.height) }
    fn cap(&self, cap: u64) -> u64 { drm::default_cap(cap) }
    fn crtc_ids(&self) -> Vec<u32> { alloc::vec![drm::crtc_id_for(0)] }
    fn connector_ids(&self) -> Vec<u32> { alloc::vec![drm::connector_id_for(0)] }
    fn encoder_ids(&self) -> Vec<u32> { alloc::vec![drm::encoder_id_for(0)] }
    fn plane_ids(&self) -> Vec<u32> { alloc::vec![drm::plane_id_for(0)] }
    fn mode_for(&self, _idx: usize) -> drm::DrmModeModeinfo { drm::mode_from_rect(self.width, self.height) }
    fn connector_info(&self, idx: usize) -> Option<drm::ConnectorInfo> {
        (idx == 0).then_some(drm::ConnectorInfo { connection: drm::DRM_MODE_CONNECTED,
            connector_type: drm::DRM_MODE_CONNECTOR_UNKNOWN, encoder_id: drm::encoder_id_for(0), mm_width: 0, mm_height: 0 })
    }
    fn crtc_info(&self, idx: usize) -> Option<drm::CrtcInfo> {
        (idx == 0).then_some(drm::CrtcInfo { mode_valid: 1, fb_id: 0, x: 0, y: 0, gamma_size: 0, mode: self.mode_for(0) })
    }
    fn encoder_info(&self, idx: usize) -> Option<drm::EncoderInfo> {
        (idx == 0).then_some(drm::EncoderInfo { encoder_type: drm::DRM_MODE_ENCODER_NONE,
            crtc_id: drm::crtc_id_for(0), possible_crtcs: 1, possible_clones: 0 })
    }
    fn plane_info(&self, idx: usize) -> Option<drm::PlaneInfo> {
        (idx == 0).then_some(drm::PlaneInfo { crtc_id: drm::crtc_id_for(0), fb_id: 0, possible_crtcs: 1 })
    }
}

fn create_from_pa(_key: drm::node::ScanoutDriverKey, pa: u64, width: u32, height: u32, pitch: u32, format: u32) -> Option<u32> {
    let live = LIVE.lock();
    if width != live.as_ref()?.fb.width || height != live.as_ref()?.fb.height || pitch < width.checked_mul(4)?
        || !matches!(format, drm::DRM_FORMAT_XRGB8888 | drm::DRM_FORMAT_ARGB8888) { return None; }
    drop(live);
    let id = NEXT_RESOURCE.fetch_add(1, Ordering::AcqRel);
    if id == 0 { return None; }
    RESOURCES.lock().push(Resource { id, pa, width, height, pitch, format });
    Some(id)
}

fn destroy_resource(_key: drm::node::ScanoutDriverKey, id: u32) -> bool {
    let mut resources = RESOURCES.lock();
    let Some(index) = resources.iter().position(|resource| resource.id == id) else { return false; };
    resources.remove(index); true
}

#[cfg(target_os = "oxide-kernel")]
fn present_drm(_key: drm::node::ScanoutDriverKey, id: u32, width: u32, height: u32, damage: drm::node::DamageRect) -> bool {
    let resources = RESOURCES.lock();
    let Some(resource) = resources.iter().find(|resource| resource.id == id && resource.width == width && resource.height == height
        && matches!(resource.format, drm::DRM_FORMAT_XRGB8888 | drm::DRM_FORMAT_ARGB8888)) else { return false; };
    let bytes = match u64::from(resource.pitch).checked_mul(u64::from(resource.height)) { Some(bytes) => bytes, None => return false };
    let src_va = match pmm::user_as::hhdm_offset().checked_add(resource.pa) { Some(va) => va, None => return false };
    // SAFETY: the DRM dumb-buffer lifetime owns this contiguous PMM range until
    // DRM invokes destroy_resource; RESOURCES retains that reference here.
    let src = unsafe { core::slice::from_raw_parts(src_va as *const u8, bytes as usize) };
    present_xrgb(src, resource.pitch / 4, width, height, damage.x, damage.y, damage.w, damage.h)
}

#[cfg(not(target_os = "oxide-kernel"))]
fn present_drm(_key: drm::node::ScanoutDriverKey, _id: u32, _width: u32, _height: u32, _damage: drm::node::DamageRect) -> bool { false }

fn restore_console(_key: drm::node::ScanoutDriverKey) -> bool { fbcon::kernel::force_repaint(); true }
fn unsupported_cursor(_key: drm::node::ScanoutDriverKey, _id: u32, _w: u32, _h: u32, _x: i32, _y: i32, _hot_x: i32, _hot_y: i32) -> bool { false }
fn unsupported_move_cursor(_key: drm::node::ScanoutDriverKey, _x: i32, _y: i32) -> bool { false }
fn no_boot_resource(_key: drm::node::ScanoutDriverKey) -> u32 { 0 }

static DRIVER: SimpleFbDriver = SimpleFbDriver;

/// Platform simple-framebuffer driver-model handle.
/// # C: O(1)
pub fn driver() -> &'static dyn drv::Driver { &DRIVER }

/// Canonical platform address matched by [`driver`].
/// # C: O(1)
pub fn device_addr() -> &'static str { DEVICE_ADDR }
