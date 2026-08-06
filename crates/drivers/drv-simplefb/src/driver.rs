use alloc::sync::Arc;
use boot_info::BootFramebuffer;
use core::sync::atomic::{AtomicBool, Ordering};
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
}

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

fn detach() {
    let live = LIVE.lock().take();
    let Some(live) = live else { return };
    PRESENT.store(false, Ordering::Release);
    unpublish_console();
    let _ = fbdev::unregister(live.idx);
    drop(live.mapping);
}

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
        if present() { return Err(drv::Error::Busy); }
        let fb = *CONFIG.lock();
        let bytes = fb.byte_len().ok_or(drv::Error::Invalid)?;
        let end = fb.base_pa.checked_add(bytes - 1).ok_or(drv::Error::Invalid)?;
        if !dev.resources.iter().any(|r| r.flags & drv::IORESOURCE_MEM != 0 && r.start <= fb.base_pa && r.end >= end) {
            return Err(drv::Error::Invalid);
        }
        let page_pa = fb.base_pa & !(PAGE_BYTES - 1);
        let page_off = fb.base_pa - page_pa;
        let span = page_off.checked_add(bytes).ok_or(drv::Error::Invalid)?;
        let pages = span.checked_add(PAGE_BYTES - 1).ok_or(drv::Error::Invalid)? / PAGE_BYTES;
        // SAFETY: the platform resource above contains the complete firmware
        // framebuffer; its lifetime is the bound device's lifetime and page_pa
        // is aligned. The driver owns the returned WC alias until detach.
        let mapping = unsafe { mmio_map::map_owned_wc(page_pa, pages) };
        let fb_va = mapping.base_va() + page_off;
        let var = format::fb_var(fb).ok_or(drv::Error::Invalid)?;
        let idx = fbdev::init_scanout_configured(
            fb.base_pa, fb_va, bytes, fb.pitch, var, vmm::PhysCacheMode::WriteCombine,
        );
        if idx == fbdev::INVALID_FB_INDEX { return Err(drv::Error::ProbeFailed); }
        *LIVE.lock() = Some(Live { fb, idx, mapping, fb_va, bytes });
        PRESENT.store(true, Ordering::Release);
        publish_console(fb);
        #[cfg(feature = "debug-boot")]
        {
            klog::write_raw(b"[INFO]  simplefb: registered WC framebuffer\n");
        }
        Ok(())
    }

    fn remove(&self, _dev: &drv::Device) { detach(); }
    fn shutdown(&self, _dev: &drv::Device) {}
}

static DRIVER: SimpleFbDriver = SimpleFbDriver;

/// Platform simple-framebuffer driver-model handle.
/// # C: O(1)
pub fn driver() -> &'static dyn drv::Driver { &DRIVER }

/// Canonical platform address matched by [`driver`].
/// # C: O(1)
pub fn device_addr() -> &'static str { DEVICE_ADDR }
