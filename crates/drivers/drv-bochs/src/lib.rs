//! Linux-shaped QEMU stdvga (Bochs DISPI) PCI display driver.
//!
//! This is the first native PCI scanout implementation, not a replacement for
//! the DRM/KMS core needed by broader Linux GPU driver compatibility.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;

#[cfg(any(test, all(target_os = "oxide-kernel", target_arch = "x86_64")))]
mod bochs {
    use boot_info::{BootFramebuffer, BootFramebufferBitfield, BootFramebufferKind};

    pub const BOCHS_VENDOR: u16 = 0x1234;
    pub const BOCHS_DEVICE: u16 = 0x1111;
    pub const VBE_INDEX_PORT: u16 = 0x01ce;
    pub const VBE_DATA_PORT: u16 = 0x01cf;
    pub const VBE_ID0: u16 = 0xb0c0;
    pub const VBE_INDEX_ID: u16 = 0;
    pub const VBE_INDEX_XRES: u16 = 1;
    pub const VBE_INDEX_YRES: u16 = 2;
    pub const VBE_INDEX_BPP: u16 = 3;
    pub const VBE_INDEX_ENABLE: u16 = 4;
    pub const VBE_INDEX_BANK: u16 = 5;
    pub const VBE_INDEX_VIRT_WIDTH: u16 = 6;
    pub const VBE_INDEX_VIRT_HEIGHT: u16 = 7;
    pub const VBE_INDEX_X_OFFSET: u16 = 8;
    pub const VBE_INDEX_Y_OFFSET: u16 = 9;
    pub const VBE_INDEX_VIDEO_MEMORY_64K: u16 = 10;
    pub const VBE_ENABLED: u16 = 0x01;
    pub const VBE_LFB_ENABLED: u16 = 0x40;
    pub const MODE_WIDTH: u32 = 1024;
    pub const MODE_HEIGHT: u32 = 768;
    pub const MODE_BPP: u8 = 32;
    pub const DRM_FORMAT_XRGB8888: u32 = 0x3432_5258;
    pub const DRM_FORMAT_ARGB8888: u32 = 0x3432_5241;

    pub fn mode_bytes(width: u32, height: u32, bpp: u8) -> Option<u64> {
        u64::from(width).checked_mul(u64::from(height))?.checked_mul(u64::from(bpp).checked_div(8)?)
    }

    pub fn framebuffer(base_pa: u64, vram_bytes: u64) -> Option<BootFramebuffer> {
        let pitch = MODE_WIDTH.checked_mul(u32::from(MODE_BPP).checked_div(8)?)?;
        let bytes = mode_bytes(MODE_WIDTH, MODE_HEIGHT, MODE_BPP)?;
        if base_pa == 0 || bytes > vram_bytes { return None; }
        Some(BootFramebuffer {
            base_pa, pitch, width: MODE_WIDTH, height: MODE_HEIGHT, bpp: MODE_BPP,
            kind: BootFramebufferKind::Rgb,
            red: BootFramebufferBitfield { offset: 16, length: 8 },
            green: BootFramebufferBitfield { offset: 8, length: 8 },
            blue: BootFramebufferBitfield { offset: 0, length: 8 },
            _pad: [0; 2],
        })
    }
}

#[cfg(any(test, all(target_os = "oxide-kernel", target_arch = "x86_64")))]
use bochs::*;

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
mod kernel {
    use alloc::sync::Arc;
    use alloc::string::String;
    use alloc::vec::Vec;
    use core::sync::atomic::{AtomicU32, Ordering};
    use sync::{Spinlock, TaskList as DriverLockClass};

    use super::*;

    struct Record { bdf: pci::Bdf, command_orig: u16, card_id: u32, scanout_key: u32 }
    static DEVICES: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());
    struct Resource { key: u32, id: u32, pa: u64, width: u32, height: u32, pitch: u32, format: u32 }
    static RESOURCES: Spinlock<Vec<Resource>, DriverLockClass> = Spinlock::new(Vec::new());
    static NEXT_RESOURCE: AtomicU32 = AtomicU32::new(1);

    struct BochsDrm { unique: String }

    impl drm::DrmDriver for BochsDrm {
        fn name(&self) -> &'static str { "bochs" }
        fn version(&self) -> (u32, u32, u32) { (1, 0, 0) }
        fn date(&self) -> &'static str { "20260812" }
        fn desc(&self) -> &'static str { "Bochs DISPI VGA" }
        fn unique(&self) -> &str { self.unique.as_str() }
        fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 1, 1, 1) }
        fn dim_bounds(&self) -> (u32, u32, u32, u32) { (MODE_WIDTH, MODE_WIDTH, MODE_HEIGHT, MODE_HEIGHT) }
        fn cap(&self, cap: u64) -> u64 { drm::default_cap(cap) }
        fn crtc_ids(&self) -> Vec<u32> { alloc::vec![drm::crtc_id_for(0)] }
        fn connector_ids(&self) -> Vec<u32> { alloc::vec![drm::connector_id_for(0)] }
        fn encoder_ids(&self) -> Vec<u32> { alloc::vec![drm::encoder_id_for(0)] }
        fn plane_ids(&self) -> Vec<u32> { alloc::vec![drm::plane_id_for(0)] }
        fn mode_for(&self, _idx: usize) -> drm::DrmModeModeinfo { drm::mode_from_rect(MODE_WIDTH, MODE_HEIGHT) }
        fn connector_info(&self, idx: usize) -> Option<drm::ConnectorInfo> {
            (idx == 0).then_some(drm::ConnectorInfo { connection: drm::DRM_MODE_CONNECTED,
                connector_type: drm::DRM_MODE_CONNECTOR_VIRTUAL, encoder_id: drm::encoder_id_for(0), mm_width: 0, mm_height: 0 })
        }
        fn crtc_info(&self, idx: usize) -> Option<drm::CrtcInfo> {
            (idx == 0).then_some(drm::CrtcInfo { mode_valid: 1, fb_id: 0, x: 0, y: 0, gamma_size: 0, mode: drm::mode_from_rect(MODE_WIDTH, MODE_HEIGHT) })
        }
        fn encoder_info(&self, idx: usize) -> Option<drm::EncoderInfo> {
            (idx == 0).then_some(drm::EncoderInfo { encoder_type: drm::DRM_MODE_ENCODER_VIRTUAL,
                crtc_id: drm::crtc_id_for(0), possible_crtcs: 1, possible_clones: 0 })
        }
        fn plane_info(&self, idx: usize) -> Option<drm::PlaneInfo> {
            (idx == 0).then_some(drm::PlaneInfo { crtc_id: drm::crtc_id_for(0), fb_id: 0, possible_crtcs: 1 })
        }
    }

    fn resource_key(bdf: pci::Bdf) -> u32 { u32::from(bdf.raw()) + 1 }

    fn create_from_pa(key: drm::node::ScanoutDriverKey, pa: u64, width: u32, height: u32, pitch: u32, format: u32) -> Option<u32> {
        if width != MODE_WIDTH || height != MODE_HEIGHT || pitch < width.checked_mul(4)?
            || !matches!(format, DRM_FORMAT_XRGB8888 | DRM_FORMAT_ARGB8888) { return None; }
        let id = NEXT_RESOURCE.fetch_add(1, Ordering::AcqRel);
        if id == 0 { return None; }
        RESOURCES.lock().push(Resource { key: key.raw(), id, pa, width, height, pitch, format });
        Some(id)
    }

    fn destroy_resource(key: drm::node::ScanoutDriverKey, id: u32) -> bool {
        let mut resources = RESOURCES.lock();
        let Some(pos) = resources.iter().position(|resource| resource.key == key.raw() && resource.id == id) else { return false; };
        resources.remove(pos); true
    }

    fn present(key: drm::node::ScanoutDriverKey, id: u32, width: u32, height: u32, damage: drm::node::DamageRect) -> bool {
        let resources = RESOURCES.lock();
        let Some(resource) = resources.iter().find(|resource| resource.key == key.raw() && resource.id == id
            && resource.width == width && resource.height == height
            && matches!(resource.format, DRM_FORMAT_XRGB8888 | DRM_FORMAT_ARGB8888)) else { return false; };
        let bytes = match u64::from(resource.pitch).checked_mul(u64::from(resource.height)) { Some(bytes) => bytes, None => return false };
        let src_va = match pmm::user_as::hhdm_offset().checked_add(resource.pa) { Some(va) => va, None => return false };
        // SAFETY: the live dumb buffer owns this contiguous PMM allocation until
        // the DRM core calls destroy_resource after releasing its scanout ref.
        let src = unsafe { core::slice::from_raw_parts(src_va as *const u8, bytes as usize) };
        drv_simplefb::present_xrgb(src, resource.pitch / 4, width, height, damage.x, damage.y, damage.w, damage.h)
    }

    fn restore_console(_key: drm::node::ScanoutDriverKey) -> bool { fbcon::kernel::force_repaint(); true }
    fn unsupported_cursor(_key: drm::node::ScanoutDriverKey, _id: u32, _w: u32, _h: u32, _x: i32, _y: i32, _hot_x: i32, _hot_y: i32) -> bool { false }
    fn unsupported_move_cursor(_key: drm::node::ScanoutDriverKey, _x: i32, _y: i32) -> bool { false }
    fn no_boot_resource(_key: drm::node::ScanoutDriverKey) -> u32 { 0 }

    #[inline]
    unsafe fn outw(port: u16, value: u16) {
        // SAFETY: caller owns the Bochs DISPI port pair at CPL=0.
        unsafe { core::arch::asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags)); }
    }

    #[inline]
    unsafe fn inw(port: u16) -> u16 {
        let value: u16;
        // SAFETY: caller owns the Bochs DISPI port pair at CPL=0.
        unsafe { core::arch::asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags)); }
        value
    }

    fn read(index: u16) -> u16 {
        // SAFETY: this driver is the sole owner of the validated DISPI port pair.
        unsafe { outw(VBE_INDEX_PORT, index); inw(VBE_DATA_PORT) }
    }

    fn write(index: u16, value: u16) {
        // SAFETY: this driver is the sole owner of the validated DISPI port pair.
        unsafe { outw(VBE_INDEX_PORT, index); outw(VBE_DATA_PORT, value); }
    }

    fn program_mode() {
        // This is the same order as Linux bochs_hw_setmode(): disable, set
        // geometry/virtual geometry, reset offsets, then enable LFB scanout.
        write(VBE_INDEX_ENABLE, 0);
        write(VBE_INDEX_BPP, u16::from(MODE_BPP));
        write(VBE_INDEX_XRES, MODE_WIDTH as u16);
        write(VBE_INDEX_YRES, MODE_HEIGHT as u16);
        write(VBE_INDEX_BANK, 0);
        write(VBE_INDEX_VIRT_WIDTH, MODE_WIDTH as u16);
        write(VBE_INDEX_VIRT_HEIGHT, MODE_HEIGHT as u16);
        write(VBE_INDEX_X_OFFSET, 0);
        write(VBE_INDEX_Y_OFFSET, 0);
        write(VBE_INDEX_ENABLE, VBE_ENABLED | VBE_LFB_ENABLED);
    }

    fn restore_command(bdf: pci::Bdf, command_orig: u16) {
        if let Some(reader) = hal_x86_64::pci::EcamPci::from_published() {
            let _ = pci::restore_mem_bus_master(&reader, bdf, command_orig);
        }
    }

    pub struct BochsDriver;

    impl drv::Driver for BochsDriver {
        fn name(&self) -> &'static str { "bochs-drm" }

        fn matches(&self, dev: &drv::Device) -> bool {
            dev.bus == "pci" && dev.vendor_id == BOCHS_VENDOR && dev.device_id == BOCHS_DEVICE
        }

        fn probe(&self, dev: &Arc<drv::Device>) -> drv::KResult<()> {
            let bdf = pci::parse_bdf_addr(&dev.addr).ok_or(drv::Error::ProbeFailed)?;
            let reader = hal_x86_64::pci::EcamPci::from_published().ok_or(drv::Error::ProbeFailed)?;
            let command_orig = pci::enable_mem_decode(&reader, bdf);
            let Some(bar) = dev.resources.iter().find(|r| r.bar == 0 && r.flags & drv::IORESOURCE_MEM != 0) else {
                restore_command(bdf, command_orig);
                return Err(drv::Error::ProbeFailed);
            };
            let Some(bar_bytes) = bar.end.checked_sub(bar.start).and_then(|n| n.checked_add(1)) else {
                restore_command(bdf, command_orig);
                return Err(drv::Error::ProbeFailed);
            };
            let id = read(VBE_INDEX_ID);
            let vram_bytes = u64::from(read(VBE_INDEX_VIDEO_MEMORY_64K)).saturating_mul(64 * 1024);
            let Some(fb) = framebuffer(bar.start, core::cmp::min(bar_bytes, vram_bytes)) else {
                restore_command(bdf, command_orig);
                return Err(drv::Error::ProbeFailed);
            };
            if id & 0xfff0 != VBE_ID0 {
                restore_command(bdf, command_orig);
                return Err(drv::Error::NoMatch);
            }
            fbdev::remove_conflicting_apertures(bar.start, bar_bytes).map_err(|_| drv::Error::ProbeFailed)?;
            program_mode();
            if let Err(err) = drv_simplefb::attach_native_scanout(fb) {
                write(VBE_INDEX_ENABLE, 0);
                restore_command(bdf, command_orig);
                return Err(err);
            }
            let scanout_key = resource_key(bdf);
            let drm_dev = Arc::new(BochsDrm { unique: alloc::format!("pci:{:04x}:{:02x}:{:02x}.{}", bdf.segment, bdf.bus, bdf.device, bdf.function) });
            let card_id = drm::register_with_parent(drm_dev, Some(dev));
            if card_id == u32::MAX {
                write(VBE_INDEX_ENABLE, 0);
                drv_simplefb::driver().remove(dev);
                restore_command(bdf, command_orig);
                return Err(drv::Error::ProbeFailed);
            }
            let Some(key) = drm::node::ScanoutDriverKey::from_raw(scanout_key) else {
                let _ = drm::unregister(card_id);
                write(VBE_INDEX_ENABLE, 0);
                drv_simplefb::driver().remove(dev);
                restore_command(bdf, command_orig);
                return Err(drv::Error::ProbeFailed);
            };
            drm::node::set_scanout_ops(card_id, drm::node::ScanoutOps {
                driver_key: key, create_from_pa, destroy_resource, present,
                set_cursor: unsupported_cursor, move_cursor: unsupported_move_cursor,
                restore_console, boot_res_id: no_boot_resource,
            });
            DEVICES.lock().push(Record { bdf, command_orig, card_id, scanout_key });
            Ok(())
        }

        fn remove(&self, dev: &drv::Device) {
            let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return };
            let mut records = DEVICES.lock();
            let Some(index) = records.iter().position(|record| record.bdf == bdf) else { return };
            let record = records.remove(index);
            drop(records);
            RESOURCES.lock().retain(|resource| resource.key != record.scanout_key);
            let _ = drm::unregister(record.card_id);
            write(VBE_INDEX_ENABLE, 0);
            drv_simplefb::driver().remove(dev);
            restore_command(record.bdf, record.command_orig);
        }

        fn shutdown(&self, dev: &drv::Device) { self.remove(dev); }
    }

    pub static BOCHS_DRIVER: BochsDriver = BochsDriver;
}

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
pub use kernel::BOCHS_DRIVER;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_requires_enough_vram() {
        assert!(framebuffer(0xe000_0000, mode_bytes(MODE_WIDTH, MODE_HEIGHT, MODE_BPP).unwrap()).is_some());
        assert!(framebuffer(0xe000_0000, 1).is_none());
    }
}
