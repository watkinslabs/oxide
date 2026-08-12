//! Linux-shaped QEMU stdvga (Bochs DISPI) PCI display driver.
//!
//! This is the first native PCI scanout implementation, not a replacement for
//! the DRM/KMS core needed by broader Linux GPU driver compatibility.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;

use boot_info::{BootFramebuffer, BootFramebufferBitfield, BootFramebufferKind};

const BOCHS_VENDOR: u16 = 0x1234;
const BOCHS_DEVICE: u16 = 0x1111;
const VBE_INDEX_PORT: u16 = 0x01ce;
const VBE_DATA_PORT: u16 = 0x01cf;
const VBE_ID0: u16 = 0xb0c0;
const VBE_INDEX_ID: u16 = 0;
const VBE_INDEX_XRES: u16 = 1;
const VBE_INDEX_YRES: u16 = 2;
const VBE_INDEX_BPP: u16 = 3;
const VBE_INDEX_ENABLE: u16 = 4;
const VBE_INDEX_BANK: u16 = 5;
const VBE_INDEX_VIRT_WIDTH: u16 = 6;
const VBE_INDEX_VIRT_HEIGHT: u16 = 7;
const VBE_INDEX_X_OFFSET: u16 = 8;
const VBE_INDEX_Y_OFFSET: u16 = 9;
const VBE_INDEX_VIDEO_MEMORY_64K: u16 = 10;
const VBE_ENABLED: u16 = 0x01;
const VBE_LFB_ENABLED: u16 = 0x40;
const MODE_WIDTH: u32 = 1024;
const MODE_HEIGHT: u32 = 768;
const MODE_BPP: u8 = 32;

fn mode_bytes(width: u32, height: u32, bpp: u8) -> Option<u64> {
    u64::from(width).checked_mul(u64::from(height))?.checked_mul(u64::from(bpp).checked_div(8)?)
}

fn framebuffer(base_pa: u64, vram_bytes: u64) -> Option<BootFramebuffer> {
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

#[cfg(all(target_os = "oxide-kernel", target_arch = "x86_64"))]
mod kernel {
    use alloc::sync::Arc;
    use alloc::vec::Vec;
    use sync::{Spinlock, TaskList as DriverLockClass};

    use super::*;

    struct Record { bdf: pci::Bdf, command_orig: u16 }
    static DEVICES: Spinlock<Vec<Record>, DriverLockClass> = Spinlock::new(Vec::new());

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
            DEVICES.lock().push(Record { bdf, command_orig });
            Ok(())
        }

        fn remove(&self, dev: &drv::Device) {
            let Some(bdf) = pci::parse_bdf_addr(&dev.addr) else { return };
            let mut records = DEVICES.lock();
            let Some(index) = records.iter().position(|record| record.bdf == bdf) else { return };
            let record = records.remove(index);
            drop(records);
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
