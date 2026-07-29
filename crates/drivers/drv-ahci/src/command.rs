//! AHCI slot-0 command DMA staging and polling-only IDENTIFY.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;

use crate::port::{hhdm, now_ns, Ahci};
use crate::regs;

const IO_TIMEOUT_NS: u64 = 5_000_000_000;
const CFL_DWORDS: u32 = 5;
const CT_PRDT_OFF: usize = 0x80;
const PRDT_BYTE_COUNT_MASK: u32 = 0x003F_FFFF;
const PRDT_INTERRUPT_ON_COMPLETION: u32 = 1 << 31;
const COMMAND_SLOT_ZERO: u32 = 1;

impl Ahci {
    fn stage_command(
        &mut self,
        fis: &[u8; 20],
        write: bool,
        bytes: u32,
        interrupt: bool,
    ) -> bool {
        let h = hhdm();
        if h == 0 { return false; }
        let prdtl: u32 = if bytes == 0 { 0 } else { 1 };
        let clb_va = h.wrapping_add(self.clb_pa) as *mut u32;
        // SAFETY: HHDM maps the owned command-list frame; slot zero occupies
        // dwords 0..8 and is not visible until the PxCI doorbell below.
        unsafe {
            core::ptr::write_volatile(
                clb_va.add(0),
                regs::cmd_header_dw0(CFL_DWORDS, write, prdtl),
            );
            core::ptr::write_volatile(clb_va.add(1), 0);
            core::ptr::write_volatile(clb_va.add(2), self.ctba_pa as u32);
            core::ptr::write_volatile(clb_va.add(3), (self.ctba_pa >> 32) as u32);
            for i in 4..8 { core::ptr::write_volatile(clb_va.add(i), 0); }
        }

        let ct_va = h.wrapping_add(self.ctba_pa) as *mut u8;
        // SAFETY: HHDM maps the owned command-table frame; the CFIS plus one
        // PRDT entry fit within it and the bounce PA remains controller-owned.
        unsafe {
            for i in 0..CT_PRDT_OFF { core::ptr::write_volatile(ct_va.add(i), 0); }
            for (i, b) in fis.iter().enumerate() {
                core::ptr::write_volatile(ct_va.add(i), *b);
            }
            if prdtl != 0 {
                let prdt = ct_va.add(CT_PRDT_OFF) as *mut u32;
                core::ptr::write_volatile(prdt.add(0), self.bounce_pa as u32);
                core::ptr::write_volatile(prdt.add(1), (self.bounce_pa >> 32) as u32);
                core::ptr::write_volatile(prdt.add(2), 0);
                let ioc = if interrupt { PRDT_INTERRUPT_ON_COMPLETION } else { 0 };
                core::ptr::write_volatile(
                    prdt.add(3),
                    ((bytes - 1) & PRDT_BYTE_COUNT_MASK) | ioc,
                );
            }
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::Release);
        self.clear_command_interrupts();
        self.pw(regs::P_CI, COMMAND_SLOT_ZERO);
        true
    }

    fn issue_poll(&mut self, fis: &[u8; 20], write: bool, bytes: u32) -> bool {
        if !self.stage_command(fis, write, bytes, false) { return false; }
        let deadline = now_ns().saturating_add(IO_TIMEOUT_NS);
        loop {
            if self.pr(regs::P_TFD) & regs::TFD_ERR != 0 { return false; }
            if self.pr(regs::P_CI) & COMMAND_SLOT_ZERO == 0 {
                return self.pr(regs::P_TFD) & regs::TFD_ERR == 0;
            }
            if now_ns() >= deadline { return false; }
            core::hint::spin_loop();
        }
    }

    /// Polling-only IDENTIFY used before runtime IRQ activation. # C: O(command)
    pub(crate) fn identify(&mut self) -> bool {
        let fis = regs::h2d_fis(regs::ATA_IDENTIFY, 0, 0, 0);
        if !self.issue_poll(&fis, false, 512) { return false; }
        let p = hhdm().wrapping_add(self.bounce_pa) as *const u16;
        let mut words = [0u16; 256];
        // SAFETY: the device filled the owned bounce frame with 512 bytes;
        // these aligned volatile reads remain within that frame.
        unsafe {
            for i in 0..words.len() {
                words[i] = core::ptr::read_volatile(p.add(i));
            }
        }
        self.sectors = regs::identify_sector_count(&words);
        self.blk_size = regs::identify_sector_size(&words);
        let (serial, serial_len) = regs::identify_serial(&words);
        self.serial = if serial_len == 0 {
            None
        } else {
            let mut s = String::new();
            for b in &serial[..serial_len] { s.push(*b as char); }
            Some(s)
        };
        self.sectors > 0
    }

    /// Stage and issue one interrupt-completing DMA transfer. # C: O(command)
    pub(crate) fn start_rw(&mut self, write: bool, lba: u64, count: u16) -> bool {
        let cmd = if write {
            regs::ATA_WRITE_DMA_EXT
        } else {
            regs::ATA_READ_DMA_EXT
        };
        let fis = regs::h2d_fis(cmd, lba, count, regs::ATA_DEV_LBA);
        self.stage_command(
            &fis,
            write,
            (count as u32).saturating_mul(self.blk_size),
            true,
        )
    }

    /// Stage and issue one interrupt-completing cache flush. # C: O(command)
    pub(crate) fn start_flush(&mut self) -> bool {
        let fis = regs::h2d_fis(regs::ATA_FLUSH_EXT, 0, 0, regs::ATA_DEV_LBA);
        self.stage_command(&fis, false, 0, true)
    }

    /// Validate slot-zero terminal hardware state after an IRQ. # C: O(1)
    pub(crate) fn command_finished_ok(&self) -> bool {
        self.pr(regs::P_CI) & COMMAND_SLOT_ZERO == 0
            && self.pr(regs::P_TFD) & regs::TFD_ERR == 0
    }

    /// HHDM VA of this controller's exclusive bounce frame. # C: O(1)
    pub(crate) fn bounce_va(&self) -> u64 {
        hhdm().wrapping_add(self.bounce_pa)
    }
}
