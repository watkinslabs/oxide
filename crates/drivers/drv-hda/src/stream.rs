// Stream descriptor programming and the playback/capture data path. One
// output stream and one input stream, each with its own BDL and a
// contiguous DMA buffer the driver copies through.

#![cfg(target_os = "oxide-kernel")]

use crate::bdl::{self, Geometry};
use crate::platform::{now_ns, udelay};
use crate::regs::Regs;
use crate::uapi::*;

/// Periods per stream buffer.
pub const PERIODS: u32 = 4;
/// Buffer order: `PERIODS` periods of at most a page each.
pub const BUFFER_ORDER: u32 = 2;
pub const BUFFER_BYTES: u32 = (hal::PAGE_SIZE_BYTES as u32) << BUFFER_ORDER;
/// Largest period the buffer can hold while keeping `PERIODS` of them.
pub const MAX_PERIOD_BYTES: u32 = BUFFER_BYTES / PERIODS;

/// Stream reset assert/deassert poll bound.
const RESET_POLL_US: u64 = 3;
const RESET_TIMEOUT_NS: u64 = 300_000;
/// How long a transfer waits for the hardware to free ring space.
const XFER_TIMEOUT_NS: u64 = 500_000_000;

/// One programmed stream descriptor.
pub struct Stream {
    /// Stream descriptor index in the controller's register file.
    pub index: u8,
    /// Stream tag the codec converter is bound to.
    pub tag: u8,
    pub bdl_pa: u64,
    pub bdl_va: u64,
    pub buffer_pa: u64,
    pub buffer_va: u64,
    /// This descriptor's slot in the controller-global DMA position buffer.
    pub posbuf_va: u64,
    pub geometry: Geometry,
    pub frame_bytes: u32,
    /// Byte offset the driver has filled to.
    pub write_off: u32,
    /// Completed laps of the ring, so a pointer keeps counting past the end.
    pub laps: u64,
    /// Last hardware position seen, used to spot a lap.
    pub last_position: u32,
    pub running: bool,
}

impl Stream {
    /// # C: O(1)
    pub fn new(index: u8, tag: u8, bdl_pa: u64, bdl_va: u64, buffer_pa: u64,
               buffer_va: u64, posbuf_va: u64) -> Self {
        Self {
            index, tag, bdl_pa, bdl_va, buffer_pa, buffer_va, posbuf_va,
            geometry: Geometry { period_bytes: MAX_PERIOD_BYTES, periods: PERIODS },
            frame_bytes: 4, write_off: 0, laps: 0, last_position: 0, running: false,
        }
    }

    fn ctl(&self, regs: &Regs) -> u64 { regs.sd(self.index) + SD_CTL }

    /// Stop DMA and clear the latched status. # C: O(1)
    pub fn stop(&mut self, regs: &Regs) {
        regs.clear32(self.ctl(regs), SD_CTL_DMA_START | SD_INT_MASK);
        regs.w8(regs.sd(self.index) + SD_STS, SD_INT_MASK as u8);
        regs.clear32(REG_INTCTL, 1u32 << self.index);
        self.running = false;
    }

    /// Full stream reset: the controller requires DMA stopped first, then the
    /// reset bit set and cleared, each acknowledged.
    /// # C: O(RESET_TIMEOUT_NS)
    pub fn reset(&mut self, regs: &Regs) {
        self.stop(regs);
        regs.set32(self.ctl(regs), SD_CTL_STREAM_RESET);
        let deadline = now_ns() + RESET_TIMEOUT_NS;
        while regs.r32(self.ctl(regs)) & SD_CTL_STREAM_RESET == 0 && now_ns() < deadline {
            udelay(RESET_POLL_US);
        }
        regs.clear32(self.ctl(regs), SD_CTL_STREAM_RESET);
        let deadline = now_ns() + RESET_TIMEOUT_NS;
        while regs.r32(self.ctl(regs)) & SD_CTL_STREAM_RESET != 0 && now_ns() < deadline {
            udelay(RESET_POLL_US);
        }
        self.write_off = 0;
        self.laps = 0;
        self.last_position = 0;
    }

    /// Write the BDL and program the descriptor for `format`.
    /// # C: O(periods)
    pub fn setup(&mut self, regs: &Regs, format: u16, geometry: Geometry, frame_bytes: u32) -> bool {
        let Some(entries) = bdl::build(self.buffer_pa, &geometry) else { return false; };
        for (index, entry) in entries.iter().enumerate() {
            let words = bdl::encode(entry);
            let slot = self.bdl_va + (index * BDL_ENTRY_BYTES) as u64;
            for (word, value) in words.iter().enumerate() {
                // SAFETY: the BDL page is a driver-owned DMA frame reached
                // through the HHDM; `build` refused any list longer than the
                // page holds, so `slot` is inside it.
                unsafe { core::ptr::write_volatile((slot + (word * 4) as u64) as *mut u32, *value); }
            }
        }
        pmm::dma::clean_to_device(self.bdl_va, entries.len() * BDL_ENTRY_BYTES);

        self.geometry = geometry;
        self.frame_bytes = frame_bytes.max(1);
        self.reset(regs);
        // SAFETY: `posbuf_va` is this stream's aligned u32 slot in the
        // probe-owned DMA page, kept alive until controller teardown.
        unsafe { core::ptr::write_volatile(self.posbuf_va as *mut u32, 0); }
        pmm::dma::clean_to_device(self.posbuf_va, core::mem::size_of::<u32>());

        let base = regs.sd(self.index);
        let tagged = (regs.r32(base + SD_CTL) & !SD_CTL_STREAM_TAG_MASK)
            | (u32::from(self.tag) << SD_CTL_STREAM_TAG_SHIFT);
        regs.w32(base + SD_CTL, tagged);
        regs.w32(base + SD_CBL, geometry.buffer_bytes());
        regs.w16(base + SD_FORMAT, format);
        regs.w16(base + SD_LVI, (entries.len() - 1) as u16);
        regs.w32(base + SD_BDLPL, self.bdl_pa as u32);
        regs.w32(base + SD_BDLPU, (self.bdl_pa >> 32) as u32);
        regs.set32(REG_DPLBASE, DPLBASE_ENABLE);
        regs.set32(base + SD_CTL, SD_INT_MASK);
        true
    }

    /// Start DMA and enable this stream's interrupt. # C: O(1)
    pub fn start(&mut self, regs: &Regs) {
        regs.set32(REG_INTCTL, 1u32 << self.index);
        regs.set32(self.ctl(regs), SD_CTL_DMA_START | SD_INT_MASK);
        self.running = true;
    }

    /// Suspend DMA without touching the ring position. # C: O(1)
    pub fn pause(&mut self, regs: &Regs) {
        regs.clear32(self.ctl(regs), SD_CTL_DMA_START);
        self.running = false;
    }

    /// Byte position the hardware has reached in the buffer. # C: O(1)
    pub fn position(&self, regs: &Regs) -> u32 {
        let buffer = self.geometry.buffer_bytes();
        if buffer == 0 { return 0; }
        pmm::dma::invalidate_from_device(self.posbuf_va, core::mem::size_of::<u32>());
        // SAFETY: `posbuf_va` is this stream's aligned slot in the live
        // probe-owned DMA page, and invalidation made the device write visible.
        let posbuf = unsafe { core::ptr::read_volatile(self.posbuf_va as *const u32) };
        crate::position::select(posbuf, regs.r32(regs.sd(self.index) + SD_LPIB), buffer)
    }

    /// Frames the hardware has consumed since setup, counting laps so the
    /// answer keeps rising past the end of the buffer.
    /// # C: O(1)
    pub fn frames(&mut self, regs: &Regs) -> u64 {
        let position = self.position(regs);
        if position < self.last_position { self.laps += 1; }
        self.last_position = position;
        bdl::total_frames(self.laps, self.geometry.buffer_bytes(), position, self.frame_bytes)
    }

    /// Copy `bytes` into the ring, waiting for the hardware to make room.
    /// Returns the count accepted, which is short only on timeout.
    /// # C: O(bytes) plus the wait for ring space
    pub fn write(&mut self, regs: &Regs, bytes: &[u8]) -> usize {
        let size = self.geometry.buffer_bytes();
        if size == 0 { return 0; }
        let mut done = 0usize;
        let deadline = now_ns() + XFER_TIMEOUT_NS;
        while done < bytes.len() {
            let free = if self.running { bdl::writable(size, self.write_off, self.position(regs)) }
                       else { size - 1 };
            if free == 0 {
                if now_ns() >= deadline { break; }
                udelay(RESET_POLL_US);
                continue;
            }
            let take = usize::min(bytes.len() - done, free as usize);
            let (head, tail) = bdl::split_at_wrap(size, self.write_off, take as u32);
            self.copy_in(&bytes[done..done + head as usize], self.write_off);
            if tail != 0 {
                self.copy_in(&bytes[done + head as usize..done + take], 0);
            }
            self.write_off = bdl::advance(size, self.write_off, take as u32);
            done += take;
        }
        done
    }

    fn copy_in(&self, src: &[u8], offset: u32) {
        let base = self.buffer_va + u64::from(offset);
        for (index, byte) in src.iter().enumerate() {
            // SAFETY: the stream buffer is a driver-owned contiguous DMA
            // allocation reached through the HHDM; `offset + src.len()` was
            // bounded by the ring split before the call.
            unsafe { core::ptr::write_volatile((base + index as u64) as *mut u8, *byte); }
        }
        pmm::dma::clean_to_device(base, src.len());
    }

    /// Copy captured bytes out of the ring behind the hardware position.
    /// # C: O(out.len)
    pub fn read(&mut self, regs: &Regs, out: &mut [u8]) -> usize {
        let size = self.geometry.buffer_bytes();
        if size == 0 { return 0; }
        let mut done = 0usize;
        let deadline = now_ns() + XFER_TIMEOUT_NS;
        while done < out.len() {
            let position = self.position(regs);
            let available = position.wrapping_sub(self.write_off) % size;
            if available == 0 {
                if now_ns() >= deadline { break; }
                udelay(RESET_POLL_US);
                continue;
            }
            let take = usize::min(out.len() - done, available as usize);
            let (head, tail) = bdl::split_at_wrap(size, self.write_off, take as u32);
            self.copy_out(&mut out[done..done + head as usize], self.write_off);
            if tail != 0 { self.copy_out(&mut out[done + head as usize..done + take], 0); }
            self.write_off = bdl::advance(size, self.write_off, take as u32);
            done += take;
        }
        done
    }

    fn copy_out(&self, dst: &mut [u8], offset: u32) {
        let base = self.buffer_va + u64::from(offset);
        pmm::dma::invalidate_from_device(base, dst.len());
        for (index, byte) in dst.iter_mut().enumerate() {
            // SAFETY: as copy_in — the stream buffer is driver-owned and the
            // span was bounded by the ring split before the call.
            *byte = unsafe { core::ptr::read_volatile((base + index as u64) as *const u8) };
        }
    }

    /// Zero the whole buffer, so a started-but-unfed stream plays silence
    /// rather than whatever the frame previously held. # C: O(buffer)
    pub fn silence(&self) {
        for offset in 0..self.geometry.buffer_bytes() {
            // SAFETY: driver-owned contiguous DMA buffer reached through the
            // HHDM, written entirely within its own length.
            unsafe { core::ptr::write_volatile((self.buffer_va + u64::from(offset)) as *mut u8, 0); }
        }
        pmm::dma::clean_to_device(self.buffer_va, self.geometry.buffer_bytes() as usize);
    }
}
