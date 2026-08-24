// CORB/RIRB command transport. Commands go out through the CORB ring;
// responses arrive in the RIRB, either collected by the interrupt handler or
// polled here. A controller whose ring DMA never answers falls back to the
// immediate-command registers, which is how a codec is still reachable on a
// controller with a broken response ring.

#![cfg(target_os = "oxide-kernel")]

use crate::platform::{now_ns, udelay};
use crate::ownership::RegLock;
use crate::regs::Regs;
use crate::ring;
use crate::uapi::*;
use crate::verb;

/// Overall deadline for one response, matching the reference's one second.
const RESPONSE_TIMEOUT_NS: u64 = 1_000_000_000;
/// Poll interval while waiting for a response.
const RESPONSE_POLL_US: u64 = 10;
/// Link reset assert/deassert deadline.
const RESET_TIMEOUT_NS: u64 = 100_000_000;
/// Settle after asserting reset, before deasserting.
const RESET_SETTLE_US: u64 = 500;
/// Settle after deasserting reset, before codecs answer.
const CODEC_INIT_US: u64 = 1_000;
/// CORB read-pointer reset acknowledgement poll.
const CORBRP_POLLS: u32 = 1000;

/// The command ring pair, as physical addresses into one shared page.
pub struct Rings {
    /// Physical base of the shared ring page.
    pub page_pa: u64,
    /// HHDM virtual base of the same page.
    pub page_va: u64,
    /// Driver's copy of the RIRB read pointer.
    pub rirb_read: u16,
    /// Commands outstanding per codec address.
    pub pending: [u8; MAX_CODECS as usize],
    /// Last response received per codec address.
    pub response: [u32; MAX_CODECS as usize],
    /// Unsolicited responses the handler collected, oldest first.
    pub unsolicited: [(u32, u32); UNSOL_QUEUE],
    pub unsolicited_count: usize,
}

/// Unsolicited responses retained before the oldest is dropped.
pub const UNSOL_QUEUE: usize = 16;

impl Rings {
    /// # C: O(1)
    pub fn new(page_pa: u64, page_va: u64) -> Self {
        Self {
            page_pa, page_va, rirb_read: 0,
            pending: [0; MAX_CODECS as usize],
            response: [0; MAX_CODECS as usize],
            unsolicited: [(0, 0); UNSOL_QUEUE],
            unsolicited_count: 0,
        }
    }

    fn corb_va(&self) -> u64 { self.page_va }
    fn rirb_va(&self) -> u64 { self.page_va + RIRB_PAGE_OFFSET }
    fn rirb_pa(&self) -> u64 { self.page_pa + RIRB_PAGE_OFFSET }
}

/// Bring the controller out of reset and record which codec slots answered.
/// Returns the `STATESTS` codec-presence mask.
/// # C: O(reset timeouts)
pub fn reset_link(regs: &Regs) -> Option<u16> {
    if regs.r32(REG_GCTL) & GCTL_RESET != 0 {
        regs.w16(REG_STATESTS, STATESTS_INT_MASK);
    }
    regs.clear32(REG_GCTL, GCTL_RESET);
    let deadline = now_ns() + RESET_TIMEOUT_NS;
    while regs.r32(REG_GCTL) & GCTL_RESET != 0 && now_ns() < deadline { udelay(RESET_SETTLE_US); }
    udelay(RESET_SETTLE_US);

    regs.set32(REG_GCTL, GCTL_RESET);
    let deadline = now_ns() + RESET_TIMEOUT_NS;
    while regs.r32(REG_GCTL) & GCTL_RESET == 0 && now_ns() < deadline { udelay(RESET_SETTLE_US); }
    // Codecs need time to come up before STATESTS is meaningful.
    udelay(CODEC_INIT_US);
    if regs.r32(REG_GCTL) & GCTL_RESET == 0 { return None; }
    Some(regs.r16(REG_STATESTS) & STATESTS_INT_MASK)
}

/// Clear every latched interrupt status the controller starts with.
/// # C: O(streams)
pub fn clear_interrupts(regs: &Regs, streams: u8) {
    for index in 0..streams { regs.w8(regs.sd(index) + SD_STS, SD_INT_MASK as u8); }
    regs.w16(REG_STATESTS, STATESTS_INT_MASK);
    regs.w8(REG_RIRBSTS, RIRBSTS_INT_MASK);
    regs.w32(REG_INTSTS, INT_CTRL_EN | INT_ALL_STREAM);
}

/// Program and start the CORB and RIRB DMA engines. # C: O(CORBRP_POLLS)
pub fn init_cmd_io(regs: &Regs, rings: &mut Rings, interrupts: bool) {
    regs.w32(REG_CORBLBASE, rings.page_pa as u32);
    regs.w32(REG_CORBUBASE, (rings.page_pa >> 32) as u32);
    regs.w8(REG_CORBSIZE, RING_SIZE_256);
    regs.w16(REG_CORBWP, 0);
    regs.w16(REG_CORBRP, CORBRP_RST);
    for _ in 0..CORBRP_POLLS {
        if regs.r16(REG_CORBRP) & CORBRP_RST != 0 { break; }
        udelay(1);
    }
    regs.w16(REG_CORBRP, 0);
    for _ in 0..CORBRP_POLLS {
        if regs.r16(REG_CORBRP) == 0 { break; }
        udelay(1);
    }
    regs.w8(REG_CORBCTL, CORBCTL_RUN);

    rings.rirb_read = 0;
    regs.w32(REG_RIRBLBASE, rings.rirb_pa() as u32);
    regs.w32(REG_RIRBUBASE, (rings.rirb_pa() >> 32) as u32);
    regs.w8(REG_RIRBSIZE, RING_SIZE_256);
    regs.w16(REG_RIRBWP, RIRBWP_RST);
    regs.w16(REG_RINTCNT, RIRB_INT_COUNT);
    // Enabling the response interrupt without a handler leaves the
    // controller asserting its line forever, so it is tied to having one.
    let rirb_ctl = if interrupts { RIRBCTL_DMA_EN | RIRBCTL_IRQ_EN } else { RIRBCTL_DMA_EN };
    regs.w8(REG_RIRBCTL, rirb_ctl);
    // Only now may the controller deliver unsolicited responses.
    regs.set32(REG_GCTL, GCTL_UNSOL);
}

/// Stop both command DMA engines. # C: O(1)
pub fn stop_cmd_io(regs: &Regs) {
    regs.w8(REG_RIRBCTL, 0);
    regs.w8(REG_CORBCTL, 0);
    regs.clear32(REG_GCTL, GCTL_UNSOL);
}

/// Post one command to the CORB. # C: O(1)
fn send_corb(regs: &Regs, rings: &mut Rings, command: u32) -> bool {
    let write = regs.r16(REG_CORBWP);
    let read = regs.r16(REG_CORBRP);
    let Some(next) = ring::corb_next_write(write, read) else { return false; };
    let addr = verb::verb_addr(command) as usize;
    if addr >= MAX_CODECS as usize { return false; }
    let slot = rings.corb_va() + ring::corb_offset(next) as u64;
    // SAFETY: the ring page is a driver-owned DMA-coherent frame reached
    // through the HHDM; `corb_offset(next)` is inside its first kibibyte.
    unsafe { core::ptr::write_volatile(slot as *mut u32, command); }
    pmm::dma::clean_to_device(slot, CORB_ENTRY_BYTES);
    rings.pending[addr] = rings.pending[addr].saturating_add(1);
    regs.w16(REG_CORBWP, next);
    true
}

/// Drain every RIRB entry the controller has produced, routing solicited
/// responses to their codec slot and queueing unsolicited ones.
/// # C: O(new entries)
pub fn update_rirb(regs: &Regs, rings: &mut Rings) -> bool {
    let hardware = regs.r16(REG_RIRBWP);
    if hardware == ring::POINTER_INVALID { return false; }
    let mut unsolicited = false;
    let mut pending = ring::rirb_pending(rings.rirb_read, hardware);
    while pending > 0 {
        pending -= 1;
        let (next, dword) = ring::rirb_step(rings.rirb_read);
        rings.rirb_read = next;
        let entry = rings.rirb_va() + (dword * 4) as u64;
        pmm::dma::invalidate_from_device(entry, RIRB_ENTRY_BYTES);
        // SAFETY: the RIRB occupies the second half of the driver-owned ring
        // page reached through the HHDM; `dword` indexes inside its 2 KiB.
        let (value, extended) = unsafe {
            (core::ptr::read_volatile(entry as *const u32),
             core::ptr::read_volatile((entry + 4) as *const u32))
        };
        let response = verb::decode_response(value, extended);
        let addr = response.addr as usize;
        if addr >= MAX_CODECS as usize { continue; }
        if response.unsolicited {
            if rings.unsolicited_count < UNSOL_QUEUE {
                rings.unsolicited[rings.unsolicited_count] = (value, extended);
                rings.unsolicited_count += 1;
                unsolicited = true;
            }
            continue;
        }
        if rings.pending[addr] != 0 {
            rings.response[addr] = value;
            rings.pending[addr] -= 1;
        }
    }
    unsolicited
}

/// Send one command through the immediate-command registers. This is the
/// path a controller whose response ring is not answering still supports.
/// # C: O(IMMEDIATE_POLLS)
fn immediate_command(regs: &Regs, command: u32) -> Option<u32> {
    for _ in 0..IMMEDIATE_POLLS {
        if regs.r16(REG_IRS) & IRS_BUSY == 0 {
            regs.w16(REG_IRS, regs.r16(REG_IRS) | IRS_VALID);
            regs.w32(REG_IC, command);
            regs.w16(REG_IRS, regs.r16(REG_IRS) | IRS_BUSY);
            for _ in 0..IMMEDIATE_POLLS {
                if regs.r16(REG_IRS) & IRS_VALID != 0 { return Some(regs.r32(REG_IR)); }
                udelay(1);
            }
            return None;
        }
        udelay(1);
    }
    None
}

/// Put one command and wait for its response. # C: O(RESPONSE_TIMEOUT_NS)
pub fn exec(regs: &Regs, ring_lock: &RegLock<Rings>, command: u32) -> Option<u32> {
    let addr = verb::verb_addr(command) as usize;
    if addr >= MAX_CODECS as usize { return None; }
    let sent = {
        let mut rings = lock_regs(ring_lock);
        send_corb(regs, &mut rings, command)
    };
    if !sent {
        lock_regs(ring_lock).pending[addr] = 0;
        return immediate_command(regs, command);
    }
    let deadline = now_ns() + RESPONSE_TIMEOUT_NS;
    loop {
        {
            let mut rings = lock_regs(ring_lock);
            let _ = update_rirb(regs, &mut rings);
            if rings.pending[addr] == 0 { return Some(rings.response[addr]); }
        }
        if now_ns() >= deadline { break; }
        udelay(RESPONSE_POLL_US);
    }
    // The ring never answered: forget the outstanding command so the next
    // one is not matched against this response, and try the direct path.
    lock_regs(ring_lock).pending[addr] = 0;
    immediate_command(regs, command)
}

/// Acquire one controller's register state with its local hard IRQ excluded.
/// # C: O(1) plus bounded IRQ-handler contention
pub fn lock_regs(rings: &RegLock<Rings>) -> impl core::ops::DerefMut<Target = Rings> + '_ {
    #[cfg(target_arch = "x86_64")]
    { rings.lock_irqsave::<hal_x86_64::X86IrqGate>() }
    #[cfg(target_arch = "aarch64")]
    { rings.lock_irqsave::<hal_aarch64::ArmIrqGate>() }
}
