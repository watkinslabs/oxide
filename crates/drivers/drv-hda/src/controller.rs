// Controller bring-up and the codec-facing operations the ALSA card layer
// calls: enumerate, apply the routing plan, program a stream, read a jack.

#![cfg(target_os = "oxide-kernel")]

use alloc::{sync::Arc, vec::Vec};

use crate::bdl::Geometry;
use crate::generic::{self, OutputRoute, Plan};
use crate::graph::{self, Codec, CodecBus};
use crate::regs::Regs;
use crate::ownership::RegLock;
use crate::stream::Stream;
use crate::transport::{self, Rings};
use crate::uapi::*;
use crate::verb;
use crate::widget;

/// A codec address bound to a controller, usable as a command bus while the
/// driver lock is held.
pub struct CodecPort<'a> {
    regs: Regs,
    rings: &'a RegLock<Rings>,
    addr: u8,
}

impl<'a> CodecPort<'a> {
    /// # C: O(1)
    pub fn new(regs: Regs, rings: &'a RegLock<Rings>, addr: u8) -> Self {
        Self { regs, rings, addr }
    }
}

impl CodecBus for CodecPort<'_> {
    fn command(&self, nid: u8, cmd: u16, payload: u16) -> Option<u32> {
        let command = verb::make_verb(self.addr, nid, cmd, payload)?;
        transport::exec(&self.regs, self.rings, command)
    }
}

/// Everything one controller owns.
pub struct CodecState {
    pub codec: Codec,
    pub plan: Plan,
    /// Capture route selected by this codec's Capture Source mux.
    pub capture_source: u32,
    /// Unsolicited-response tag assigned to each jack-detectable output pin.
    pub jack_tags: [(u8, u8); MAX_JACKS],
    pub jack_count: usize,
    /// Last reported presence per tracked jack.
    pub jack_present: [bool; MAX_JACKS],
    /// Number of retaskable input pins currently driven as output pairs.
    pub multi_io_active: u8,
}

impl CodecState {
    fn new(codec: Codec, plan: Plan) -> Self {
        Self {
            codec, plan, capture_source: 0,
            jack_tags: [(0, 0); MAX_JACKS], jack_count: 0,
            jack_present: [false; MAX_JACKS], multi_io_active: 0,
        }
    }
}

pub struct Hda {
    pub regs: Regs,
    /// Controller-global DMA position-buffer address.
    pub posbuf_pa: u64,
    pub rings: Arc<RegLock<Rings>>,
    pub playback: Vec<Stream>,
    pub capture: Vec<Stream>,
    /// Codecs discovered on this controller's HDA bus, in codec-address order.
    /// Each entry owns its graph, route plan, jack state, and retask state.
    pub codecs: Vec<CodecState>,
    /// ALSA PCM device number -> `(codec index, flattened output route index)`.
    pub playback_routes: Vec<(usize, usize)>,
    /// ALSA capture device number -> `(codec index, capture route index)`.
    pub capture_routes: Vec<(usize, usize)>,
    pub streams: u8,
    /// The controller has an interrupt vector, so the response ring may be
    /// serviced by the handler. Without one the driver polls, which is a
    /// working transport rather than a broken one.
    pub interrupts: bool,
}

/// Jacks the driver tracks presence for.
pub const MAX_JACKS: usize = 4;

/// Immutable hard-IRQ endpoint for one controller. It shares only the
/// bounded register/ring state with process-side codec commands.
pub struct IrqEndpoint {
    regs: Regs,
    playback_indices: Vec<u8>,
    capture_indices: Vec<u8>,
}

impl IrqEndpoint {
    /// # C: O(1)
    pub fn new(hda: &Hda) -> Self {
        Self {
            regs: hda.regs,
            playback_indices: hda.playback.iter().map(|stream| stream.index).collect(),
            capture_indices: hda.capture.iter().map(|stream| stream.index).collect(),
        }
    }

    /// Acknowledge one controller interrupt and publish completed responses.
    /// # C: O(new responses)
    pub fn handle(&self, ring_lock: &RegLock<Rings>) -> bool {
        let mut rings = transport::lock_regs(ring_lock);
        let status = self.regs.r32(REG_INTSTS);
        if status == 0 || status == u32::MAX { return false; }
        for index in self.playback_indices.iter().chain(self.capture_indices.iter()).copied() {
            if status & (1u32 << index) == 0 { continue; }
            let sd_status = self.regs.r8(self.regs.sd(index) + SD_STS);
            self.regs.w8(self.regs.sd(index) + SD_STS, SD_INT_MASK as u8);
            let _ = sd_status;
        }
        let rirb = self.regs.r8(REG_RIRBSTS);
        let mut unsolicited = false;
        if rirb & RIRBSTS_INT_MASK != 0 {
            self.regs.w8(REG_RIRBSTS, RIRBSTS_INT_MASK);
            if rirb & RIRBSTS_IRQ != 0 { unsolicited = transport::update_rirb(&self.regs, &mut rings); }
        }
        unsolicited
    }
}

mod lifecycle;
mod routes;
