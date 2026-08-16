//! What a video-capture driver supplies to the device core.
//!
//! The core owns everything an application talks to: the command surface, the
//! buffer queue, the controls, the events, the node. A driver owns the
//! transport — how a frame is actually obtained — and describes itself in the
//! core's terms. A transport-private encoding never crosses this boundary.

use alloc::string::String;
use alloc::vec::Vec;
use syscall::errno::Errno;

use crate::format::{Fract, FormatDesc, PixFormat};

/// The three identity strings `VIDIOC_QUERYCAP` reports.
#[derive(Clone, Debug)]
pub struct Identity {
    /// Module name, as an application matches on to recognise a driver.
    pub driver: String,
    /// Human-readable device name.
    pub card: String,
    /// Bus location, which is what makes two identical cameras
    /// distinguishable.
    pub bus_info: String,
}

/// One video input a device can select between.
#[derive(Copy, Clone, Debug)]
pub struct InputDesc {
    pub name: &'static str,
    /// `V4L2_INPUT_TYPE_*`.
    pub input_type: u32,
    /// `V4L2_IN_ST_*` bits describing what is wrong with the signal, zero when
    /// nothing is.
    pub status: u32,
    /// `V4L2_IN_CAP_*`.
    pub capabilities: u32,
}

/// A driver's transport.
pub trait VideoOps: Send + Sync {
    /// Formats this device produces, in preference order — the first entry is
    /// what a caller asking for something unsupported is given.
    /// # C: O(1)
    fn formats(&self) -> &'static [FormatDesc];

    /// Inputs this device selects between. A camera with one sensor still
    /// reports one input: an application enumerates them before it will use
    /// the device at all.
    /// # C: O(1)
    fn inputs(&self) -> &'static [InputDesc];

    /// The device now delivers `format`. Called after the core has settled the
    /// negotiation, so the format is one this driver declared.
    /// # C: O(1)
    fn set_format(&self, format: &PixFormat);

    /// Select an input the core has already bounds-checked. # C: O(1)
    fn set_input(&self, index: u32) -> Result<(), Errno>;

    /// The device now paces at `interval`, already clamped to the declared
    /// set. # C: O(1)
    fn set_interval(&self, interval: Fract);

    /// Begin producing frames into the buffers named by `handed`, in that
    /// order. A refusal leaves the queue as it was, with every buffer back in
    /// the queued state and usable by a second attempt.
    /// # C: O(handed)
    fn start_streaming(&self, handed: &[u32]) -> Result<(), Errno>;

    /// Stop producing frames. Must not return until the device will not
    /// complete another buffer, because the caller frees them next.
    /// # C: O(1)
    fn stop_streaming(&self);

    /// A buffer became available mid-stream. # C: O(1)
    fn buf_queue(&self, index: u32);

    /// Bytes each plane needs for `format`, and how many planes there are.
    /// The default derives both from the format the core already computed,
    /// which is right for every single-planar capture device.
    /// # C: O(1)
    fn queue_setup(&self, count: u32, format: &PixFormat) -> crate::vb2::QueueSetup {
        let mut plane_sizes = [0u32; crate::uapi::layout::MAX_PLANES];
        plane_sizes[0] = format.sizeimage.max(1);
        crate::vb2::QueueSetup { count: count.max(1), num_planes: 1, plane_sizes }
    }

    /// Controls this device offers, in any order — the handler sorts them.
    /// # C: O(1)
    fn controls(&self) -> Vec<crate::ctrl::ControlDesc> { Vec::new() }

    /// A control's value changed. A driver that programs hardware from a
    /// control does it here.
    /// # C: O(1)
    fn control_changed(&self, _id: u32, _value: i64) {}

    /// Is the device progressive, i.e. does it deliver whole frames? A
    /// progressive device reports `V4L2_FIELD_NONE` whatever the caller asked
    /// for.
    /// # C: O(1)
    fn progressive(&self) -> bool { true }
}
