//! Registration and the periodic frame producer.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicUsize, Ordering};
use sync::{Spinlock, TaskList};

use v4l2::device::VideoDevice;
use v4l2::ops::Identity;
use v4l2::uapi::flags;

use crate::device::Vivid;

struct Registered {
    vivid: Arc<Vivid>,
    device: Arc<VideoDevice>,
}

static CAMERAS: Spinlock<Vec<Registered>, TaskList> = Spinlock::new(Vec::new());

/// How many cameras are streaming right now.
///
/// The producer runs on every tick for the whole life of the machine, and for
/// almost all of it no camera is open. Reading one atomic and returning is the
/// difference between a timer callback that costs nothing and one that takes
/// two locks and allocates, sixty times a second, from boot.
static STREAMING: AtomicUsize = AtomicUsize::new(0);

/// How often the producer looks for work: twice the fastest frame rate the
/// device offers, which is enough to pace it without the tick itself becoming
/// the clock.
const TICK_NS: u64 = 1_000_000_000 / 60;

/// A camera started or stopped streaming. # C: O(1)
pub fn note_streaming(started: bool) {
    if started { STREAMING.fetch_add(1, Ordering::AcqRel); }
    else {
        let _ = STREAMING.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                                       |v| Some(v.saturating_sub(1)));
    }
}

/// Register one virtual camera and publish its node.
///
/// A machine with no camera hardware still gets `/dev/video0`, which is what
/// makes the whole capture path exercisable — and what a desktop's camera
/// settings panel needs before it will show anything at all.
/// # C: O(1)
pub fn register(index_hint: u32) -> bool {
    let vivid = Vivid::new();
    let registration = v4l2::device::Registration {
        identity: Identity {
            driver: String::from("vivid"),
            card: String::from("Virtual Video Capture"),
            bus_info: alloc::format!("platform:vivid-{:03}", index_hint),
        },
        device_caps: crate::tables::DEVICE_CAPS,
        ops: vivid.clone(),
        alloc: Arc::new(v4l2::node::FrameAlloc),
        buf_type: flags::BUF_TYPE_VIDEO_CAPTURE,
        // Only the mapped model: the pages are the driver's own, and there is
        // nothing here that can import a caller's memory or a descriptor.
        buf_caps: flags::BUF_CAP_SUPPORTS_MMAP,
        timestamp_flags: flags::BUF_FLAG_TIMESTAMP_MONOTONIC | flags::BUF_FLAG_TSTAMP_SRC_EOF,
    };
    match v4l2::node::register_and_publish(registration) {
        Ok(device) => {
            #[cfg(feature="debug-boot")]
            { klog::kinfo!("[vivid] virtual capture device published"); }
            CAMERAS.lock().push(Registered { vivid, device });
            true
        }
        Err(_) => {
            #[cfg(feature="debug-boot")]
            { klog::kwarn!("[vivid] could not publish a capture device"); }
            false
        }
    }
}

/// Produce whatever frames are due. Runs from the timer's process context, so
/// it may take the device lock and write into buffer pages.
/// # C: O(cameras * pixels)
fn tick(now: u64) {
    if STREAMING.load(Ordering::Acquire) == 0 { return; }
    let cameras: Vec<(Arc<Vivid>, Arc<VideoDevice>)> = {
        let guard = CAMERAS.lock();
        guard.iter().map(|r| (r.vivid.clone(), r.device.clone())).collect()
    };
    for (vivid, device) in cameras {
        let Some(pending) = vivid.take_due(now) else { continue };
        let format = vivid.format();
        let filled = fill(&device, pending.index, &format, pending.sequence, vivid.motion());
        let mut bytesused = [0u32; v4l2::uapi::layout::MAX_PLANES];
        bytesused[0] = filled;
        v4l2::node::buffer_done(&device, &v4l2::vb2::Completion {
            index: pending.index,
            state: v4l2::vb2::BufState::Done,
            bytesused,
            timestamp_ns: now,
            sequence: pending.sequence,
            field: flags::FIELD_NONE,
            last: false,
        });
    }
}

/// Render the pattern into the buffer's pages, returning the bytes written.
/// # C: O(pixels)
fn fill(device: &Arc<VideoDevice>, index: u32, format: &v4l2::format::PixFormat, sequence: u32,
        motion: crate::tpg::Motion)
    -> u32
{
    let stride = v4l2::uapi::fourcc::bytesperline(format.pixelformat, format.width) as usize;
    if stride == 0 { return 0; }
    let mut line = alloc::vec![0u8; stride];
    let shift = sequence % crate::tpg::BARS.len() as u32;
    if crate::tpg::render_line_at(format.pixelformat, format.width, format.height, 0, shift,
                                  sequence, motion, &mut line) == 0 {
        return 0;
    }
    // The plane's page list is copied out and the device lock dropped before
    // the pixels are written. A frame is up to a megabyte and a half; holding
    // a spinlock across that copy would park every other caller of this
    // device — and, at thirty frames a second, do it continuously.
    let (frames, length) = {
        let state = device.state.lock();
        let Some(buffer) = state.queue.buffer(index) else { return 0 };
        let Some(plane) = buffer.planes.first() else { return 0 };
        (plane.frames.clone(), plane.length as usize)
    };
    let mut written = 0usize;
    for y in 0..format.height {
        if written + stride > length { break; }
        let n = crate::tpg::render_line_at(format.pixelformat, format.width, format.height, y,
                                           shift, sequence, motion, &mut line);
        if n == 0 { break; }
        written += v4l2::node::write_plane(&frames, written, &line);
    }
    written as u32
}

/// Start the frame producer. # C: O(1)
pub fn start() { timer::register_periodic(TICK_NS, tick); }
