//! The video device: its live state, its handles, and the registry of every
//! device the machine has.

use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use sync::{Spinlock, TaskList};
use syscall::errno::Errno;

use crate::ctrl::Handler;
use crate::event::EventQueue;
use crate::format::{Fract, PixFormat};
use crate::ids;
use crate::ops::{Identity, VideoOps};
use crate::prio::PrioState;
use crate::uapi::flags;
use crate::vb2::{PlaneAlloc, Queue};

/// The parts of a device that change while it runs.
pub struct DevState {
    pub format: PixFormat,
    pub input: u32,
    pub interval: Fract,
    pub queue: Queue,
    /// Cleared when the device goes away, so every command on a handle that
    /// outlives it answers `ENODEV` instead of touching freed transport state.
    pub registered: bool,
}

/// One `/dev/videoN`.
pub struct VideoDevice {
    /// `videoN` — the number in the node name, and the device's index in the
    /// class.
    pub index: u32,
    /// Minor number of the node.
    pub minor: u32,
    pub identity: Identity,
    /// `V4L2_CAP_*` this node itself has. The `capabilities` field additionally
    /// carries the device-capabilities marker, which is derived rather than
    /// stored so the two can never disagree.
    pub device_caps: u32,
    pub ops: Arc<dyn VideoOps>,
    pub alloc: Arc<dyn PlaneAlloc>,
    pub controls: Handler,
    pub prio: PrioState,
    pub state: Spinlock<DevState, TaskList>,
    handles: Spinlock<Vec<Arc<FileHandle>>, TaskList>,
}

impl VideoDevice {
    /// `v4l2_capability.capabilities`: what the whole driver can do, which for
    /// a single-node device is this node's own set plus the marker saying the
    /// per-node field is meaningful. # C: O(1)
    pub fn capabilities(&self) -> u32 { self.device_caps | flags::CAP_DEVICE_CAPS }

    /// Is the device still present? # C: O(1)
    pub fn registered(&self) -> bool { self.state.lock().registered }

    /// Every open handle. # C: O(handles)
    pub fn handles(&self) -> Vec<Arc<FileHandle>> { self.handles.lock().clone() }

    /// Deliver `ev` to every handle subscribed to it, skipping `except` unless
    /// that handle asked for its own changes to be echoed back.
    /// # C: O(handles)
    pub fn broadcast(&self, ev: crate::event::Event, sec: u64, nsec: u64, except: Option<u64>)
        -> Vec<Arc<FileHandle>>
    {
        let mut woken = Vec::new();
        for handle in self.handles().into_iter() {
            let mut queue = handle.events.lock();
            if Some(handle.id) == except && !queue.wants_feedback(ev.ev_type, ev.id) { continue; }
            if queue.queue(ev, sec, nsec) { drop(queue); woken.push(handle); }
        }
        woken
    }
}

/// One open file description of a video device.
pub struct FileHandle {
    /// Identity the queue's ownership is keyed on. Unique for the lifetime of
    /// the boot, so a closed handle's number is never mistaken for a live one.
    pub id: u64,
    pub device: Arc<VideoDevice>,
    prio: AtomicU32,
    pub events: Spinlock<EventQueue, TaskList>,
}

impl FileHandle {
    /// This handle's priority. # C: O(1)
    pub fn priority(&self) -> u32 { self.prio.load(Ordering::Acquire) }

    /// `VIDIOC_S_PRIORITY`. # C: O(1)
    pub fn set_priority(&self, prio: u32) -> Result<(), Errno> {
        let previous = self.prio.swap(prio, Ordering::AcqRel);
        match self.device.prio.change(previous, prio) {
            Ok(()) => Ok(()),
            Err(e) => { self.prio.store(previous, Ordering::Release); Err(e) }
        }
    }

    /// Does this handle own the buffer queue? # C: O(1)
    pub fn owns_queue(&self) -> bool {
        self.device.state.lock().queue.owner == Some(self.id)
    }
}

static DEVICES: Spinlock<Vec<Arc<VideoDevice>>, TaskList> = Spinlock::new(Vec::new());
static NEXT_HANDLE_ID: AtomicU64 = AtomicU64::new(1);

/// Lowest free `videoN` index, or `None` when the class is full. # C: O(n)
fn free_index(taken: &[Arc<VideoDevice>]) -> Option<u32> {
    (0..ids::MAX_VIDEO_DEVICES).find(|i| !taken.iter().any(|d| d.index == *i))
}

/// What a driver hands the core to get a node.
pub struct Registration {
    pub identity: Identity,
    pub device_caps: u32,
    pub ops: Arc<dyn VideoOps>,
    pub alloc: Arc<dyn PlaneAlloc>,
    /// Buffer type the node's queue serves.
    pub buf_type: u32,
    /// `V4L2_BUF_CAP_*` memory models the driver supports.
    pub buf_caps: u32,
    /// `V4L2_BUF_FLAG_TIMESTAMP_*` and `TSTAMP_SRC_*` the driver stamps with.
    pub timestamp_flags: u32,
}

/// Register a video device, allocating it the lowest free index.
///
/// The device's starting format is the first entry of the driver's table at
/// its first frame size — a device that reports no format at all is refused,
/// because an application's first act is to enumerate one.
/// # C: O(devices)
pub fn register(reg: Registration) -> Result<Arc<VideoDevice>, Errno> {
    let mut guard = DEVICES.lock();
    let index = free_index(&guard).ok_or(Errno::Enospc)?;
    let mut format = PixFormat::empty();
    if !crate::format::try_fmt(reg.ops.formats(), &mut format, reg.ops.progressive()) {
        return Err(Errno::Einval);
    }
    let interval = reg.ops.formats().first()
        .and_then(|d| d.intervals.first().copied())
        .unwrap_or(Fract { numerator: 1, denominator: 30 });
    let controls = Handler::new(&reg.ops.controls());
    let device = Arc::new(VideoDevice {
        index,
        minor: ids::VIDEO_MINOR_BASE + index,
        identity: reg.identity,
        device_caps: reg.device_caps,
        ops: reg.ops,
        alloc: reg.alloc,
        controls,
        prio: PrioState::new(),
        state: Spinlock::new(DevState {
            format, input: 0, interval,
            queue: Queue::new(reg.buf_type, reg.buf_caps, reg.timestamp_flags),
            registered: true,
        }),
        handles: Spinlock::new(Vec::new()),
    });
    guard.push(device.clone());
    Ok(device)
}

/// Remove a device. Open handles survive and answer `ENODEV`, which is what
/// lets a program notice a camera was unplugged instead of faulting.
/// # C: O(devices)
pub fn unregister(device: &Arc<VideoDevice>) {
    {
        let mut state = device.state.lock();
        state.registered = false;
        if state.queue.streaming { device.ops.stop_streaming(); }
        crate::vb2::stream::cancel(&mut state.queue);
    }
    let mut guard = DEVICES.lock();
    guard.retain(|d| d.index != device.index);
}

/// Device with node index `index`. # C: O(devices)
pub fn by_index(index: u32) -> Option<Arc<VideoDevice>> {
    DEVICES.lock().iter().find(|d| d.index == index).cloned()
}

/// Device owning `minor`. # C: O(devices)
pub fn by_minor(minor: u32) -> Option<Arc<VideoDevice>> {
    DEVICES.lock().iter().find(|d| d.minor == minor).cloned()
}

/// Every registered device, lowest index first. # C: O(devices)
pub fn all() -> Vec<Arc<VideoDevice>> {
    let mut list = DEVICES.lock().clone();
    list.sort_by_key(|d| d.index);
    list
}

/// Open a handle on `device`. # C: O(handles)
pub fn open(device: &Arc<VideoDevice>) -> Arc<FileHandle> {
    let handle = Arc::new(FileHandle {
        id: NEXT_HANDLE_ID.fetch_add(1, Ordering::AcqRel),
        device: device.clone(),
        prio: AtomicU32::new(flags::PRIORITY_DEFAULT),
        events: Spinlock::new(EventQueue::new()),
    });
    device.prio.change(flags::PRIORITY_UNSET, flags::PRIORITY_DEFAULT).ok();
    device.handles.lock().push(handle.clone());
    handle
}

/// Close a handle.
///
/// The handle that owns the queue takes the buffers with it: a stream left
/// running by a program that exited would keep the device busy forever, and
/// the next program to open it would find a queue it cannot claim.
/// # C: O(handles + buffers)
pub fn close(handle: &Arc<FileHandle>) {
    let device = handle.device.clone();
    device.prio.release(handle.priority());
    {
        let mut state = device.state.lock();
        if state.queue.owner == Some(handle.id) {
            // The transport must be quiet before the buffers go, or it
            // completes into memory the allocator has taken back.
            if state.queue.streaming { device.ops.stop_streaming(); }
            crate::vb2::stream::cancel(&mut state.queue);
            let alloc = device.alloc.clone();
            crate::vb2::reqbufs::free_buffers(&mut state.queue, alloc.as_ref());
        }
    }
    device.handles.lock().retain(|h| h.id != handle.id);
}
