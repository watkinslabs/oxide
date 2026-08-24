//! A fake capture device the command surface can be driven against without a
//! kernel: no hardware, no user memory, no scheduler.

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use sync::{Spinlock, TaskList};
use syscall::errno::Errno;

use crate::ctrl::{standard, ControlDesc};
use crate::device::{self, FileHandle, Registration, VideoDevice};
use crate::format::{Fract, FormatDesc, FrameSize, PixFormat};
use crate::ioctl::Ctx;
use crate::ops::{Identity, InputDesc, VideoOps};
use crate::uapi::{ctrl_ids as cid, flags, fourcc};
use crate::usermem::UserMem;
use crate::vb2::PlaneAlloc;

pub const SIZES: &[FrameSize] = &[
    FrameSize { width: 320, height: 240 },
    FrameSize { width: 640, height: 480 },
    FrameSize { width: 1280, height: 720 },
];
pub const INTERVALS: &[Fract] = &[
    Fract { numerator: 1, denominator: 30 },
    Fract { numerator: 1, denominator: 15 },
    Fract { numerator: 1, denominator: 5 },
];
pub const FORMATS: &[FormatDesc] = &[
    FormatDesc { pixelformat: fourcc::YUYV, description: "YUYV 4:2:2", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::RGB24, description: "24-bit RGB", flags: 0,
                 sizes: SIZES, intervals: INTERVALS, compressed_sizeimage: 0 },
    FormatDesc { pixelformat: fourcc::MJPEG, description: "Motion-JPEG",
                 flags: flags::FMT_FLAG_COMPRESSED, sizes: SIZES, intervals: INTERVALS,
                 compressed_sizeimage: 1024 * 1024 },
];
pub const INPUTS: &[InputDesc] = &[
    InputDesc { name: "Camera", input_type: flags::INPUT_TYPE_CAMERA, status: 0,
                capabilities: 0 },
    InputDesc { name: "Camera 2", input_type: flags::INPUT_TYPE_CAMERA,
                status: flags::IN_ST_NO_SIGNAL, capabilities: 0 },
];

/// The driver under test: it records what the core asked of it and refuses on
/// command, which is how the failure paths get exercised.
pub struct FakeOps {
    pub started: AtomicBool,
    pub start_count: AtomicU32,
    pub stop_count: AtomicU32,
    pub queued: Spinlock<Vec<u32>, TaskList>,
    pub refuse_start: AtomicBool,
    pub input: AtomicU32,
    pub changed: Spinlock<Vec<(u32, i64)>, TaskList>,
}

impl FakeOps {
    pub fn new() -> Arc<FakeOps> {
        Arc::new(FakeOps {
            started: AtomicBool::new(false), start_count: AtomicU32::new(0),
            stop_count: AtomicU32::new(0), queued: Spinlock::new(Vec::new()),
            refuse_start: AtomicBool::new(false), input: AtomicU32::new(0),
            changed: Spinlock::new(Vec::new()),
        })
    }
}

impl VideoOps for FakeOps {
    fn formats(&self) -> &'static [FormatDesc] { FORMATS }
    fn inputs(&self) -> &'static [InputDesc] { INPUTS }
    fn set_format(&self, _f: &PixFormat) {}
    fn set_input(&self, index: u32) -> Result<(), Errno> {
        self.input.store(index, Ordering::Release);
        Ok(())
    }
    fn set_interval(&self, _i: Fract) {}
    fn start_streaming(&self, handed: &[u32]) -> Result<(), Errno> {
        if self.refuse_start.load(Ordering::Acquire) { return Err(Errno::Eio); }
        self.start_count.fetch_add(1, Ordering::AcqRel);
        self.started.store(true, Ordering::Release);
        self.queued.lock().extend_from_slice(handed);
        Ok(())
    }
    fn stop_streaming(&self) {
        self.stop_count.fetch_add(1, Ordering::AcqRel);
        self.started.store(false, Ordering::Release);
        self.queued.lock().clear();
    }
    fn buf_queue(&self, index: u32) { self.queued.lock().push(index); }
    fn controls(&self) -> Vec<ControlDesc> {
        alloc::vec![
            standard::USER_CLASS,
            standard::simple(cid::CID_BRIGHTNESS, cid::CTRL_TYPE_INTEGER, "Brightness",
                             -64, 64, 2, 0),
            standard::simple(cid::CID_CONTRAST, cid::CTRL_TYPE_INTEGER, "Contrast",
                             0, 100, 1, 50),
            standard::simple(cid::CID_HFLIP, cid::CTRL_TYPE_BOOLEAN, "Horizontal Flip",
                             0, 1, 1, 0),
            standard::POWER_LINE_FREQUENCY,
            standard::AUTO_WHITE_BALANCE,
            standard::simple(cid::CID_WHITE_BALANCE_TEMPERATURE, cid::CTRL_TYPE_INTEGER,
                             "White Balance Temperature", 2800, 6500, 100, 4600),
            standard::CAMERA_CLASS,
            standard::EXPOSURE_AUTO,
            standard::simple(cid::CID_EXPOSURE_ABSOLUTE, cid::CTRL_TYPE_INTEGER,
                             "Exposure Time, Absolute", 1, 10000, 1, 156),
            standard::simple(cid::CID_EXPOSURE_AUTO_PRIORITY, cid::CTRL_TYPE_BOOLEAN,
                             "Exposure, Dynamic Framerate", 0, 1, 1, 0),
        ]
    }
    fn control_changed(&self, id: u32, value: i64) -> bool {
        self.changed.lock().push((id, value));
        false
    }
}

/// Plane allocator handing out increasing fake frame addresses, counting what
/// it gave out so a leak is visible to a test.
pub struct FakeAlloc {
    next: AtomicU32,
    pub outstanding: AtomicU32,
}

impl FakeAlloc {
    pub fn new() -> Arc<FakeAlloc> {
        Arc::new(FakeAlloc { next: AtomicU32::new(1), outstanding: AtomicU32::new(0) })
    }
}

impl PlaneAlloc for FakeAlloc {
    fn alloc(&self, bytes: u32) -> Option<Vec<u64>> {
        let pages = bytes.div_ceil(4096).max(1);
        let mut frames = Vec::new();
        for _ in 0..pages {
            let n = self.next.fetch_add(1, Ordering::AcqRel);
            frames.push((n as u64) << 12);
        }
        self.outstanding.fetch_add(pages, Ordering::AcqRel);
        Some(frames)
    }
    fn free(&self, frames: &[u64]) {
        self.outstanding.fetch_sub(frames.len() as u32, Ordering::AcqRel);
    }
}

/// A flat model of the caller's address space, keyed by address.
pub struct FakeUser {
    memory: Spinlock<Vec<(u64, Vec<u8>)>, TaskList>,
}

impl FakeUser {
    pub fn new() -> FakeUser { FakeUser { memory: Spinlock::new(Vec::new()) } }
    /// Place `bytes` at `addr` so a command can follow a pointer to them,
    /// replacing whatever was there — a second batch at the same address must
    /// not be shadowed by the first, which would have a test assert against a
    /// previous call's data.
    pub fn place(&self, addr: u64, bytes: Vec<u8>) {
        let mut guard = self.memory.lock();
        guard.retain(|(base, _)| *base != addr);
        guard.push((addr, bytes));
    }
    /// Read back what a command wrote.
    pub fn peek(&self, addr: u64, len: usize) -> Vec<u8> {
        let mut out = alloc::vec![0u8; len];
        let _ = self.read(addr, &mut out);
        out
    }
}

impl UserMem for FakeUser {
    fn read(&self, addr: u64, dst: &mut [u8]) -> Result<(), Errno> {
        let guard = self.memory.lock();
        for (base, bytes) in guard.iter() {
            if addr >= *base && addr + dst.len() as u64 <= *base + bytes.len() as u64 {
                let off = (addr - *base) as usize;
                dst.copy_from_slice(&bytes[off..off + dst.len()]);
                return Ok(());
            }
        }
        Err(Errno::Efault)
    }
    fn write(&self, addr: u64, src: &[u8]) -> Result<(), Errno> {
        let mut guard = self.memory.lock();
        for (base, bytes) in guard.iter_mut() {
            if addr >= *base && addr + src.len() as u64 <= *base + bytes.len() as u64 {
                let off = (addr - *base) as usize;
                bytes[off..off + src.len()].copy_from_slice(src);
                return Ok(());
            }
        }
        Err(Errno::Efault)
    }
}

/// The context a hosted command runs in: no clock, no sleeping. A blocking
/// wait is an error rather than a hang, so a test that reaches one fails
/// instead of stalling the suite.
pub struct FakeCtx {
    pub nonblocking: bool,
    pub user: FakeUser,
    pub waits: AtomicU32,
    pub wakes: AtomicU32,
    /// Was the queue marked as having a parked reader at the moment the wait
    /// ran? Observed here because that is the only point the flag is true.
    pub saw_waiting: AtomicBool,
}

impl FakeCtx {
    pub fn new(nonblocking: bool) -> FakeCtx {
        FakeCtx { nonblocking, user: FakeUser::new(),
                  waits: AtomicU32::new(0), wakes: AtomicU32::new(0),
                  saw_waiting: AtomicBool::new(false) }
    }
}

impl Ctx for FakeCtx {
    fn now(&self) -> (u64, u64) { (1234, 567_000_000) }
    fn nonblocking(&self) -> bool { self.nonblocking }
    fn wait_for_buffer(&self, device: &Arc<VideoDevice>) -> Result<(), Errno> {
        self.waits.fetch_add(1, Ordering::AcqRel);
        if device.state.lock().queue.waiting_in_dqbuf {
            self.saw_waiting.store(true, Ordering::Release);
        }
        Err(Errno::Eintr)
    }
    fn user(&self) -> &dyn UserMem { &self.user }
    fn wake(&self, _device: &Arc<VideoDevice>) { self.wakes.fetch_add(1, Ordering::AcqRel); }
}

/// One registered fake device with one open handle.
pub struct Rig {
    pub device: Arc<VideoDevice>,
    pub handle: Arc<FileHandle>,
    pub ops: Arc<FakeOps>,
    pub alloc: Arc<FakeAlloc>,
}

impl Rig {
    /// Register a fake capture device and open a handle on it. # C: O(1)
    pub fn new() -> Rig {
        let ops = FakeOps::new();
        let alloc = FakeAlloc::new();
        let device = device::register(Registration {
            identity: Identity {
                driver: String::from("fake"),
                card: String::from("Fake Camera"),
                bus_info: String::from("platform:fake"),
            },
            device_caps: flags::CAP_VIDEO_CAPTURE | flags::CAP_STREAMING
                | flags::CAP_EXT_PIX_FORMAT,
            ops: ops.clone(),
            alloc: alloc.clone(),
            buf_type: flags::BUF_TYPE_VIDEO_CAPTURE,
            buf_caps: flags::BUF_CAP_SUPPORTS_MMAP | flags::BUF_CAP_SUPPORTS_USERPTR,
            timestamp_flags: flags::BUF_FLAG_TIMESTAMP_MONOTONIC,
        }).expect("device registers");
        let handle = device::open(&device);
        Rig { device, handle, ops, alloc }
    }

    /// Run one command with a fresh zeroed argument buffer of `size` bytes.
    /// # C: per command
    pub fn call(&self, cmd: u64, arg: &mut [u8], ctx: &FakeCtx) -> Result<(), Errno> {
        crate::ioctl::dispatch(&self.handle, cmd, arg, ctx)
    }

    /// Allocate `count` MMAP buffers, returning how many were made. # C: O(count)
    pub fn reqbufs(&self, count: u32, ctx: &FakeCtx) -> Result<u32, Errno> {
        use crate::uapi::layout as l;
        let mut arg = alloc::vec![0u8; l::REQUESTBUFFERS_SIZE];
        crate::usermem::w32(&mut arg, l::REQBUFS_COUNT, count);
        crate::usermem::w32(&mut arg, l::REQBUFS_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
        crate::usermem::w32(&mut arg, l::REQBUFS_MEMORY, flags::MEMORY_MMAP);
        self.call(crate::uapi::ioctl::VIDIOC_REQBUFS, &mut arg, ctx)?;
        Ok(crate::usermem::r32(&arg, l::REQBUFS_COUNT))
    }

    /// Queue the buffer at `index`. # C: O(1)
    pub fn qbuf(&self, index: u32, ctx: &FakeCtx) -> Result<(), Errno> {
        use crate::uapi::layout as l;
        let mut arg = alloc::vec![0u8; l::BUFFER_SIZE];
        crate::usermem::w32(&mut arg, l::BUF_INDEX, index);
        crate::usermem::w32(&mut arg, l::BUF_TYPE, flags::BUF_TYPE_VIDEO_CAPTURE);
        crate::usermem::w32(&mut arg, l::BUF_MEMORY, flags::MEMORY_MMAP);
        self.call(crate::uapi::ioctl::VIDIOC_QBUF, &mut arg, ctx)
    }

    /// Start the stream. # C: O(1)
    pub fn streamon(&self, ctx: &FakeCtx) -> Result<(), Errno> {
        let mut arg = flags::BUF_TYPE_VIDEO_CAPTURE.to_le_bytes().to_vec();
        self.call(crate::uapi::ioctl::VIDIOC_STREAMON, &mut arg, ctx)
    }

    /// Stop the stream. # C: O(1)
    pub fn streamoff(&self, ctx: &FakeCtx) -> Result<(), Errno> {
        let mut arg = flags::BUF_TYPE_VIDEO_CAPTURE.to_le_bytes().to_vec();
        self.call(crate::uapi::ioctl::VIDIOC_STREAMOFF, &mut arg, ctx)
    }

    /// Complete the buffer at `index` as the driver would. # C: O(1)
    pub fn complete(&self, index: u32, sequence: u32, bytes: u32) -> bool {
        let mut bytesused = [0u32; crate::uapi::layout::MAX_PLANES];
        bytesused[0] = bytes;
        let mut state = self.device.state.lock();
        crate::vb2::stream::buffer_done(&mut state.queue, &crate::vb2::Completion {
            index, state: crate::vb2::BufState::Done, bytesused,
            timestamp_ns: 5_000_000_000, sequence, field: flags::FIELD_NONE, last: false,
        })
    }
}

impl Drop for Rig {
    fn drop(&mut self) {
        device::close(&self.handle);
        device::unregister(&self.device);
    }
}
