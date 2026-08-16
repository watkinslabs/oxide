//! `/usr/local/bin/v4l2_capture_probe` — one real capture through
//! `/dev/video0`.
//!
//! A node in `/dev` proves publication and nothing else. This drives the path
//! an application drives — `QUERYCAP`, `ENUM_FMT`, `G_FMT`, `ENUMINPUT`, the
//! control query and a write, `REQBUFS`, `mmap`, `QBUF`, `STREAMON`, blocking
//! `DQBUF` — and asserts each frame carries a payload, the done flag and a
//! mapped page that is no longer zero. The last of those is the one that
//! matters: a buffer can complete with perfect bookkeeping and never have been
//! written to, and only reading the mapping tells the two apart.

use support::{fail, fail_errno, report, line, Verdict};

mod uapi;
use uapi::*;

const PROBE: &str = "v4l2_probe";
const NODE: &str = "/dev/video0";
/// Frames to capture. More than one, so a stream that produces exactly one
/// buffer and then stalls is not mistaken for a working camera.
const FRAMES: u32 = 3;
/// Buffers to ask for.
const WANT_BUFFERS: u32 = 3;

fn main() -> std::process::ExitCode { report(PROBE, run()) }

/// `ioctl(fd, request, &mut buf)`. # C: O(1)
fn ioctl(fd: libc::c_int, request: libc::c_ulong, buf: &mut [u8]) -> i32 {
    // SAFETY: `buf` is a live, uniquely borrowed allocation at least as large
    // as the size the request encodes, which is what the kernel copies.
    unsafe { libc::ioctl(fd, request, buf.as_mut_ptr()) }
}

/// `ioctl` whose argument is a bare `int`, as the streaming commands take.
/// # C: O(1)
fn ioctl_int(fd: libc::c_int, request: libc::c_ulong, value: i32) -> i32 {
    let mut v = value;
    // SAFETY: the request encodes a four-byte argument and `v` is exactly that.
    unsafe { libc::ioctl(fd, request, &mut v as *mut i32) }
}

struct Mapped { addr: *mut libc::c_void, len: usize }

impl Mapped {
    /// Is any byte of the first `len` non-zero, sampled on a stride so a whole
    /// frame is covered without reading every byte? # C: O(len/stride)
    fn any_nonzero(&self, len: usize) -> bool {
        // SAFETY: the mapping covers `self.len` readable bytes and the walk is
        // bounded by `min(len, self.len)`.
        let bytes = unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.len) };
        bytes.iter().take(len.min(self.len)).step_by(509).any(|b| *b != 0)
    }
    /// The first eight bytes, as hex. # C: O(1)
    fn head(&self) -> String {
        // SAFETY: as `any_nonzero`; the mapping is at least eight bytes.
        let bytes = unsafe { core::slice::from_raw_parts(self.addr as *const u8, self.len.min(8)) };
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

fn run() -> Verdict {
    let path = std::ffi::CString::new(NODE).unwrap();
    // SAFETY: a NUL-terminated path and a flags word; the descriptor is closed
    // by the process exiting.
    let fd = unsafe { libc::open(path.as_ptr(), libc::O_RDWR) };
    if fd < 0 { return fail_errno("open"); }

    // --- identity -------------------------------------------------------
    let mut cap = [0u8; CAPABILITY_SIZE];
    if ioctl(fd, VIDIOC_QUERYCAP, &mut cap) < 0 { return fail_errno("querycap"); }
    let driver = name(&cap, 0, 16);
    let card = name(&cap, 16, 32);
    let bus = name(&cap, 48, 32);
    let caps = r32(&cap, 84);
    let device_caps = r32(&cap, 88);
    line(&format!("{PROBE}: driver={driver} card={card} bus={bus} caps={caps:#x} device_caps={device_caps:#x}"));
    if caps & V4L2_CAP_DEVICE_CAPS == 0 { return fail("querycap-no-device-caps-marker"); }
    if device_caps & V4L2_CAP_VIDEO_CAPTURE == 0 { return fail("querycap-not-a-capture-device"); }
    if device_caps & V4L2_CAP_STREAMING == 0 { return fail("querycap-not-streaming"); }

    // --- what it can produce --------------------------------------------
    let mut formats = 0u32;
    loop {
        let mut d = [0u8; FMTDESC_SIZE];
        w32(&mut d, 0, formats);
        w32(&mut d, 4, V4L2_BUF_TYPE_VIDEO_CAPTURE);
        if ioctl(fd, VIDIOC_ENUM_FMT, &mut d) < 0 { break; }
        line(&format!("{PROBE}: format[{}] fourcc={} desc={}",
                      formats, fourcc(r32(&d, 44)), name(&d, 12, 32)));
        formats += 1;
        if formats > 32 { return fail("enum_fmt-does-not-terminate"); }
    }
    if formats == 0 { return fail("enum_fmt-reports-nothing"); }

    let mut inputs = 0u32;
    loop {
        let mut i = [0u8; INPUT_SIZE];
        w32(&mut i, 0, inputs);
        if ioctl(fd, VIDIOC_ENUMINPUT, &mut i) < 0 { break; }
        line(&format!("{PROBE}: input[{}] name={}", inputs, name(&i, 4, 32)));
        inputs += 1;
        if inputs > 32 { return fail("enuminput-does-not-terminate"); }
    }
    if inputs == 0 { return fail("enuminput-reports-nothing"); }

    // --- controls --------------------------------------------------------
    let mut controls = 0u32;
    let mut id = 0u32;
    loop {
        let mut q = [0u8; QUERYCTRL_SIZE];
        w32(&mut q, 0, id | V4L2_CTRL_FLAG_NEXT_CTRL);
        if ioctl(fd, VIDIOC_QUERYCTRL, &mut q) < 0 { break; }
        id = r32(&q, 0);
        controls += 1;
        if controls > 128 { return fail("queryctrl-walk-does-not-terminate"); }
    }
    if controls == 0 { return fail("queryctrl-reports-nothing"); }
    line(&format!("{PROBE}: controls={controls}"));

    let mut c = [0u8; CONTROL_SIZE];
    w32(&mut c, 0, V4L2_CID_BRIGHTNESS);
    if ioctl(fd, VIDIOC_G_CTRL, &mut c) < 0 { return fail_errno("g_ctrl-brightness"); }
    let before = r32(&c, 4);
    w32(&mut c, 4, before.wrapping_add(7));
    if ioctl(fd, VIDIOC_S_CTRL, &mut c) < 0 { return fail_errno("s_ctrl-brightness"); }
    let mut back = [0u8; CONTROL_SIZE];
    w32(&mut back, 0, V4L2_CID_BRIGHTNESS);
    if ioctl(fd, VIDIOC_G_CTRL, &mut back) < 0 { return fail_errno("g_ctrl-brightness-readback"); }
    let after = r32(&back, 4);
    line(&format!("{PROBE}: brightness {before} -> {after}"));
    if after == before { return fail("s_ctrl-did-not-take"); }

    // --- format ----------------------------------------------------------
    line(&format!("{PROBE}: step=g_fmt"));
    let mut fmt = [0u8; FORMAT_SIZE];
    w32(&mut fmt, 0, V4L2_BUF_TYPE_VIDEO_CAPTURE);
    if ioctl(fd, VIDIOC_G_FMT, &mut fmt) < 0 { return fail_errno("g_fmt"); }
    // Ask for a size the device is unlikely to offer exactly, so the answer
    // proves the negotiation ran rather than echoing the request back.
    w32(&mut fmt, 8, 700);
    w32(&mut fmt, 12, 500);
    if ioctl(fd, VIDIOC_S_FMT, &mut fmt) < 0 { return fail_errno("s_fmt"); }
    let (w, h) = (r32(&fmt, 8), r32(&fmt, 12));
    let pixfmt = r32(&fmt, 16);
    let bytesperline = r32(&fmt, 24);
    let sizeimage = r32(&fmt, 28) as usize;
    line(&format!("{PROBE}: negotiated {w}x{h} {} bytesperline={bytesperline} sizeimage={sizeimage}",
                  fourcc(pixfmt)));
    if (w, h) == (700, 500) { return fail("s_fmt-echoed-an-unsupported-size"); }
    if sizeimage == 0 { return fail("s_fmt-gave-no-image-size"); }
    if bytesperline as usize * h as usize != sizeimage {
        return fail("s_fmt-size-is-not-stride-times-height");
    }

    // --- buffers ---------------------------------------------------------
    // Each step announces itself before the call it is about to make. A probe
    // that only reports completed steps cannot distinguish a command that
    // wedged from one whose result line never reached the console, and this
    // gate has already had to tell those two apart once.
    line(&format!("{PROBE}: step=reqbufs want={WANT_BUFFERS}"));
    let mut req = [0u8; REQUESTBUFFERS_SIZE];
    w32(&mut req, 0, WANT_BUFFERS);
    w32(&mut req, 4, V4L2_BUF_TYPE_VIDEO_CAPTURE);
    w32(&mut req, 8, V4L2_MEMORY_MMAP);
    if ioctl(fd, VIDIOC_REQBUFS, &mut req) < 0 { return fail_errno("reqbufs"); }
    let count = r32(&req, 0);
    line(&format!("{PROBE}: reqbufs count={count} capabilities={:#x}", r32(&req, 12)));
    if count == 0 { return fail("reqbufs-allocated-nothing"); }

    let mut maps: Vec<Mapped> = Vec::new();
    for index in 0..count {
        let mut b = [0u8; BUFFER_SIZE];
        w32(&mut b, 0, index);
        w32(&mut b, 4, V4L2_BUF_TYPE_VIDEO_CAPTURE);
        w32(&mut b, 60, V4L2_MEMORY_MMAP);
        if ioctl(fd, VIDIOC_QUERYBUF, &mut b) < 0 { return fail_errno("querybuf"); }
        let offset = r64(&b, 64);
        let length = r32(&b, 72) as usize;
        if length < sizeimage { return fail("querybuf-buffer-smaller-than-the-image"); }
        line(&format!("{PROBE}: step=mmap index={index} offset={offset:#x} length={length}"));
        // SAFETY: a shared read-only mapping of `length` bytes at the cookie
        // the device just reported; the mapping outlives every read below.
        let addr = unsafe {
            libc::mmap(core::ptr::null_mut(), length, libc::PROT_READ, libc::MAP_SHARED,
                       fd, offset as libc::off_t)
        };
        if addr == libc::MAP_FAILED { return fail_errno("mmap"); }
        maps.push(Mapped { addr, len: length });
        if ioctl(fd, VIDIOC_QBUF, &mut b) < 0 { return fail_errno("qbuf"); }
    }
    line(&format!("{PROBE}: mapped and queued {count} buffers"));

    // --- stream ----------------------------------------------------------
    line(&format!("{PROBE}: step=streamon"));
    if ioctl_int(fd, VIDIOC_STREAMON, V4L2_BUF_TYPE_VIDEO_CAPTURE as i32) < 0 {
        return fail_errno("streamon");
    }
    let mut last_sequence: Option<u32> = None;
    for _ in 0..FRAMES {
        let mut d = [0u8; BUFFER_SIZE];
        w32(&mut d, 4, V4L2_BUF_TYPE_VIDEO_CAPTURE);
        w32(&mut d, 60, V4L2_MEMORY_MMAP);
        line(&format!("{PROBE}: step=dqbuf"));
        if ioctl(fd, VIDIOC_DQBUF, &mut d) < 0 { return fail_errno("dqbuf"); }
        let index = r32(&d, 0) as usize;
        let bytesused = r32(&d, 8);
        let flags = r32(&d, 12);
        let sequence = r32(&d, 56);
        let seconds = r64(&d, 24);
        let micros = r64(&d, 32);
        let Some(map) = maps.get(index) else {
            return fail("dqbuf-returned-an-index-outside-the-pool");
        };
        let nonzero = map.any_nonzero(sizeimage);
        line(&format!("{PROBE}: frame index={index} bytesused={bytesused} seq={sequence} \
flags={flags:#x} ts={seconds}.{micros:06} head={} nonzero={nonzero}", map.head()));
        if flags & V4L2_BUF_FLAG_DONE == 0 { return fail("dqbuf-buffer-lacks-the-done-flag"); }
        if flags & V4L2_BUF_FLAG_ERROR != 0 { return fail("dqbuf-buffer-carries-the-error-flag"); }
        if bytesused as usize != sizeimage { return fail("dqbuf-payload-is-not-a-whole-frame"); }
        if seconds == 0 && micros == 0 { return fail("dqbuf-frame-has-no-timestamp"); }
        if !nonzero { return fail("dqbuf-frame-is-entirely-zero"); }
        if let Some(previous) = last_sequence {
            if sequence <= previous { return fail("dqbuf-sequence-did-not-advance"); }
        }
        last_sequence = Some(sequence);
        if ioctl(fd, VIDIOC_QBUF, &mut d) < 0 { return fail_errno("requeue"); }
    }
    if ioctl_int(fd, VIDIOC_STREAMOFF, V4L2_BUF_TYPE_VIDEO_CAPTURE as i32) < 0 {
        return fail_errno("streamoff");
    }

    Verdict::Pass(format!("{FRAMES} frames of {w}x{h} {} from {card}", fourcc(pixfmt)))
}

/// A four-character code as the four characters it packs. # C: O(1)
fn fourcc(v: u32) -> String {
    v.to_le_bytes().iter().map(|b| *b as char).collect()
}
