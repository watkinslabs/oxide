//! `/bin/drm_probe` — DRM/KMS modeset-info regression.
//!
//! Proves the kernel's DRM primary/render nodes are Linux-shaped and the card
//! node returns REAL CRTC/connector/encoder objects built from the virtio-gpu
//! display info, not counts-only + EINVAL. Opens `/dev/dri/card0`, then:
//!   1. `MODE_GETRESOURCES` two-pass (learn counts, alloc, fetch ids) -> assert
//!      at least one crtc / connector / encoder.
//!   2. `MODE_GETCONNECTOR` two-pass for the mode list -> assert connected and
//!      at least one mode with sane width/height.
//!   3. `MODE_GETCRTC` + `MODE_GETENCODER` on the first ids -> assert no error.
//!
//! The render node is checked FIRST and must REFUSE the KMS ioctl with EACCES:
//! a render node that answers modeset calls is the interesting bug, and it would
//! otherwise be masked by the card node succeeding.

use std::os::fd::AsRawFd;
use support::{Verdict, fail, fail_errno, report};

mod uapi;

const PROBE: &str = "drm_probe";
const CARD_NODE: &str = "/dev/dri/card0";
const RENDER_NODE: &str = "/dev/dri/renderD128";
/// Sanity ceiling on a reported object count. Buffers are sized from the count
/// the kernel reports, NOT from this — a fixed-size buffer is what made this
/// probe silently unable to pass: Linux fills a counted array only when the
/// caller's buffer holds the WHOLE list (`drm_connector.c`, `count_modes >=
/// mode_count`), so asking for 16 slots against 19 modes returns zeros, not a
/// short read. This bound only catches a counts-pass returning garbage.
const MAX_OBJECTS: usize = 1024;
/// Sanity window for a reported mode, in pixels.
const MIN_DIMENSION: u32 = 1;
const MAX_DIMENSION: u32 = 8192;

fn main() -> std::process::ExitCode { report(PROBE, run()) }

fn run() -> Verdict {
    if let Some(f) = render_node_refuses_kms() { return f; }

    let card = match std::fs::OpenOptions::new().read(true).write(true).open(CARD_NODE) {
        Ok(f) => f,
        Err(_) => return fail_errno("open /dev/dri/card0"),
    };

    let mut res = uapi::CardRes::default();
    if ioctl(&card, uapi::DRM_IOCTL_MODE_GETRESOURCES, &mut res) < 0 {
        return fail_errno("GETRESOURCES pass1");
    }
    if res.count_crtcs < 1 || res.count_connectors < 1 || res.count_encoders < 1 {
        return fail("no crtc/connector/encoder");
    }
    if res.count_crtcs as usize > MAX_OBJECTS
        || res.count_connectors as usize > MAX_OBJECTS
        || res.count_encoders as usize > MAX_OBJECTS {
        return fail("too many objects");
    }

    // Size every buffer to what pass 1 reported.
    let mut crtcs = vec![0u32; res.count_crtcs as usize];
    let mut conns = vec![0u32; res.count_connectors as usize];
    let mut encs = vec![0u32; res.count_encoders as usize];
    res.crtc_id_ptr = crtcs.as_mut_ptr() as u64;
    res.connector_id_ptr = conns.as_mut_ptr() as u64;
    res.encoder_id_ptr = encs.as_mut_ptr() as u64;
    if ioctl(&card, uapi::DRM_IOCTL_MODE_GETRESOURCES, &mut res) < 0 {
        return fail_errno("GETRESOURCES pass2");
    }

    let mut conn = uapi::GetConnector { connector_id: conns[0], ..Default::default() };
    if ioctl(&card, uapi::DRM_IOCTL_MODE_GETCONNECTOR, &mut conn) < 0 {
        return fail_errno("GETCONNECTOR pass1");
    }
    if conn.connection != uapi::DRM_MODE_CONNECTED { return fail("connector not connected"); }
    if conn.count_modes < 1 { return fail("no modes"); }
    let advertised = conn.count_modes;

    if advertised as usize > MAX_OBJECTS { return fail(&format!("absurd mode count {advertised}")); }
    let mut modes = vec![uapi::ModeInfo::default(); advertised as usize];
    let mut conn = uapi::GetConnector {
        connector_id: conns[0],
        count_modes: advertised,
        modes_ptr: modes.as_mut_ptr() as u64,
        ..Default::default()
    };
    if ioctl(&card, uapi::DRM_IOCTL_MODE_GETCONNECTOR, &mut conn) < 0 {
        return fail_errno("GETCONNECTOR pass2");
    }
    let (w, h) = (modes[0].hdisplay as u32, modes[0].vdisplay as u32);
    if !(MIN_DIMENSION..=MAX_DIMENSION).contains(&w) || !(MIN_DIMENSION..=MAX_DIMENSION).contains(&h) {
        // Name what the kernel claimed vs what it wrote: a count-only answer and
        // a genuinely blank mode are different bugs and used to look identical.
        let name = modes[0].name.split(|b| *b == 0).next().unwrap_or(&[]);
        return fail(&format!("insane mode dims {w}x{h} advertised={advertised} returned={} clock={} name={}",
            conn.count_modes, modes[0].clock, String::from_utf8_lossy(name)));
    }

    let mut crtc = uapi::Crtc { crtc_id: crtcs[0], ..Default::default() };
    if ioctl(&card, uapi::DRM_IOCTL_MODE_GETCRTC, &mut crtc) < 0 { return fail_errno("GETCRTC"); }

    let mut enc = uapi::GetEncoder { encoder_id: encs[0], ..Default::default() };
    if ioctl(&card, uapi::DRM_IOCTL_MODE_GETENCODER, &mut enc) < 0 { return fail_errno("GETENCODER"); }

    Verdict::Pass(format!("res={w}x{h} crtcs={} conns={} modes={advertised}", res.count_crtcs, res.count_connectors))
}

/// `Some(failure)` if the render node accepted a KMS ioctl, or refused it with
/// anything other than EACCES. # C: O(1)
fn render_node_refuses_kms() -> Option<Verdict> {
    let render = match std::fs::OpenOptions::new().read(true).write(true).open(RENDER_NODE) {
        Ok(f) => f,
        Err(_) => return Some(fail_errno("open /dev/dri/renderD128")),
    };
    let mut res = uapi::CardRes::default();
    let rc = ioctl(&render, uapi::DRM_IOCTL_MODE_GETRESOURCES, &mut res);
    if rc >= 0 { return Some(fail("render node allowed KMS ioctl")); }
    if support::errno() != libc::EACCES {
        return Some(fail_errno("render node refused KMS ioctl with the wrong error"));
    }
    None
}

/// One `ioctl(2)` against an owned fd with a mutable UAPI struct. # C: O(1)
fn ioctl<T>(file: &std::fs::File, request: libc::c_ulong, arg: &mut T) -> libc::c_int {
    // SAFETY: `file` owns the descriptor for the duration of the call, `request`
    // encodes `size_of::<T>()` so the kernel reads and writes exactly the object
    // `arg` points at, and `arg` is a live unique borrow of that object.
    unsafe { libc::ioctl(file.as_raw_fd(), request as _, arg as *mut T) }
}
