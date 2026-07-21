use crate::uapi::{
    DrmModeModeinfo, DRM_MODE_FLAG_PHSYNC, DRM_MODE_FLAG_PVSYNC, DRM_MODE_TYPE_DRIVER,
    DRM_MODE_TYPE_PREFERRED,
};
use alloc::vec::Vec;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Error {
    Inval,
    NoMem,
    Busy,
    NoSpc,
    OpNotSupp,
    Perm,
    NoEnt,
}

pub type KResult<T> = core::result::Result<T, Error>;

#[derive(Copy, Clone, Debug)]
pub struct ConnectorInfo {
    pub connection: u32,
    pub connector_type: u32,
    pub encoder_id: u32,
    pub mm_width: u32,
    pub mm_height: u32,
    pub mode_count: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct CrtcInfo {
    pub mode_valid: u32,
    pub fb_id: u32,
    pub x: u32,
    pub y: u32,
    pub gamma_size: u32,
    pub mode: DrmModeModeinfo,
}

#[derive(Copy, Clone, Debug)]
pub struct EncoderInfo {
    pub encoder_type: u32,
    pub crtc_id: u32,
    pub possible_crtcs: u32,
    pub possible_clones: u32,
}

#[derive(Copy, Clone, Debug)]
pub struct PlaneInfo {
    pub crtc_id: u32,
    pub fb_id: u32,
    pub possible_crtcs: u32,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum VirtgpuCaps { NoCapsets }

pub trait DrmDriver: Send + Sync {
    fn name(&self) -> &'static str;
    fn version(&self) -> (u32, u32, u32);
    fn date(&self) -> &'static str;
    fn desc(&self) -> &'static str;
    fn unique(&self) -> &str;
    fn resource_counts(&self) -> (u32, u32, u32, u32);
    fn dim_bounds(&self) -> (u32, u32, u32, u32);
    fn cap(&self, cap: u64) -> u64;

    /// VIRTGPU_GETPARAM: `Some(value)` if this is a virtio-gpu driver answering
    /// `param`; `None` → not a virtgpu driver (caller returns ENOTTY, matching
    /// Linux where non-virtgpu cards lack the ioctl). # C: O(1)
    fn virtgpu_getparam(&self, _param: u64) -> Option<u64> { None }

    /// VIRTGPU_GET_CAPS. `None` means this is not a virtio-gpu driver; the
    /// caller returns ENOTTY just as DRM core does for an unregistered ioctl.
    /// # C: O(1)
    fn virtgpu_get_caps(&self, _arg: u64) -> Option<VirtgpuCaps> { None }

    fn crtc_ids(&self) -> Vec<u32> { Vec::new() }
    fn connector_ids(&self) -> Vec<u32> { Vec::new() }
    fn encoder_ids(&self) -> Vec<u32> { Vec::new() }
    fn plane_ids(&self) -> Vec<u32> { Vec::new() }
    fn mode_for(&self, _idx: usize) -> DrmModeModeinfo { DrmModeModeinfo::default() }
    fn connector_info(&self, _idx: usize) -> Option<ConnectorInfo> { None }
    fn crtc_info(&self, _idx: usize) -> Option<CrtcInfo> { None }
    fn encoder_info(&self, _idx: usize) -> Option<EncoderInfo> { None }
    fn plane_info(&self, _idx: usize) -> Option<PlaneInfo> { None }
}

pub fn mode_from_rect(w: u32, h: u32) -> DrmModeModeinfo {
    let w16 = w as u16;
    let h16 = h as u16;
    let hsync_start = w16.saturating_add(w16 / 20);
    let hsync_end = w16.saturating_add(w16 / 10);
    let htotal = w16.saturating_add(w16 / 4);
    let vsync_start = h16.saturating_add(3);
    let vsync_end = h16.saturating_add(9);
    let vtotal = h16.saturating_add(h16 / 40).saturating_add(20);
    let clock = ((htotal as u64) * (vtotal as u64) * 60 / 1000) as u32;
    let mut name = [0u8; 32];
    write_mode_name(&mut name, w, h);
    DrmModeModeinfo {
        clock,
        hdisplay: w16, hsync_start, hsync_end, htotal, hskew: 0,
        vdisplay: h16, vsync_start, vsync_end, vtotal, vscan: 0,
        vrefresh: 60,
        flags: DRM_MODE_FLAG_PHSYNC | DRM_MODE_FLAG_PVSYNC,
        ty: DRM_MODE_TYPE_DRIVER | DRM_MODE_TYPE_PREFERRED,
        name,
    }
}

fn write_mode_name(out: &mut [u8; 32], w: u32, h: u32) {
    let mut p = 0usize;
    p += write_dec(&mut out[p..], w);
    if p < 31 {
        out[p] = b'x';
        p += 1;
    }
    let _ = write_dec(&mut out[p..], h);
}

fn write_dec(out: &mut [u8], mut v: u32) -> usize {
    let mut tmp = [0u8; 10];
    let mut n = 0;
    if v == 0 {
        tmp[n] = b'0';
        n += 1;
    }
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut w = 0;
    while w < n && w < out.len() {
        out[w] = tmp[n - 1 - w];
        w += 1;
    }
    w
}
