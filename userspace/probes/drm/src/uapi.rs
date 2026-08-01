//! DRM mode-setting UAPI. Struct layouts and ioctl encodings only — no policy.
//!
//! `libdrm` is not linked, so the structs are declared here and must match
//! `include/uapi/drm/drm_mode.h` field for field: the kernel reads them by
//! offset, and a mismatch silently corrupts the two-pass count/fetch protocol
//! rather than failing loudly.

/// DRM ioctl type byte — `'d'`.
const DRM_IOCTL_BASE: u32 = 0x64;

// `_IOC` direction bits.
const IOC_WRITE: u32 = 1;
const IOC_READ: u32 = 2;
const IOC_NRSHIFT: u32 = 0;
const IOC_TYPESHIFT: u32 = 8;
const IOC_SIZESHIFT: u32 = 16;
const IOC_DIRSHIFT: u32 = 30;

/// `_IOWR(type, nr, T)`. # C: O(1)
const fn iowr<T>(nr: u32) -> libc::c_ulong {
    let dir = IOC_READ | IOC_WRITE;
    (((dir) << IOC_DIRSHIFT)
        | ((size_of::<T>() as u32) << IOC_SIZESHIFT)
        | ((DRM_IOCTL_BASE) << IOC_TYPESHIFT)
        | ((nr) << IOC_NRSHIFT)) as libc::c_ulong
}

const NR_MODE_GETRESOURCES: u32 = 0xa0;
const NR_MODE_GETCRTC: u32 = 0xa1;
const NR_MODE_GETENCODER: u32 = 0xa6;
const NR_MODE_GETCONNECTOR: u32 = 0xa7;

pub(crate) const DRM_IOCTL_MODE_GETRESOURCES: libc::c_ulong = iowr::<CardRes>(NR_MODE_GETRESOURCES);
pub(crate) const DRM_IOCTL_MODE_GETCRTC: libc::c_ulong = iowr::<Crtc>(NR_MODE_GETCRTC);
pub(crate) const DRM_IOCTL_MODE_GETENCODER: libc::c_ulong = iowr::<GetEncoder>(NR_MODE_GETENCODER);
pub(crate) const DRM_IOCTL_MODE_GETCONNECTOR: libc::c_ulong = iowr::<GetConnector>(NR_MODE_GETCONNECTOR);

/// `connection` value meaning a display is attached.
pub(crate) const DRM_MODE_CONNECTED: u32 = 1;

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct CardRes {
    pub fb_id_ptr: u64,
    pub crtc_id_ptr: u64,
    pub connector_id_ptr: u64,
    pub encoder_id_ptr: u64,
    pub count_fbs: u32,
    pub count_crtcs: u32,
    pub count_connectors: u32,
    pub count_encoders: u32,
    pub min_width: u32,
    pub max_width: u32,
    pub min_height: u32,
    pub max_height: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct ModeInfo {
    pub clock: u32,
    pub hdisplay: u16,
    pub hsync_start: u16,
    pub hsync_end: u16,
    pub htotal: u16,
    pub hskew: u16,
    pub vdisplay: u16,
    pub vsync_start: u16,
    pub vsync_end: u16,
    pub vtotal: u16,
    pub vscan: u16,
    pub vrefresh: u32,
    pub flags: u32,
    pub kind: u32,
    pub name: [u8; 32],
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct Crtc {
    pub set_connectors_ptr: u64,
    pub count_connectors: u32,
    pub crtc_id: u32,
    pub fb_id: u32,
    pub x: u32,
    pub y: u32,
    pub gamma_size: u32,
    pub mode_valid: u32,
    pub mode: ModeInfo,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct GetEncoder {
    pub encoder_id: u32,
    pub encoder_type: u32,
    pub crtc_id: u32,
    pub possible_crtcs: u32,
    pub possible_clones: u32,
}

#[repr(C)]
#[derive(Default, Clone, Copy)]
pub(crate) struct GetConnector {
    pub encoders_ptr: u64,
    pub modes_ptr: u64,
    pub props_ptr: u64,
    pub prop_values_ptr: u64,
    pub count_modes: u32,
    pub count_props: u32,
    pub count_encoders: u32,
    pub encoder_id: u32,
    pub connector_id: u32,
    pub connector_type: u32,
    pub connector_type_id: u32,
    pub connection: u32,
    pub mm_width: u32,
    pub mm_height: u32,
    pub subpixel: u32,
    pub pad: u32,
}

// Layout proofs as CONST assertions, not `#[test]`: `cargo test` runs on the host
// only, so a `#[test]` would leave the aarch64 build unproven. These are
// evaluated by every build of every target, and verified against the installed
// libdrm/kernel UAPI headers (`sizeof` + the `_IOWR` expansions) rather than
// transcribed from memory.
//
// The kernel reads these by offset. A reordered or repacked field would not fail
// the ioctl — it would hand back the wrong words. And the size travels INSIDE the
// ioctl number, so a struct-size drift changes the request itself.
const _: () = assert!(size_of::<CardRes>() == 64);
const _: () = assert!(size_of::<ModeInfo>() == 68);
const _: () = assert!(size_of::<Crtc>() == 104);
const _: () = assert!(size_of::<GetEncoder>() == 20);
const _: () = assert!(size_of::<GetConnector>() == 80);
const _: () = assert!(DRM_IOCTL_MODE_GETRESOURCES == 0xc040_64a0);
const _: () = assert!(DRM_IOCTL_MODE_GETCRTC == 0xc068_64a1);
const _: () = assert!(DRM_IOCTL_MODE_GETENCODER == 0xc014_64a6);
const _: () = assert!(DRM_IOCTL_MODE_GETCONNECTOR == 0xc050_64a7);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mode_dimensions_are_the_16_bit_fields_the_kernel_fills() {
        let mut mode = ModeInfo::default();
        mode.hdisplay = u16::MAX;
        mode.vdisplay = 1;
        assert_eq!(mode.hdisplay as u32, 65535);
        assert_eq!(mode.vdisplay as u32, 1);
    }
}
