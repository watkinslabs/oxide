/// `struct drm_mode_create_dumb` — 32 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeCreateDumb {
    pub height: u32,
    pub width:  u32,
    pub bpp:    u32,
    pub flags:  u32,
    pub handle: u32,
    pub pitch:  u32,
    pub size:   u64,
}

/// `struct drm_mode_map_dumb` — 16 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeMapDumb {
    pub handle: u32,
    pub pad:    u32,
    pub offset: u64,
}

/// `struct drm_mode_destroy_dumb` — 4 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeDestroyDumb {
    pub handle: u32,
}

/// `struct drm_mode_fb_cmd2` — 104 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeFbCmd2 {
    pub fb_id:        u32,
    pub width:        u32,
    pub height:       u32,
    pub pixel_format: u32,
    pub flags:        u32,
    pub handles:      [u32; 4],
    pub pitches:      [u32; 4],
    pub offsets:      [u32; 4],
    pub modifier:     [u64; 4],
}

/// `struct drm_mode_fb_cmd` (legacy ADDFB) — 28 bytes. # C: ABI
#[repr(C)]
#[derive(Copy, Clone, Default, Debug)]
pub struct DrmModeFbCmd {
    pub fb_id:  u32,
    pub width:  u32,
    pub height: u32,
    pub pitch:  u32,
    pub bpp:    u32,
    pub depth:  u32,
    pub handle: u32,
}
