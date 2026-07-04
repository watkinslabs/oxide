pub const DRM_CRTC_ID_BASE: u32 = 1;
pub const DRM_CONNECTOR_ID_BASE: u32 = 0x100;
pub const DRM_ENCODER_ID_BASE: u32 = 0x200;
pub const DRM_PLANE_ID_BASE: u32 = 0x300;
pub const DRM_PLANE_ID_END: u32 = 0x400;

pub const fn crtc_id_for(i: usize) -> u32 { DRM_CRTC_ID_BASE + i as u32 }
pub const fn connector_id_for(i: usize) -> u32 { DRM_CONNECTOR_ID_BASE + i as u32 }
pub const fn encoder_id_for(i: usize) -> u32 { DRM_ENCODER_ID_BASE + i as u32 }
pub const fn plane_id_for(i: usize) -> u32 { DRM_PLANE_ID_BASE + i as u32 }

pub fn crtc_idx_of(id: u32, count: usize) -> Option<usize> {
    if id == 0 { return None; }
    let i = (id - 1) as usize;
    if i < count { Some(i) } else { None }
}

pub fn connector_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < DRM_CONNECTOR_ID_BASE { return None; }
    let i = (id - DRM_CONNECTOR_ID_BASE) as usize;
    if i < count { Some(i) } else { None }
}

pub fn encoder_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < DRM_ENCODER_ID_BASE || id >= DRM_PLANE_ID_BASE { return None; }
    let i = (id - DRM_ENCODER_ID_BASE) as usize;
    if i < count { Some(i) } else { None }
}

pub fn plane_idx_of(id: u32, count: usize) -> Option<usize> {
    if id < DRM_PLANE_ID_BASE || id >= DRM_PLANE_ID_END { return None; }
    let i = (id - DRM_PLANE_ID_BASE) as usize;
    if i < count { Some(i) } else { None }
}
