// DRM/KMS card nodes per `47`. /dev/dri/cardN dispatches ioctls through the
// stable DrmDriver slot in the drm crate. Render nodes are intentionally not
// published until a real render/GEM UAPI exists behind them.
//
// Module manifest:
// - `auth`: per-file magic, master ownership, client capability, user-copy helpers.
// - `publication`: `/dev/dri/cardN` inode/file ops and model/devtmpfs publication.
// - `scanout`: runtime scanout backend hook table installed by GPU drivers.
// - `uapi`: local DRM ioctl wire structs and interface constants.
// - `tests`: node publication, auth, and ioctl contract tests.

#![allow(dead_code)]

mod auth;
mod publication;
mod scanout;
mod uapi;

#[cfg(test)]
mod tests;

pub use publication::{register, unregister};
#[cfg(test)]
pub use publication::{registered_card_ids, unregister_all};
pub use scanout::{clear_scanout_ops, scanout_ops, set_scanout_ops, ScanoutOps};

use auth::{
    atomic_property_count, authorize_magic, client_cap_atomic, copy_bytes_to_user,
    drop_master_owner, file_magic, file_token, ioctl_takes_user_ptr, is_master, set_master_owner,
    valid_user_range,
};
use publication::{drm_inode_parts, DRM_CARD_INO, DRM_RENDER_INO};
use uapi::{
    DrmModeAtomic, DrmSetVersion, DrmUnique, DrmVersion, DRM_IF_MAJOR, DRM_IF_MINOR,
    DRM_MODE_ATOMIC_SUPPORTED_FLAGS, FALLBACK_DATE, FALLBACK_DESC, FALLBACK_NAME, FALLBACK_UNIQUE,
};

use crate::{
    DRM_IOCTL_VERSION, DRM_IOCTL_GET_CAP, DRM_IOCTL_GET_UNIQUE,
    DRM_IOCTL_SET_VERSION, DRM_IOCTL_MODE_GETRESOURCES,
    DRM_IOCTL_MODE_ATOMIC,
    DRM_IOCTL_SET_CLIENT_CAP, DRM_IOCTL_SET_MASTER, DRM_IOCTL_DROP_MASTER,
    DRM_IOCTL_AUTH_MAGIC, DRM_IOCTL_GET_MAGIC,
    DRM_IOCTL_MODE_GETPLANERESOURCES, DRM_IOCTL_MODE_GETPLANE,
    DRM_IOCTL_MODE_GETCRTC, DRM_IOCTL_MODE_GETENCODER,
    DRM_IOCTL_MODE_GETCONNECTOR,
    DRM_IOCTL_MODE_CREATE_DUMB, DRM_IOCTL_MODE_MAP_DUMB,
    DRM_IOCTL_MODE_DESTROY_DUMB, DRM_IOCTL_MODE_ADDFB2,
    DRM_IOCTL_MODE_ADDFB, DRM_IOCTL_MODE_RMFB,
    DRM_IOCTL_MODE_SETCRTC, DRM_IOCTL_MODE_PAGE_FLIP,
};

use vfs::File;

/// mmap backing for a DRM card inode (offset-keyed). Legacy raw lookup used
/// by tests/diagnostics; production mmap should prefer `pin_mmap_backing` so
/// VMA lifetime pins the dumb buffer. # C: O(n)
pub fn mmap_backing(inode: &vfs::InodeRef, offset: u64) -> Option<(u64, u64)> {
    let Some((DRM_CARD_INO, card_id)) = drm_inode_parts(inode) else { return None; };
    crate::dumb::mmap_backing(card_id, offset)
}

/// Pin a DRM dumb buffer for a userspace VMA. The returned pin owns a mmap ref
/// until `dumb::unpin_mmap` is called by the VMA backing's Drop path. # C: O(n)
pub fn pin_mmap_backing(inode: &vfs::InodeRef, offset: u64) -> Option<crate::dumb::DumbMmapPin> {
    let Some((DRM_CARD_INO, card_id)) = drm_inode_parts(inode) else { return None; };
    crate::dumb::pin_mmap(card_id, offset)
}

/// ioctl on a DRM fd. Returns Some(rv) when handled; None otherwise (caller
/// falls back to the generic CharDev path).
/// # C: O(1)
pub fn handle_drm_ioctl(file: &File, req: u64, arg: u64) -> Option<i64> {
    let inode = file.inode();
    let (tag, card_id) = drm_inode_parts(inode)?;
    use syscall::errno::Errno;
    if tag == DRM_RENDER_INO && crate::is_master_only(req) {
        return Some(-(Errno::Eacces.as_i32() as i64));
    }
    if ioctl_takes_user_ptr(req) && (arg == 0 || arg >= hal::USER_VA_END) {
        return Some(-(Errno::Efault.as_i32() as i64));
    }
    let token = file_token(file);
    let driver = crate::card(card_id);
    match req {
        DRM_IOCTL_VERSION => {
            let (name, date, desc, ver) = match driver.as_ref() {
                Some(d) => (d.name(), d.date(), d.desc(), d.version()),
                None    => (FALLBACK_NAME, FALLBACK_DATE, FALLBACK_DESC, (1, 6, 0)),
            };
            // SAFETY: arg validated < USER_VA_END; struct drm_version is 88 bytes.
            let mut v: DrmVersion = unsafe { core::ptr::read_volatile(arg as *const DrmVersion) };
            v.version_major     = ver.0 as i32;
            v.version_minor     = ver.1 as i32;
            v.version_patchlevel = ver.2 as i32;
            // SAFETY: each user pointer + len validated < USER_VA_END before write; CPL=0 writes through caller's AS.
            unsafe {
                if v.name != 0 && v.name < hal::USER_VA_END && v.name_len > 0 {
                    let n = (v.name_len as usize).min(name.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.name + i as u64) as *mut u8, name.as_bytes()[i]);
                    }
                }
                if v.date != 0 && v.date < hal::USER_VA_END && v.date_len > 0 {
                    let n = (v.date_len as usize).min(date.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.date + i as u64) as *mut u8, date.as_bytes()[i]);
                    }
                }
                if v.desc != 0 && v.desc < hal::USER_VA_END && v.desc_len > 0 {
                    let n = (v.desc_len as usize).min(desc.len());
                    for i in 0..n {
                        core::ptr::write_volatile((v.desc + i as u64) as *mut u8, desc.as_bytes()[i]);
                    }
                }
            }
            v.name_len = name.len() as u64;
            v.date_len = date.len() as u64;
            v.desc_len = desc.len() as u64;
            // SAFETY: arg validated; struct drm_version is 88 bytes; CPL=0 writes through caller's AS.
            unsafe { core::ptr::write_volatile(arg as *mut DrmVersion, v); }
            Some(0)
        }
        DRM_IOCTL_GET_CAP => {
            // struct drm_get_cap { capability u64; value u64; }.
            // Delegate to driver.cap(); fall back to crate::default_cap.
            // SAFETY: arg validated < USER_VA_END; aligned u64 read of capability + write of value.
            let cap = unsafe { core::ptr::read_volatile(arg as *const u64) };
            let val = match driver.as_ref() {
                Some(d) => d.cap(cap),
                None    => crate::default_cap(cap),
            };
            // SAFETY: arg validated; cap struct is 16 bytes; value at +8.
            unsafe { core::ptr::write_volatile((arg + 8) as *mut u64, val); }
            Some(0)
        }
        DRM_IOCTL_GET_UNIQUE => {
            if !valid_user_range(arg, core::mem::size_of::<DrmUnique>() as u64) {
                return Some(-(Errno::Efault.as_i32() as i64));
            }
            let unique = match driver.as_ref() {
                Some(d) => d.unique(),
                None    => FALLBACK_UNIQUE,
            };
            // SAFETY: the full drm_unique user struct was validated above.
            let mut u: DrmUnique = unsafe { core::ptr::read_volatile(arg as *const DrmUnique) };
            if u.unique != 0 && u.unique_len > 0 {
                if copy_bytes_to_user(u.unique, u.unique_len, unique.as_bytes()).is_err() {
                    return Some(-(Errno::Efault.as_i32() as i64));
                }
            }
            u.unique_len = unique.len() as u64;
            // SAFETY: the full drm_unique user struct was validated above.
            unsafe { core::ptr::write_volatile(arg as *mut DrmUnique, u); }
            Some(0)
        }
        DRM_IOCTL_SET_VERSION => {
            if !valid_user_range(arg, core::mem::size_of::<DrmSetVersion>() as u64) {
                return Some(-(Errno::Efault.as_i32() as i64));
            }
            // SAFETY: the full drm_set_version user struct was validated above.
            let mut v: DrmSetVersion = unsafe { core::ptr::read_volatile(arg as *const DrmSetVersion) };
            if v.drm_di_major != DRM_IF_MAJOR || v.drm_di_minor > DRM_IF_MINOR {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            v.drm_di_major = DRM_IF_MAJOR;
            v.drm_di_minor = DRM_IF_MINOR;
            v.drm_dd_major = 0;
            v.drm_dd_minor = 0;
            // SAFETY: the full drm_set_version user struct was validated above.
            unsafe { core::ptr::write_volatile(arg as *mut DrmSetVersion, v); }
            Some(0)
        }
        DRM_IOCTL_MODE_GETRESOURCES => {
            // Real 2-pass enumeration when a card is registered;
            // empty counts (no objects) when none. drm_mode_card_res
            // is 64 B; validated < USER_VA_END above.
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_resources(d, arg)),
                None => {
                    // SAFETY: arg validated; struct ≥ 64 B; zero counts + dims.
                    unsafe {
                        for off in [32u64, 36, 40, 44, 48, 52, 56, 60] {
                            core::ptr::write_volatile((arg + off) as *mut u32, 0);
                        }
                    }
                    Some(0)
                }
            }
        }
        DRM_IOCTL_MODE_GETPLANERESOURCES => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_plane_res(d, arg)),
                None => {
                    // SAFETY: arg validated; field at +8 is the count u32.
                    unsafe { core::ptr::write_volatile((arg + 8) as *mut u32, 0); }
                    Some(0)
                }
            }
        }
        DRM_IOCTL_MODE_GETPLANE => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_plane(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETCRTC => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_crtc(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETENCODER => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_encoder(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_GETCONNECTOR => {
            match driver.as_ref() {
                Some(d) => Some(crate::modeset::get_connector(d, arg)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_SET_CLIENT_CAP => {
            if !valid_user_range(arg, 16) {
                return Some(-(Errno::Efault.as_i32() as i64));
            }
            // struct drm_set_client_cap { capability u64; value u64; }
            // SAFETY: arg..arg+16 was validated above.
            let capability = unsafe { core::ptr::read_volatile(arg as *const u64) };
            // SAFETY: same validated struct, second u64.
            let value = unsafe { core::ptr::read_volatile((arg + 8) as *const u64) };
            if value > 1 {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            let bit = match capability {
                crate::DRM_CLIENT_CAP_UNIVERSAL_PLANES => 1u64 << capability,
                crate::DRM_CLIENT_CAP_STEREO_3D
                | crate::DRM_CLIENT_CAP_ATOMIC
                | crate::DRM_CLIENT_CAP_ASPECT_RATIO
                | crate::DRM_CLIENT_CAP_WRITEBACK_CONNECTORS
                | crate::DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT if value == 0 => 1u64 << capability,
                crate::DRM_CLIENT_CAP_STEREO_3D
                | crate::DRM_CLIENT_CAP_ATOMIC
                | crate::DRM_CLIENT_CAP_ASPECT_RATIO
                | crate::DRM_CLIENT_CAP_WRITEBACK_CONNECTORS
                | crate::DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT => {
                    return Some(-(Errno::Eopnotsupp.as_i32() as i64));
                }
                _ => return Some(-(Errno::Einval.as_i32() as i64)),
            };
            let mut state = file.private_data();
            if value != 0 {
                state |= bit;
            } else {
                state &= !bit;
            }
            file.set_private_data(state);
            Some(0)
        }
        DRM_IOCTL_SET_MASTER => Some(set_master_owner(card_id, token)),
        DRM_IOCTL_DROP_MASTER => Some(drop_master_owner(card_id, token)),
        DRM_IOCTL_GET_MAGIC => {
            if !valid_user_range(arg, 4) {
                return Some(-(Errno::Efault.as_i32() as i64));
            }
            // SAFETY: arg..arg+4 was validated above; drm_auth is one u32.
            unsafe { core::ptr::write_volatile(arg as *mut u32, file_magic(file)); }
            Some(0)
        }
        DRM_IOCTL_AUTH_MAGIC => {
            if !valid_user_range(arg, 4) {
                return Some(-(Errno::Efault.as_i32() as i64));
            }
            if !is_master(card_id, token) {
                return Some(-(Errno::Eacces.as_i32() as i64));
            }
            // SAFETY: arg..arg+4 was validated above; drm_auth is one u32.
            let magic = unsafe { core::ptr::read_volatile(arg as *const u32) };
            authorize_magic(card_id, magic);
            Some(0)
        }
        DRM_IOCTL_MODE_ATOMIC => {
            if !valid_user_range(arg, core::mem::size_of::<DrmModeAtomic>() as u64) {
                return Some(-(Errno::Efault.as_i32() as i64));
            }
            if !is_master(card_id, token) || !client_cap_atomic(file) {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            // SAFETY: the full drm_mode_atomic user struct was validated above.
            let atomic: DrmModeAtomic = unsafe { core::ptr::read_volatile(arg as *const DrmModeAtomic) };
            if (atomic.flags & !DRM_MODE_ATOMIC_SUPPORTED_FLAGS) != 0 {
                return Some(-(Errno::Einval.as_i32() as i64));
            }
            if atomic.count_objs == 0 {
                return Some(0);
            }

            let obj_bytes = (atomic.count_objs as u64)
                .checked_mul(core::mem::size_of::<u32>() as u64)
                .filter(|bytes| valid_user_range(atomic.objs_ptr, *bytes));
            if obj_bytes.is_none() {
                return Some(-(Errno::Efault.as_i32() as i64));
            }
            let prop_count = match atomic_property_count(atomic.count_props_ptr, atomic.count_objs) {
                Ok(count) => count,
                Err(()) => return Some(-(Errno::Efault.as_i32() as i64)),
            };
            if prop_count > 0 {
                let prop_bytes = prop_count.checked_mul(core::mem::size_of::<u32>() as u64);
                let value_bytes = prop_count.checked_mul(core::mem::size_of::<u64>() as u64);
                if prop_bytes.is_none_or(|bytes| !valid_user_range(atomic.props_ptr, bytes))
                    || value_bytes.is_none_or(|bytes| !valid_user_range(atomic.prop_values_ptr, bytes))
                {
                    return Some(-(Errno::Efault.as_i32() as i64));
                }
            }
            Some(-(Errno::Eopnotsupp.as_i32() as i64))
        }
        // ---- D5b-1 dumb buffers + ADDFB2 (offscreen; no scanout) ----
        DRM_IOCTL_MODE_CREATE_DUMB  => Some(crate::dumb::create_dumb(card_id, arg)),
        DRM_IOCTL_MODE_MAP_DUMB     => Some(crate::dumb::map_dumb(card_id, arg)),
        DRM_IOCTL_MODE_DESTROY_DUMB => Some(crate::dumb::destroy_dumb(card_id, arg)),
        DRM_IOCTL_MODE_ADDFB2       => Some(crate::dumb::addfb2(card_id, arg)),
        DRM_IOCTL_MODE_ADDFB        => Some(crate::dumb::addfb(card_id, arg)),
        DRM_IOCTL_MODE_RMFB         => Some(crate::dumb::rmfb(card_id, arg)),
        // ---- D5b-2 SETCRTC / PAGE_FLIP (real scanout) ----
        // Token = the open file description, matching Linux's file-scoped
        // DRM master/KMS ownership. Card required (no GPU → set_crtc
        // honest-fails EINVAL).
        DRM_IOCTL_MODE_SETCRTC => {
            if !is_master(card_id, token) {
                return Some(-(Errno::Eacces.as_i32() as i64));
            }
            match driver.as_ref() {
                Some(d) => Some(crate::crtc::set_crtc(card_id, d, arg, token)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        DRM_IOCTL_MODE_PAGE_FLIP => {
            if !is_master(card_id, token) {
                return Some(-(Errno::Eacces.as_i32() as i64));
            }
            match driver.as_ref() {
                Some(d) => Some(crate::crtc::page_flip(card_id, d, arg, token)),
                None    => Some(-(Errno::Einval.as_i32() as i64)),
            }
        }
        _ => Some(-(Errno::Enotty.as_i32() as i64)),
    }
}
