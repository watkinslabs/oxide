use super::*;
use syscall::errno::Errno;

#[test]
fn drm_set_client_cap_accepts_atomic_without_affecting_other_rejections() {
    let _guard = crate::TEST_LOCK.lock();
    let card = open_file(make_card_inode(0));
    let unsupported = [
        crate::DRM_CLIENT_CAP_STEREO_3D,
        crate::DRM_CLIENT_CAP_ASPECT_RATIO,
        crate::DRM_CLIENT_CAP_WRITEBACK_CONNECTORS,
    ];

    for value in [0u64, 1u64] {
        card.set_private_data(0);
        let mut req = [crate::DRM_CLIENT_CAP_ATOMIC, value];
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_CLIENT_CAP, req.as_mut_ptr() as u64), Some(0));
        assert_eq!(card.private_data() & DRM_FILE_CAP_ATOMIC, value << crate::DRM_CLIENT_CAP_ATOMIC);
    }

    for value in [0u64, 1u64] {
        card.set_private_data(0);
        let mut req = [crate::DRM_CLIENT_CAP_CURSOR_PLANE_HOTSPOT, value];
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_CLIENT_CAP, req.as_mut_ptr() as u64), Some(0));
    }

    for capability in unsupported {
        for value in [0u64, 1u64] {
            card.set_private_data(DRM_FILE_CAP_ATOMIC);
            let mut req = [capability, value];
            assert_eq!(
                handle_drm_ioctl(&card, DRM_IOCTL_SET_CLIENT_CAP, req.as_mut_ptr() as u64),
                Some(-(Errno::Eopnotsupp.as_i32() as i64))
            );
            assert_eq!(card.private_data(), DRM_FILE_CAP_ATOMIC);
        }
    }
}
