use super::*;
use crate::uapi::DRM_RENDER_MINOR_BASE;

#[test]
fn register_rejects_duplicate_card_id_without_republishing() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = 0x7ff0;
    unregister(card_id);

    assert!(register(card_id, None));
    assert!(!register(card_id, None));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "drm" && d.addr == format!("dri/card{card_id}"))
            .count(),
        1
    );

    unregister(card_id);
}

#[test]
fn unregister_then_register_restores_card_and_render_nodes() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = 0x7ff2;
    let card_name = format!("dri/card{card_id}");
    let render_minor = DRM_RENDER_MINOR_BASE + card_id;
    let render_name = format!("dri/renderD{render_minor}");
    unregister(card_id);

    for _ in 0..2 {
        assert!(register(card_id, None));
        assert!(registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            2
        );
        assert!(drv::devices().iter().any(|d| d.bus == "drm" && d.addr == card_name));
        assert!(drv::devices().iter().any(|d| d.bus == "drm" && d.addr == render_name));

        unregister(card_id);
        assert!(!registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            0
        );
    }
}

#[test]
fn register_publishes_render_node() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = 0x7ff1;
    unregister(card_id);
    let render_minor = DRM_RENDER_MINOR_BASE + card_id;
    let render_name = format!("dri/renderD{render_minor}");

    assert!(register(card_id, None));
    assert!(registered_card_ids().contains(&card_id));
    let dev = drv::devices().into_iter().find(|d| d.bus == "drm" && d.addr == render_name).expect("render node");
    assert_eq!(dev.devname.as_deref(), Some(render_name.as_str()));
    assert_eq!(dev.dev_t, Some((crate::DRM_MAJOR, render_minor)));
    unregister(card_id);
}

#[test]
fn register_publishes_card_and_render_metadata_per_stable_slot() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = 0x7ff3;
    let card_name = format!("dri/card{card_id}");
    unregister(card_id);

    assert!(register(card_id, None));
    let dev = drv::devices()
        .into_iter()
        .find(|d| d.bus == "drm" && d.addr == card_name)
        .expect("drm card model device");
    assert_eq!(dev.dev_class, "drm");
    assert_eq!(dev.devname.as_deref(), Some(card_name.as_str()));
    assert_eq!(dev.dev_t, Some((crate::DRM_MAJOR, card_id)));
    let inode = dev.node_factory.as_ref().expect("drm card factory")();
    assert_eq!(inode.file_type(), vfs::FileType::CharDev);
    assert_eq!(super::super::publication::drm_inode_parts(&inode), Some((super::super::publication::DRM_CARD_INO, card_id)));

    let render_minor = DRM_RENDER_MINOR_BASE + card_id;
    let render_name = format!("dri/renderD{render_minor}");
    let render = drv::devices().into_iter().find(|d| d.bus == "drm" && d.addr == render_name).expect("drm render device");
    assert_eq!(render.dev_t, Some((crate::DRM_MAJOR, render_minor)));
    let inode = render.node_factory.as_ref().expect("drm render factory")();
    assert_eq!(inode.file_type(), vfs::FileType::CharDev);
    assert_eq!(super::super::publication::drm_inode_parts(&inode), Some((super::super::publication::DRM_RENDER_INO, card_id)));

    unregister(card_id);
}
