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

/// A card inode MUST carry the same `PollSubscribers` object the flip-event
/// queue notifies. Two distinct sets would leave every poll/epoll waiter
/// registered on something nothing ever wakes — the failure mode that made
/// tty, pty, ext4 FIFOs and mqueue fds unwakeable (B1461).
#[test]
fn card_inode_shares_the_subscriber_set_the_event_queue_notifies() {
    let card_id = 6;
    let inode = super::super::publication::make_card_inode(card_id);
    let on_inode = inode.poll_subscribers_arc().expect("card inode has no poll subscribers");
    let notified = super::super::publication::card_poll_subs(card_id);
    assert!(Arc::ptr_eq(&on_inode, &notified),
            "card inode subscriber set is not the one queue_flip_event notifies");
}

/// Linux `drm_read` never returns 0: nothing queued is `-EAGAIN` for
/// `O_NONBLOCK` and a sleep otherwise. A 0-byte read is EOF to a GLib fd
/// source, which tears the source down and re-dispatches it forever.
#[test]
fn empty_card_read_is_eagain_never_zero() {
    let card_id = 7;
    crate::crtc::clear_card_state(card_id);
    let inode = super::super::publication::make_card_inode(card_id);
    static CARD_TEST_OPS: vfs::dentry::DentryOps = vfs::dentry::DentryOps {
        d_dname: None, d_hash: None, d_compare: None, d_revalidate: None,
        d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None,
        d_init: None, d_prune: None,
    };
    let dentry = vfs::dcache::d_alloc_pseudo("card-test", inode.clone(), &CARD_TEST_OPS);
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR);
    let mut buf = [0u8; 64];
    let r = vfs::FileOps::read_file(&super::super::publication::DrmCardFileOps, &file, 0, &mut buf);
    assert!(matches!(r, Err(vfs::VfsError::Eagain)), "empty card read returned {r:?}, want Eagain");
}

/// Render minors share `drm_read` with card minors in Linux. A render fd never
/// has events queued, so it must answer `EAGAIN`/sleep — never 0, which a GLib
/// fd source reads as EOF. Same defect the card node carried.
#[test]
fn empty_render_read_is_eagain_never_zero() {
    let card_id = 9;
    crate::crtc::clear_card_state(card_id);
    let inode = super::super::publication::make_render_inode(card_id);
    static R_OPS: vfs::dentry::DentryOps = vfs::dentry::DentryOps {
        d_dname: None, d_hash: None, d_compare: None, d_revalidate: None,
        d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None,
        d_init: None, d_prune: None,
    };
    let dentry = vfs::dcache::d_alloc_pseudo("render-test", inode.clone(), &R_OPS);
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
    let mut buf = [0u8; 64];
    let r = vfs::FileOps::read_file(&super::super::publication::DrmSinkFileOps, &file, 0, &mut buf);
    assert!(matches!(r, Err(vfs::VfsError::Eagain)), "empty render read returned {r:?}, want Eagain");
}
