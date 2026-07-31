use super::*;
use crate::uapi::DRM_RENDER_MINOR_BASE;

const DUPLICATE_CARD_ID: u32 = 0x7ff0;
const RENDER_PUBLICATION_CARD_ID: u32 = 0x7ff1;
const REPUBLISH_CARD_ID: u32 = 0x7ff2;
const METADATA_CARD_ID: u32 = 0x7ff3;
const PARENTED_CARD_ID: u32 = 0x7ff4;
const CARD_POLL_CARD_ID: u32 = 6;
const EMPTY_CARD_READ_ID: u32 = 7;
const EMPTY_RENDER_READ_ID: u32 = 9;
const EVENT_READ_BUFFER_BYTES: usize = 64;

#[test]
fn register_rejects_duplicate_card_id_without_republishing() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = DUPLICATE_CARD_ID;
    unregister(card_id);

    assert!(register(card_id, None));
    assert!(!register(card_id, None));
    assert_eq!(
        drv::devices()
            .iter()
            .filter(|d| d.bus == "drm" && d.addr == format!("card{card_id}"))
            .count(),
        1
    );

    unregister(card_id);
}

#[test]
fn unregister_then_register_restores_card_and_render_nodes() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = REPUBLISH_CARD_ID;
    let card_addr = format!("card{card_id}");
    let render_minor = DRM_RENDER_MINOR_BASE + card_id;
    let render_addr = format!("renderD{render_minor}");
    unregister(card_id);

    for _ in 0..2 {
        assert!(register(card_id, None));
        assert!(registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_addr || d.addr == render_addr))
                .count(),
            2
        );
        assert!(drv::devices().iter().any(|d| d.bus == "drm" && d.addr == card_addr));
        assert!(drv::devices().iter().any(|d| d.bus == "drm" && d.addr == render_addr));

        unregister(card_id);
        assert!(!registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_addr || d.addr == render_addr))
                .count(),
            0
        );
    }
}

#[test]
fn register_publishes_render_node() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = RENDER_PUBLICATION_CARD_ID;
    unregister(card_id);
    let render_minor = DRM_RENDER_MINOR_BASE + card_id;
    let render_addr = format!("renderD{render_minor}");
    let render_name = format!("dri/{render_addr}");

    assert!(register(card_id, None));
    assert!(registered_card_ids().contains(&card_id));
    let dev = drv::devices().into_iter().find(|d| d.bus == "drm" && d.addr == render_addr).expect("render node");
    assert_eq!(dev.devname.as_deref(), Some(render_name.as_str()));
    assert_eq!(dev.dev_t, Some((crate::DRM_MAJOR, render_minor)));
    unregister(card_id);
}

#[test]
fn register_publishes_card_and_render_metadata_per_stable_slot() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = METADATA_CARD_ID;
    let card_addr = format!("card{card_id}");
    let card_name = format!("dri/{card_addr}");
    unregister(card_id);

    assert!(register(card_id, None));
    let dev = drv::devices()
        .into_iter()
        .find(|d| d.bus == "drm" && d.addr == card_addr)
        .expect("drm card model device");
    assert_eq!(dev.dev_class, "drm");
    assert_eq!(dev.devname.as_deref(), Some(card_name.as_str()));
    assert_eq!(dev.dev_t, Some((crate::DRM_MAJOR, card_id)));
    assert_eq!(
        drv::device_canon_exact(&dev),
        Some(format!("devices/virtual/drm/{card_addr}")),
    );
    let inode = dev.node_factory.as_ref().expect("drm card factory")();
    assert_eq!(inode.file_type(), vfs::FileType::CharDev);
    assert_eq!(super::super::publication::drm_inode_parts(&inode), Some((super::super::publication::DrmNodeKind::Card, card_id)));

    let render_minor = DRM_RENDER_MINOR_BASE + card_id;
    let render_addr = format!("renderD{render_minor}");
    let render = drv::devices().into_iter().find(|d| d.bus == "drm" && d.addr == render_addr).expect("drm render device");
    assert_eq!(render.dev_t, Some((crate::DRM_MAJOR, render_minor)));
    let inode = render.node_factory.as_ref().expect("drm render factory")();
    assert_eq!(inode.file_type(), vfs::FileType::CharDev);
    assert_eq!(super::super::publication::drm_inode_parts(&inode), Some((super::super::publication::DrmNodeKind::Render, card_id)));

    unregister(card_id);
}

#[test]
fn parented_nodes_publish_their_canonical_sysfs_relative_address() {
    let _guard = crate::TEST_LOCK.lock();
    let card_id = PARENTED_CARD_ID;
    let parent_addr = format!("drm-parent-{card_id}");
    let parent = drv::try_device_add(Arc::new(drv::Device::new(
        "virtio",
        alloc::string::String::from(parent_addr.as_str()),
        0,
        0,
        0,
    ))).expect("DRM parent");
    unregister(card_id);

    assert!(register(card_id, Some(&parent)));
    let card_addr = format!("card{card_id}");
    let card_devname = format!("dri/{card_addr}");
    let card_canon = format!("devices/virtio/{parent_addr}/drm/{card_addr}");
    let card = drv::devices().into_iter()
        .find(|dev| dev.bus == "drm" && dev.addr == card_addr)
        .expect("parented DRM card");
    assert_eq!(card.devname.as_deref(), Some(card_devname.as_str()));
    assert_eq!(card.parent(), Some(("virtio", parent_addr.as_str())));
    assert_eq!(
        drv::device_canon_exact(&card),
        Some(card_canon),
    );

    unregister(card_id);
    drv::device_del(&parent);
}

/// A card inode MUST carry the same `PollSubscribers` object the flip-event
/// queue notifies. Two distinct sets would leave every poll/epoll waiter
/// registered on something nothing ever wakes — the failure mode that made
/// tty, pty, ext4 FIFOs and mqueue fds unwakeable (B1461).
#[test]
fn card_inode_shares_the_subscriber_set_the_event_queue_notifies() {
    let card_id = CARD_POLL_CARD_ID;
    let inode = super::super::publication::make_card_inode(card_id);
    let on_inode = inode.poll_subscribers_arc().expect("card inode has no poll subscribers");
    let notified = super::super::publication::card_poll_subs(card_id);
    assert!(Arc::ptr_eq(&on_inode, &notified),
            "card inode subscriber set is not the one queue_flip_event notifies");
}

/// An empty DRM event queue returns `EAGAIN` for `O_NONBLOCK` and waits
/// otherwise. A zero-byte read is EOF to a GLib fd
/// source, which tears the source down and re-dispatches it forever.
#[test]
fn empty_card_read_is_eagain_never_zero() {
    let card_id = EMPTY_CARD_READ_ID;
    crate::crtc::clear_card_state(card_id);
    let inode = super::super::publication::make_card_inode(card_id);
    static CARD_TEST_OPS: vfs::dentry::DentryOps = vfs::dentry::DentryOps {
        d_dname: None, d_hash: None, d_compare: None, d_revalidate: None,
        d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None,
        d_init: None, d_prune: None,
    };
    let dentry = vfs::dcache::d_alloc_pseudo("card-test", inode.clone(), &CARD_TEST_OPS);
    let file = vfs::File::new(
        inode,
        dentry,
        vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK,
    );
    let mut buf = [0u8; EVENT_READ_BUFFER_BYTES];
    let r = file.read(&mut buf);
    assert!(matches!(r, Err(vfs::VfsError::Eagain)), "empty card read returned {r:?}, want Eagain");
}

/// Render minors share the card event-read contract. A render fd never has
/// events queued, so it must answer `EAGAIN` or wait, never return EOF.
#[test]
fn empty_render_read_is_eagain_never_zero() {
    let card_id = EMPTY_RENDER_READ_ID;
    crate::crtc::clear_card_state(card_id);
    let inode = super::super::publication::make_render_inode(card_id);
    static R_OPS: vfs::dentry::DentryOps = vfs::dentry::DentryOps {
        d_dname: None, d_hash: None, d_compare: None, d_revalidate: None,
        d_weak_revalidate: None, d_delete: None, d_release: None, d_iput: None,
        d_init: None, d_prune: None,
    };
    let dentry = vfs::dcache::d_alloc_pseudo("render-test", inode.clone(), &R_OPS);
    let file = vfs::File::new(inode, dentry, vfs::OpenFlags::O_RDWR | vfs::OpenFlags::O_NONBLOCK);
    let mut buf = [0u8; EVENT_READ_BUFFER_BYTES];
    let r = file.read(&mut buf);
    assert!(matches!(r, Err(vfs::VfsError::Eagain)), "empty render read returned {r:?}, want Eagain");
}
