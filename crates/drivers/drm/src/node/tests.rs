use super::auth::{clear_master_owner, is_magic_authorized, DRM_FILE_CAP_ATOMIC};
use super::publication::{make_card_inode, make_render_inode};
use super::uapi::{DrmModeAtomic, DrmSetVersion, DrmUnique, DRM_IF_MAJOR, DRM_IF_MINOR};
use super::*;
use alloc::format;
use alloc::sync::Arc;
use core::sync::atomic::{AtomicU32, Ordering};
use crate::DRM_MODE_ATOMIC_TEST_ONLY;
use vfs::{Dentry, File, OpenFlags};

#[path = "tests/client_cap.rs"]
mod client_cap;
#[path = "tests/get_cap.rs"]
mod get_cap;
#[path = "tests/publication.rs"]
mod publication;

static LAST_SCANOUT_DRIVER_KEY: AtomicU32 = AtomicU32::new(0);

fn scanout_key(raw: u32) -> ScanoutDriverKey { ScanoutDriverKey::from_raw(raw).unwrap() }

fn record_create(driver_key: ScanoutDriverKey, _pa: u64, _w: u32, _h: u32, _fmt: u32) -> Option<u32> {
    LAST_SCANOUT_DRIVER_KEY.store(driver_key.raw(), Ordering::Release);
    Some(driver_key.raw().wrapping_add(1))
}

fn record_destroy(driver_key: ScanoutDriverKey, _res_id: u32) -> bool {
    LAST_SCANOUT_DRIVER_KEY.store(driver_key.raw(), Ordering::Release);
    true
}

fn record_set_scanout(driver_key: ScanoutDriverKey, _res_id: u32, _w: u32, _h: u32) -> bool {
    LAST_SCANOUT_DRIVER_KEY.store(driver_key.raw(), Ordering::Release);
    true
}

fn record_set_cursor(driver_key: ScanoutDriverKey, _res_id: u32, _w: u32, _h: u32,
    _x: i32, _y: i32, _hot_x: i32, _hot_y: i32) -> bool {
    LAST_SCANOUT_DRIVER_KEY.store(driver_key.raw(), Ordering::Release);
    true
}

fn record_move_cursor(driver_key: ScanoutDriverKey, _x: i32, _y: i32) -> bool {
    LAST_SCANOUT_DRIVER_KEY.store(driver_key.raw(), Ordering::Release);
    true
}

fn record_restore(driver_key: ScanoutDriverKey) -> bool {
    LAST_SCANOUT_DRIVER_KEY.store(driver_key.raw(), Ordering::Release);
    true
}

fn record_boot(driver_key: ScanoutDriverKey) -> u32 {
    LAST_SCANOUT_DRIVER_KEY.store(driver_key.raw(), Ordering::Release);
    driver_key.raw()
}

    struct TestDrv;
    impl crate::DrmDriver for TestDrv {
        fn name(&self) -> &'static str { "test_drm" }
        fn version(&self) -> (u32, u32, u32) { (1, 2, 3) }
        fn date(&self) -> &'static str { "20260704" }
        fn desc(&self) -> &'static str { "test drm driver" }
        fn unique(&self) -> &str { "pci:0000:01:02.3" }
        fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 0, 0, 0) }
        fn dim_bounds(&self) -> (u32, u32, u32, u32) { (0, 0, 0, 0) }
        fn cap(&self, cap: u64) -> u64 { crate::default_cap(cap) }
    }

    struct UniqueDrv(&'static str);
    impl crate::DrmDriver for UniqueDrv {
        fn name(&self) -> &'static str { "unique_drm" }
        fn version(&self) -> (u32, u32, u32) { (1, 0, 0) }
        fn date(&self) -> &'static str { "20260704" }
        fn desc(&self) -> &'static str { "stable slot route test" }
        fn unique(&self) -> &str { self.0 }
        fn resource_counts(&self) -> (u32, u32, u32, u32) { (0, 0, 0, 0) }
        fn dim_bounds(&self) -> (u32, u32, u32, u32) { (0, 0, 0, 0) }
        fn cap(&self, cap: u64) -> u64 { crate::default_cap(cap) }
    }

    fn open_file(inode: vfs::InodeRef) -> Arc<File> {
        let dentry = Dentry::new_anon(Arc::clone(&inode));
        File::new(inode, dentry, OpenFlags::O_RDWR)
    }

    fn read_unique(file: &File, buf: &mut [u8; 32]) -> u64 {
        let mut unique = DrmUnique { unique_len: buf.len() as u64, unique: buf.as_mut_ptr() as u64 };
        let mut version = DrmSetVersion { drm_di_major: DRM_IF_MAJOR, drm_di_minor: DRM_IF_MINOR, drm_dd_major: -1, drm_dd_minor: -1 };
        assert_eq!(
            handle_drm_ioctl(file, DRM_IOCTL_SET_VERSION, (&mut version as *mut DrmSetVersion) as u64),
            Some(0)
        );
        assert_eq!(
            handle_drm_ioctl(file, DRM_IOCTL_GET_UNIQUE, (&mut unique as *mut DrmUnique) as u64),
            Some(0)
        );
        unique.unique_len
    }

    #[test]
    fn scanout_ops_route_by_card_id_to_driver_key() {
        let _guard = crate::TEST_LOCK.lock();
        clear_scanout_ops(7);
        clear_scanout_ops(8);
        set_scanout_ops(7, ScanoutOps {
            driver_key: scanout_key(0x7001),
            create_from_pa: record_create,
            destroy_resource: record_destroy,
            set_scanout: record_set_scanout,
            set_cursor: record_set_cursor,
            move_cursor: record_move_cursor,
            restore_console: record_restore,
            boot_res_id: record_boot,
        });
        set_scanout_ops(8, ScanoutOps {
            driver_key: scanout_key(0x8002),
            create_from_pa: record_create,
            destroy_resource: record_destroy,
            set_scanout: record_set_scanout,
            set_cursor: record_set_cursor,
            move_cursor: record_move_cursor,
            restore_console: record_restore,
            boot_res_id: record_boot,
        });

        let ops7 = scanout_ops(7).unwrap();
        let ops8 = scanout_ops(8).unwrap();
        assert_eq!(ops7.driver_key.raw(), 0x7001);
        assert_eq!(ops8.driver_key.raw(), 0x8002);
        assert!((ops7.set_scanout)(ops7.driver_key, 42, 640, 480));
        assert_eq!(LAST_SCANOUT_DRIVER_KEY.load(Ordering::Acquire), 0x7001);
        assert!((ops8.restore_console)(ops8.driver_key));
        assert_eq!(LAST_SCANOUT_DRIVER_KEY.load(Ordering::Acquire), 0x8002);

        clear_scanout_ops(7);
        clear_scanout_ops(8);
    }

    #[test]
    fn render_node_rejects_master_only_ioctls() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        let render = open_file(make_render_inode(0));
        assert_eq!(
            handle_drm_ioctl(&render, DRM_IOCTL_MODE_GETRESOURCES, 1),
            Some(-(Errno::Eacces.as_i32() as i64))
        );
        assert_eq!(
            handle_drm_ioctl(&render, DRM_IOCTL_SET_MASTER, 1),
            Some(-(Errno::Eacces.as_i32() as i64))
        );
    }

    #[test]
    fn drm_inode_tags_encode_stable_card_id() {
        let _guard = crate::TEST_LOCK.lock();
        for card_id in [0u32, 7, 0x7ffe] {
            assert_eq!(
                super::publication::drm_inode_parts(&make_card_inode(card_id)),
                Some((super::publication::DRM_CARD_INO, card_id))
            );
            assert_eq!(
                super::publication::drm_inode_parts(&make_render_inode(card_id)),
                Some((super::publication::DRM_RENDER_INO, card_id))
            );
        }
    }

    #[test]
    fn drm_nodes_do_not_acknowledge_raw_writes() {
        let _guard = crate::TEST_LOCK.lock();
        let card = open_file(make_card_inode(0));
        let render = open_file(make_render_inode(0));

        assert_eq!(card.write(b"not a drm ioctl"), Err(vfs::VfsError::Einval));
        assert_eq!(render.write(b"not a drm ioctl"), Err(vfs::VfsError::Einval));
    }

    #[test]
    fn card_master_ioctls_do_not_require_user_pointer() {
        let _guard = crate::TEST_LOCK.lock();
        let card = open_file(make_card_inode(0));
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_MASTER, 0), Some(0));
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_DROP_MASTER, 0), Some(0));
    }

    #[test]
    fn drm_master_is_owned_by_open_file_description() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        clear_master_owner(0);
        let owner = open_file(make_card_inode(0));
        let owner_dup = Arc::clone(&owner);
        let other = open_file(make_card_inode(0));

        assert_eq!(handle_drm_ioctl(&owner, DRM_IOCTL_SET_MASTER, 0), Some(0));
        assert_eq!(handle_drm_ioctl(&owner_dup, DRM_IOCTL_SET_MASTER, 0), Some(0));
        drop(owner_dup);
        assert_eq!(
            handle_drm_ioctl(&other, DRM_IOCTL_SET_MASTER, 0),
            Some(-(Errno::Ebusy.as_i32() as i64))
        );
        assert_eq!(
            handle_drm_ioctl(&other, DRM_IOCTL_DROP_MASTER, 0),
            Some(-(Errno::Einval.as_i32() as i64))
        );
        drop(owner);
        assert_eq!(handle_drm_ioctl(&other, DRM_IOCTL_SET_MASTER, 0), Some(0));
        clear_master_owner(0);
    }

    #[test]
    fn drm_atomic_client_cap_is_not_advertised_until_properties_exist() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        clear_master_owner(0);
        let card = open_file(make_card_inode(0));
        let mut atomic = [0u8; core::mem::size_of::<DrmModeAtomic>()];
        atomic[0..4].copy_from_slice(&DRM_MODE_ATOMIC_TEST_ONLY.to_le_bytes());
        let atomic_arg = atomic.as_mut_ptr() as u64;
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_MODE_ATOMIC, atomic_arg),
            Some(-(Errno::Einval.as_i32() as i64))
        );

        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_MASTER, 0), Some(0));
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_MODE_ATOMIC, atomic_arg),
            Some(-(Errno::Einval.as_i32() as i64))
        );

        let mut cap = [crate::DRM_CLIENT_CAP_ATOMIC, 1u64];
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_SET_CLIENT_CAP, cap.as_mut_ptr() as u64),
            Some(-(Errno::Eopnotsupp.as_i32() as i64))
        );
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_MODE_ATOMIC, atomic_arg),
            Some(-(Errno::Einval.as_i32() as i64))
        );

        card.set_private_data(DRM_FILE_CAP_ATOMIC);

        let mut bad_flags = DrmModeAtomic {
            flags: 0x8000_0000,
            count_objs: 0,
            objs_ptr: 0,
            count_props_ptr: 0,
            props_ptr: 0,
            prop_values_ptr: 0,
            reserved: 0,
            user_data: 0,
        };
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_MODE_ATOMIC, (&mut bad_flags as *mut DrmModeAtomic) as u64),
            Some(-(Errno::Einval.as_i32() as i64))
        );
        bad_flags.flags = DRM_MODE_ATOMIC_TEST_ONLY;
        bad_flags.reserved = 1;
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_MODE_ATOMIC, (&mut bad_flags as *mut DrmModeAtomic) as u64),
            Some(-(Errno::Einval.as_i32() as i64))
        );

        let mut bad_arrays = DrmModeAtomic {
            flags: DRM_MODE_ATOMIC_TEST_ONLY,
            count_objs: 1,
            objs_ptr: 0,
            count_props_ptr: 0,
            props_ptr: 0,
            prop_values_ptr: 0,
            reserved: 0,
            user_data: 0,
        };
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_MODE_ATOMIC, (&mut bad_arrays as *mut DrmModeAtomic) as u64),
            Some(-(Errno::Efault.as_i32() as i64))
        );

        let mut objs = [1u32];
        let mut count_props = [1u32];
        let mut props = [1u32];
        let mut values = [0u64];
        let mut unsupported_commit = DrmModeAtomic {
            flags: DRM_MODE_ATOMIC_TEST_ONLY,
            count_objs: objs.len() as u32,
            objs_ptr: objs.as_mut_ptr() as u64,
            count_props_ptr: count_props.as_mut_ptr() as u64,
            props_ptr: props.as_mut_ptr() as u64,
            prop_values_ptr: values.as_mut_ptr() as u64,
            reserved: 0,
            user_data: 0,
        };
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_MODE_ATOMIC, (&mut unsupported_commit as *mut DrmModeAtomic) as u64),
            Some(-(Errno::Eopnotsupp.as_i32() as i64))
        );
        card.set_private_data(0);
        clear_master_owner(0);
    }

    #[test]
    fn drm_auth_magic_requires_master_and_records_requested_magic() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        unregister_all();
        let master = open_file(make_card_inode(0));
        let client = open_file(make_card_inode(0));
        let mut magic = 0u32;

        assert_eq!(
            handle_drm_ioctl(&client, DRM_IOCTL_GET_MAGIC, (&mut magic as *mut u32) as u64),
            Some(0)
        );
        assert_ne!(magic, 0);
        assert_eq!(
            handle_drm_ioctl(&client, DRM_IOCTL_AUTH_MAGIC, (&mut magic as *mut u32) as u64),
            Some(-(Errno::Eacces.as_i32() as i64))
        );

        assert_eq!(handle_drm_ioctl(&master, DRM_IOCTL_SET_MASTER, 0), Some(0));
        let mut forged = magic.wrapping_add(1000);
        assert_eq!(
            handle_drm_ioctl(&master, DRM_IOCTL_AUTH_MAGIC, (&mut forged as *mut u32) as u64),
            Some(-(Errno::Einval.as_i32() as i64))
        );
        assert!(!is_magic_authorized(0, forged));
        assert_eq!(
            handle_drm_ioctl(&master, DRM_IOCTL_AUTH_MAGIC, (&mut magic as *mut u32) as u64),
            Some(0)
        );
        assert!(is_magic_authorized(0, magic));
        unregister_all();
    }

    #[test]
    fn drm_get_unique_copies_driver_bus_id_and_reports_full_length() {
        let _guard = crate::TEST_LOCK.lock();
        unregister_all();
        let card_id = crate::register(Arc::new(TestDrv));
        let card = open_file(make_card_inode(card_id));
        let expected = b"pci:0000:01:02.3";
        let mut buffer = [0u8; 32];
        let mut unique = DrmUnique { unique_len: 8, unique: buffer.as_mut_ptr() as u64 };
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_GET_UNIQUE, (&mut unique as *mut DrmUnique) as u64), Some(0));
        assert_eq!(unique.unique_len, 0);
        assert_eq!(buffer[0], 0);
        let mut version = DrmSetVersion { drm_di_major: DRM_IF_MAJOR, drm_di_minor: DRM_IF_MINOR, drm_dd_major: -1, drm_dd_minor: -1 };
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_VERSION, (&mut version as *mut DrmSetVersion) as u64), Some(0));
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_GET_UNIQUE, (&mut unique as *mut DrmUnique) as u64), Some(0));
        assert_eq!(unique.unique_len, expected.len() as u64);
        assert_eq!(&buffer[..8], &[0u8; 8]);
        unique.unique_len = buffer.len() as u64;
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_GET_UNIQUE, (&mut unique as *mut DrmUnique) as u64), Some(0));
        assert_eq!(&buffer[..expected.len()], expected);
        assert!(crate::unregister(card_id));
    }

    #[test]
    fn drm_card_fd_routes_by_stable_slot_after_lower_slot_reuse() {
        let _guard = crate::TEST_LOCK.lock();
        unregister_all();
        crate::registry::clear_cards_for_tests();
        let slot0 = crate::register(Arc::new(UniqueDrv("pci:slot0")));
        let slot1 = crate::register(Arc::new(UniqueDrv("pci:slot1")));
        assert_eq!((slot0, slot1), (0, 1));
        let card1 = open_file(make_card_inode(slot1));
        assert!(crate::unregister(slot0));
        let slot0_reused = crate::register(Arc::new(UniqueDrv("pci:slot0-reused")));
        assert_eq!(slot0_reused, 0);

        let mut buf1 = [0u8; 32];
        assert_eq!(read_unique(&card1, &mut buf1), b"pci:slot1".len() as u64);
        assert_eq!(&buf1[..b"pci:slot1".len()], b"pci:slot1");
        let card0 = open_file(make_card_inode(slot0_reused));
        let mut buf0 = [0u8; 32];
        assert_eq!(read_unique(&card0, &mut buf0), b"pci:slot0-reused".len() as u64);
        assert_eq!(&buf0[..b"pci:slot0-reused".len()], b"pci:slot0-reused");

        assert!(crate::unregister(slot0_reused));
        assert!(crate::unregister(slot1));
    }

    #[test]
    fn drm_set_version_negotiates_supported_core_interface() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        unregister_all();
        let card_id = crate::register(Arc::new(TestDrv));
        let card = open_file(make_card_inode(card_id));
        let mut version = DrmSetVersion { drm_di_major: DRM_IF_MAJOR, drm_di_minor: DRM_IF_MINOR, drm_dd_major: -1, drm_dd_minor: -1 };
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_VERSION, (&mut version as *mut DrmSetVersion) as u64), Some(0));
        assert_eq!(version.drm_di_major, DRM_IF_MAJOR);
        assert_eq!(version.drm_di_minor, DRM_IF_MINOR);
        assert_eq!(version.drm_dd_major, 1);
        assert_eq!(version.drm_dd_minor, 2);

        version.drm_di_major = -1;
        version.drm_di_minor = -1;
        version.drm_dd_major = 1;
        version.drm_dd_minor = 3;
        assert_eq!(handle_drm_ioctl(&card, DRM_IOCTL_SET_VERSION, (&mut version as *mut DrmSetVersion) as u64), Some(-(Errno::Einval.as_i32() as i64)));
        assert_eq!(version.drm_dd_minor, 2);
        assert!(crate::unregister(card_id));
    }
