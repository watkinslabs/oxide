use super::auth::{clear_master_owner, is_magic_authorized, DRM_FILE_CAP_ATOMIC};
use super::publication::{make_card_inode, make_render_inode};
use super::uapi::{DrmModeAtomic, DrmSetVersion, DrmUnique, DRM_IF_MAJOR, DRM_IF_MINOR};
use super::*;
use alloc::format;
use alloc::sync::Arc;
use crate::DRM_MODE_ATOMIC_TEST_ONLY;
use vfs::{Dentry, File, OpenFlags};

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

    fn open_file(inode: vfs::InodeRef) -> Arc<File> {
        let dentry = Dentry::new_anon(Arc::clone(&inode));
        File::new(inode, dentry, OpenFlags::O_RDWR)
    }

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
    fn unregister_then_register_restores_card_node_only() {
        let _guard = crate::TEST_LOCK.lock();
        let card_id = 0x7ff2;
        let card_name = format!("dri/card{card_id}");
        let render_minor = 128 + card_id;
        let render_name = format!("dri/renderD{render_minor}");
        unregister(card_id);

        assert!(register(card_id, None));
        assert!(registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            1
        );
        assert!(drv::devices().iter().any(|d| d.bus == "drm" && d.addr == card_name));
        assert!(drv::devices().iter().all(|d| d.bus != "drm" || d.addr != render_name));

        unregister(card_id);
        assert!(!registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            0
        );

        assert!(register(card_id, None));
        assert!(registered_card_ids().contains(&card_id));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "drm" && (d.addr == card_name || d.addr == render_name))
                .count(),
            1
        );
        assert!(drv::devices().iter().any(|d| d.bus == "drm" && d.addr == card_name));
        assert!(drv::devices().iter().all(|d| d.bus != "drm" || d.addr != render_name));

        unregister(card_id);
    }

    #[test]
    fn register_does_not_publish_render_node() {
        let _guard = crate::TEST_LOCK.lock();
        let card_id = 0x7ff1;
        unregister(card_id);
        let render_minor = 128 + card_id;
        let render_name = format!("dri/renderD{render_minor}");

        assert!(register(card_id, None));
        assert!(registered_card_ids().contains(&card_id));
        assert!(drv::devices().iter().all(|d| d.bus != "drm" || d.addr != render_name));
        unregister(card_id);
    }

    #[test]
    fn render_node_rejects_master_only_ioctls() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        let render = open_file(make_render_inode(0));
        assert_eq!(
            handle_drm_ioctl(&render, DRM_IOCTL_MODE_SETCRTC, 1),
            Some(-(Errno::Eacces.as_i32() as i64))
        );
        assert_eq!(
            handle_drm_ioctl(&render, DRM_IOCTL_SET_MASTER, 1),
            Some(-(Errno::Eacces.as_i32() as i64))
        );
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
        let other = open_file(make_card_inode(0));

        assert_eq!(handle_drm_ioctl(&owner, DRM_IOCTL_SET_MASTER, 0), Some(0));
        assert_eq!(handle_drm_ioctl(&owner, DRM_IOCTL_SET_MASTER, 0), Some(0));
        assert_eq!(
            handle_drm_ioctl(&other, DRM_IOCTL_SET_MASTER, 0),
            Some(-(Errno::Ebusy.as_i32() as i64))
        );
        assert_eq!(
            handle_drm_ioctl(&other, DRM_IOCTL_DROP_MASTER, 0),
            Some(-(Errno::Einval.as_i32() as i64))
        );
        assert_eq!(handle_drm_ioctl(&owner, DRM_IOCTL_DROP_MASTER, 0), Some(0));
        assert_eq!(handle_drm_ioctl(&other, DRM_IOCTL_SET_MASTER, 0), Some(0));
        clear_master_owner(0);
    }

    #[test]
    fn drm_atomic_client_cap_is_not_advertised_until_properties_exist() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        clear_master_owner(0);
        let card = open_file(make_card_inode(0));
        let mut atomic = [0u8; 56];
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
        };
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
        let mut unique = DrmUnique {
            unique_len: 8,
            unique: buffer.as_mut_ptr() as u64,
        };

        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_GET_UNIQUE, (&mut unique as *mut DrmUnique) as u64),
            Some(0)
        );

        assert_eq!(unique.unique_len, expected.len() as u64);
        assert_eq!(&buffer[..8], &expected[..8]);
        assert_eq!(buffer[8], 0);
        assert!(crate::unregister(card_id));
    }

    #[test]
    fn drm_set_version_negotiates_supported_core_interface() {
        let _guard = crate::TEST_LOCK.lock();
        use syscall::errno::Errno;

        let card = open_file(make_card_inode(0));
        let mut version = DrmSetVersion {
            drm_di_major: DRM_IF_MAJOR,
            drm_di_minor: DRM_IF_MINOR,
            drm_dd_major: 9,
            drm_dd_minor: 9,
        };
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_SET_VERSION, (&mut version as *mut DrmSetVersion) as u64),
            Some(0)
        );
        assert_eq!(version.drm_di_major, DRM_IF_MAJOR);
        assert_eq!(version.drm_di_minor, DRM_IF_MINOR);
        assert_eq!(version.drm_dd_major, 0);
        assert_eq!(version.drm_dd_minor, 0);

        version.drm_di_minor = DRM_IF_MINOR + 1;
        assert_eq!(
            handle_drm_ioctl(&card, DRM_IOCTL_SET_VERSION, (&mut version as *mut DrmSetVersion) as u64),
            Some(-(Errno::Einval.as_i32() as i64))
        );
    }
