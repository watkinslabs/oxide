use super::*;

#[test]
fn subsystem_registers_attrs_in_config_root() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut attr = ConfigfsAttribute {
        name: ATTR_NAME.as_ptr() as *const c_char,
        mode: 0o444,
        show: Some(show),
        store: None,
    };
    let mut attrs = [&mut attr as *mut ConfigfsAttribute, core::ptr::null_mut()];
    let mut ty = ConfigItemType {
        release: None,
        attrs: attrs.as_mut_ptr(),
        default_groups: null_mut(),
        bin_attrs: null_mut(),
        allow_link: None,
        drop_link: None,
        make_item: None,
        make_group: None,
        drop_item: None,
    };
    let mut s = ConfigfsSubsystem {
        group: ConfigGroup {
            item: ConfigItem {
                name: GROUP_NAME.as_ptr() as *const c_char,
                ty: &mut ty,
                private: null_mut(),
            },
        },
    };
    assert_eq!(configfs_register_subsystem(&mut s), 0);
    let inode = tracefs::config_root().lookup_path("sample/value").expect("configfs attr");
    let mut buf = [0u8; 8];
    let n = inode.read(0, &mut buf).expect("read configfs attr");
    assert_eq!(&buf[..n], b"ok\n");
    configfs_unregister_subsystem(&mut s);
    assert!(tracefs::config_root().lookup_path("sample/value").is_none());
}

#[test]
fn default_group_bin_attr_link_and_release_paths_work() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Release);
    LINKS.store(0, Ordering::Release);
    let mut bin = ConfigfsBinAttribute {
        attr: ConfigfsAttribute {
            name: BIN_NAME.as_ptr() as *const c_char,
            mode: 0o444,
            show: None,
            store: None,
        },
        private: null_mut(),
        size: 6,
        read: Some(bin_read),
        write: None,
    };
    let mut bin_attrs = [&mut bin as *mut ConfigfsBinAttribute, null_mut()];
    let mut child_ty = ConfigItemType {
        release: Some(release),
        attrs: null_mut(),
        default_groups: null_mut(),
        bin_attrs: bin_attrs.as_mut_ptr(),
        allow_link: None,
        drop_link: None,
        make_item: None,
        make_group: None,
        drop_item: None,
    };
    let mut child = ConfigGroup {
        item: ConfigItem {
            name: CHILD_NAME.as_ptr() as *const c_char,
            ty: &mut child_ty,
            private: null_mut(),
        },
    };
    let mut defaults = [&mut child as *mut ConfigGroup, null_mut()];
    let mut parent_ty = ConfigItemType {
        release: Some(release),
        attrs: null_mut(),
        default_groups: defaults.as_mut_ptr(),
        bin_attrs: null_mut(),
        allow_link: Some(allow_link),
        drop_link: Some(drop_link),
        make_item: None,
        make_group: None,
        drop_item: None,
    };
    let mut s = ConfigfsSubsystem {
        group: ConfigGroup {
            item: ConfigItem {
                name: GROUP_LINK_NAME.as_ptr() as *const c_char,
                ty: &mut parent_ty,
                private: null_mut(),
            },
        },
    };

    assert_eq!(configfs_register_subsystem(&mut s), 0);
    let inode = tracefs::config_root().lookup_path("sample_link/child/blob").expect("bin attr");
    let mut buf = [0u8; 8];
    let n = inode.read(0, &mut buf).expect("read bin attr");
    assert_eq!(&buf[..n], b"binary");
    assert_eq!(configfs_create_link(&mut s.group.item, &mut child.item, b"child_link\0".as_ptr() as *const c_char), 0);
    assert!(tracefs::config_root().lookup_path("sample_link/child_link").is_some());
    configfs_drop_link(&mut s.group.item, &mut child.item, b"child_link\0".as_ptr() as *const c_char);
    assert!(tracefs::config_root().lookup_path("sample_link/child_link").is_none());
    assert_eq!(LINKS.load(Ordering::Acquire), 2);
    assert_eq!(config_item_get(&mut s.group.item), &mut s.group.item as *mut ConfigItem);
    config_item_put(&mut s.group.item);
    configfs_unregister_subsystem(&mut s);
    assert_eq!(RELEASES.load(Ordering::Acquire), 2);
}

#[test]
fn mkdir_and_rmdir_call_group_ops_and_install_child_attrs() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    MAKE_GROUPS.store(0, Ordering::Release);
    DROP_ITEMS.store(0, Ordering::Release);
    let mut attr = ConfigfsAttribute {
        name: ATTR_NAME.as_ptr() as *const c_char,
        mode: 0o444,
        show: Some(show),
        store: None,
    };
    let mut attrs = [&mut attr as *mut ConfigfsAttribute, null_mut()];
    let mut child_ty = ConfigItemType {
        release: None,
        attrs: attrs.as_mut_ptr(),
        default_groups: null_mut(),
        bin_attrs: null_mut(),
        allow_link: None,
        drop_link: None,
        make_item: None,
        make_group: None,
        drop_item: None,
    };
    let mut child = ConfigGroup {
        item: ConfigItem {
            name: b"runtime\0".as_ptr() as *const c_char,
            ty: &mut child_ty,
            private: null_mut(),
        },
    };
    MADE_GROUP.store(&mut child as *mut ConfigGroup as usize, Ordering::Release);
    let mut parent_ty = ConfigItemType {
        release: None,
        attrs: null_mut(),
        default_groups: null_mut(),
        bin_attrs: null_mut(),
        allow_link: None,
        drop_link: None,
        make_item: None,
        make_group: Some(make_group),
        drop_item: Some(drop_item),
    };
    let mut s = ConfigfsSubsystem {
        group: ConfigGroup {
            item: ConfigItem {
                name: GROUP_MKDIR_NAME.as_ptr() as *const c_char,
                ty: &mut parent_ty,
                private: null_mut(),
            },
        },
    };

    assert_eq!(configfs_register_subsystem(&mut s), 0);
    let parent = tracefs::config_root().lookup_path("sample_mkdir").expect("configfs parent");
    let child_inode = parent.mkdir("runtime", 0o755, &vfs::CreateCtx::root()).expect("mkdir runtime");
    assert!(matches!(child_inode.file_type(), vfs::FileType::Directory));
    assert!(tracefs::config_root().lookup_path("sample_mkdir/runtime/value").is_some());
    assert_eq!(MAKE_GROUPS.load(Ordering::Acquire), 1);
    assert_eq!(
        compat::configfs_depend_item(&mut s, &mut child.item),
        0
    );
    assert_eq!(parent.rmdir("runtime"), Err(vfs::VfsError::Ebusy));
    compat::configfs_undepend_item(&mut s, &mut child.item);
    parent.rmdir("runtime").expect("rmdir runtime");
    assert!(tracefs::config_root().lookup_path("sample_mkdir/runtime").is_none());
    assert_eq!(DROP_ITEMS.load(Ordering::Acquire), 1);
    configfs_unregister_subsystem(&mut s);
}

