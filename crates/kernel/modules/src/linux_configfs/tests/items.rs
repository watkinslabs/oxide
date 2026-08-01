use super::*;

#[test]
fn config_item_set_name_and_get_unless_zero_work() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Release);
    let mut ty = ConfigItemType {
        release: Some(release),
        attrs: null_mut(),
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
                name: null_mut(),
                ty: &mut ty,
                private: null_mut(),
            },
        },
    };

    unsafe {
        assert_eq!(
            compat::config_item_set_name(
                &mut s.group.item,
                b"named_%u\0".as_ptr() as *const c_char,
                7u32
            ),
            0
        );
    }
    assert_eq!(configfs_register_subsystem(&mut s), 0);
    assert!(tracefs::config_root().lookup_path("named_7").is_some());
    assert_eq!(
        compat::config_item_get_unless_zero(&mut s.group.item),
        &mut s.group.item as *mut ConfigItem
    );
    config_item_put(&mut s.group.item);
    configfs_unregister_subsystem(&mut s);
    assert!(compat::config_item_get_unless_zero(&mut s.group.item).is_null());
    assert_eq!(RELEASES.load(Ordering::Acquire), 1);
}

#[test]
fn configfs_remove_default_groups_detaches_children_once() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    RELEASES.store(0, Ordering::Release);
    let mut child_ty = ConfigItemType {
        release: Some(release),
        attrs: null_mut(),
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
            name: b"defchild\0".as_ptr() as *const c_char,
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
        allow_link: None,
        drop_link: None,
        make_item: None,
        make_group: None,
        drop_item: None,
    };
    let mut s = ConfigfsSubsystem {
        group: ConfigGroup {
            item: ConfigItem {
                name: b"sample_remove_defaults\0".as_ptr() as *const c_char,
                ty: &mut parent_ty,
                private: null_mut(),
            },
        },
    };

    assert_eq!(configfs_register_subsystem(&mut s), 0);
    assert!(tracefs::config_root().lookup_path("sample_remove_defaults/defchild").is_some());
    compat::configfs_remove_default_groups(&mut s.group);
    assert!(tracefs::config_root().lookup_path("sample_remove_defaults/defchild").is_none());
    assert_eq!(RELEASES.load(Ordering::Acquire), 1);
    configfs_unregister_subsystem(&mut s);
    assert_eq!(RELEASES.load(Ordering::Acquire), 2);
}

