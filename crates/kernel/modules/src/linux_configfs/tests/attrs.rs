use super::*;

#[test]
fn attr_open_pins_active_operation_until_unregister_marks_dead() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    SHOWS.store(0, Ordering::Release);
    ACTIVE_RELEASES.store(0, Ordering::Release);
    let mut attr = ConfigfsAttribute {
        name: ATTR_NAME.as_ptr() as *const c_char,
        mode: 0o444,
        show: Some(show),
        store: None,
    };
    let mut attrs = [&mut attr as *mut ConfigfsAttribute, null_mut()];
    let mut ty = ConfigItemType {
        release: Some(active_release),
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
                name: b"sample_active\0".as_ptr() as *const c_char,
                ty: &mut ty,
                private: null_mut(),
            },
        },
    };
    assert_eq!(configfs_register_subsystem(&mut s), 0);
    let inode = tracefs::config_root().lookup_path("sample_active/value").expect("active attr");
    let fdt = FdTable::new();
    let dentry = Dentry::new_root(inode.clone());
    let fd = install_open_at(&fdt, inode, dentry, OpenFlags::O_RDONLY, 0, vfs::FileCred::root(), 1024, None)
        .expect("open configfs attr");
    let file = fdt.get(fd).expect("fd file");
    let mut buf = [0u8; 8];

    configfs_unregister_subsystem(&mut s);
    assert_eq!(ACTIVE_RELEASES.load(Ordering::Acquire), 1);
    assert_eq!(file.read(&mut buf), Err(VfsError::Enoent));
    assert_eq!(SHOWS.load(Ordering::Acquire), 0);
    fdt.close(fd).expect("close configfs fd");
}

#[test]
fn bin_attr_write_flushes_once_on_last_close() {
    let _modules = crate::test_serial::claim();
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    BIN_WRITES.store(0, Ordering::Release);
    BIN_WRITTEN_LEN.store(0, Ordering::Release);
    let mut bin = ConfigfsBinAttribute {
        attr: ConfigfsAttribute {
            name: BIN_NAME.as_ptr() as *const c_char,
            mode: 0o644,
            show: None,
            store: None,
        },
        private: null_mut(),
        size: 16,
        read: Some(bin_read),
        write: Some(bin_write),
    };
    let mut bin_attrs = [&mut bin as *mut ConfigfsBinAttribute, null_mut()];
    let mut ty = ConfigItemType {
        release: None,
        attrs: null_mut(),
        default_groups: null_mut(),
        bin_attrs: bin_attrs.as_mut_ptr(),
        allow_link: None,
        drop_link: None,
        make_item: None,
        make_group: None,
        drop_item: None,
    };
    let mut s = ConfigfsSubsystem {
        group: ConfigGroup {
            item: ConfigItem {
                name: b"sample_bin_write\0".as_ptr() as *const c_char,
                ty: &mut ty,
                private: null_mut(),
            },
        },
    };
    assert_eq!(configfs_register_subsystem(&mut s), 0);
    let inode = tracefs::config_root().lookup_path("sample_bin_write/blob").expect("bin attr");
    let fdt = FdTable::new();
    let dentry = Dentry::new_root(inode.clone());
    let fd = install_open_at(&fdt, inode, dentry, OpenFlags::O_WRONLY, 0, vfs::FileCred::root(), 1024, None)
        .expect("open bin attr");
    {
        let file = fdt.get(fd).expect("fd file");
        assert_eq!(file.write(b"abcd"), Ok(4));
        assert_eq!(BIN_WRITES.load(Ordering::Acquire), 0);
    }
    fdt.close(fd).expect("close configfs bin fd");
    assert_eq!(BIN_WRITES.load(Ordering::Acquire), 1);
    assert_eq!(BIN_WRITTEN_LEN.load(Ordering::Acquire), 4);
    configfs_unregister_subsystem(&mut s);
}
