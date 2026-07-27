use super::*;
use core::sync::atomic::{AtomicU32, Ordering};
use vfs::{FdTable, OpenFlags, VfsError};
use vfs::Dentry;
use vfs::file::install_open_at;

// Every test below drives the SAME module-level callback counters (RELEASES,
// LINKS, MAKE_GROUPS, ...): each stores 0, runs a configfs operation, then
// asserts an exact count. cargo runs a binary's tests on parallel threads, so
// without this one test's reset lands inside another's measurement window.
//
// The counters cannot be made test-local: they are written from `extern "C"`
// configfs callbacks whose signatures are fixed by the kernel ABI this file
// exists to conform to, and the only per-item slot that could carry a context
// (`ConfigItem::private`) is itself ABI surface under test here.
//
// Poison is recovered rather than propagated: a genuine assertion failure in
// one test must report as ONE failure, not cascade into every sibling.
static TEST_SERIAL: std::sync::Mutex<()> = std::sync::Mutex::new(());

static ATTR_NAME: &[u8] = b"value\0";
static BIN_NAME: &[u8] = b"blob\0";
static CHILD_NAME: &[u8] = b"child\0";
static GROUP_NAME: &[u8] = b"sample\0";
static GROUP_LINK_NAME: &[u8] = b"sample_link\0";
static GROUP_MKDIR_NAME: &[u8] = b"sample_mkdir\0";
static RELEASES: AtomicU32 = AtomicU32::new(0);
static LINKS: AtomicU32 = AtomicU32::new(0);
static MAKE_GROUPS: AtomicU32 = AtomicU32::new(0);
static DROP_ITEMS: AtomicU32 = AtomicU32::new(0);
static SHOWS: AtomicU32 = AtomicU32::new(0);
static ACTIVE_RELEASES: AtomicU32 = AtomicU32::new(0);
static BIN_WRITES: AtomicU32 = AtomicU32::new(0);
static BIN_WRITTEN_LEN: AtomicU32 = AtomicU32::new(0);
static MADE_GROUP: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);

unsafe extern "C" fn show(_item: *mut ConfigItem, buf: *mut c_char) -> isize {
    SHOWS.fetch_add(1, Ordering::AcqRel);
    let body = b"ok\n";
    // SAFETY: configfs passes a page-sized writable kernel buffer.
    unsafe { core::ptr::copy_nonoverlapping(body.as_ptr(), buf as *mut u8, body.len()); }
    body.len() as isize
}

unsafe extern "C" fn bin_read(
    _item: *mut ConfigItem,
    _private: *mut c_void,
    _buf: *mut c_void,
    out: *mut c_char,
    off: i64,
    count: usize,
) -> isize {
    let body = b"binary";
    let off = off.max(0) as usize;
    if off >= body.len() { return 0; }
    let n = (body.len() - off).min(count);
    // SAFETY: configfs passes a writable kernel buffer of count bytes.
    unsafe { core::ptr::copy_nonoverlapping(body[off..off + n].as_ptr(), out as *mut u8, n); }
    n as isize
}

unsafe extern "C" fn bin_write(
    _item: *mut ConfigItem,
    _private: *mut c_void,
    _buf: *mut c_void,
    input: *const c_char,
    _off: i64,
    count: usize,
) -> isize {
    BIN_WRITES.fetch_add(1, Ordering::AcqRel);
    BIN_WRITTEN_LEN.store(count as u32, Ordering::Release);
    assert!(!input.is_null());
    count as isize
}

unsafe extern "C" fn release(_item: *mut ConfigItem) {
    RELEASES.fetch_add(1, Ordering::AcqRel);
}

unsafe extern "C" fn active_release(_item: *mut ConfigItem) {
    ACTIVE_RELEASES.fetch_add(1, Ordering::AcqRel);
}

unsafe extern "C" fn allow_link(_parent: *mut ConfigItem, _target: *mut ConfigItem) -> i32 {
    LINKS.fetch_add(1, Ordering::AcqRel);
    0
}

unsafe extern "C" fn drop_link(_parent: *mut ConfigItem, _target: *mut ConfigItem) -> i32 {
    LINKS.fetch_add(1, Ordering::AcqRel);
    0
}

unsafe extern "C" fn make_group(_parent: *mut ConfigGroup, _name: *const c_char) -> *mut ConfigGroup {
    MAKE_GROUPS.fetch_add(1, Ordering::AcqRel);
    MADE_GROUP.load(Ordering::Acquire) as *mut ConfigGroup
}

unsafe extern "C" fn drop_item(_parent: *mut ConfigGroup, _item: *mut ConfigItem) {
    DROP_ITEMS.fetch_add(1, Ordering::AcqRel);
}

#[test]
fn export_symbols_registers_configfs_surface() {
    let _serial = TEST_SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    export_symbols();
    assert!(crate::is_exported("configfs_register_subsystem"));
    assert!(crate::is_exported("configfs_unregister_group"));
    assert!(crate::is_exported("config_item_set_name"));
    assert!(crate::is_exported("config_item_get_unless_zero"));
    assert!(crate::is_exported("configfs_depend_item"));
    assert!(crate::is_exported("configfs_create_link"));
}

#[test]
fn subsystem_registers_attrs_in_config_root() {
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

#[test]
fn config_item_set_name_and_get_unless_zero_work() {
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

#[test]
fn attr_open_pins_active_operation_until_unregister_marks_dead() {
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
