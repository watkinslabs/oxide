use super::*;

/// `/sys/class/tty/tty0/active` reports the live foreground VT as `ttyN`, and a
/// `0` reading clamps up to the boot VT `tty1` (Linux `max(1)` semantics). Both
/// checks live in ONE test: they mutate the shared `ACTIVE_VT_HOOK` static, so
/// splitting them would race under the parallel test runner.
#[test]
fn tty0_active_reports_foreground_vt() {
    let root = make_sys_devices_virtual_tty_inode();
    let dir = root.lookup("tty0").expect("tty0 device dir");

    set_active_vt_hook(|| 3);
    let active = dir.lookup("active").expect("tty0/active attr");
    let mut buf = [0u8; 16];
    let n = active.read(0, &mut buf).expect("read active");
    assert_eq!(&buf[..n], b"tty3\n");

    set_active_vt_hook(|| 0);
    let active = dir.lookup("active").expect("tty0/active attr");
    let n = active.read(0, &mut buf).expect("read active");
    assert_eq!(&buf[..n], b"tty1\n");

    assert_eq!(active.poll(), vfs::POLL_IN);

    let file = vfs::File::new(active.clone(), vfs::Dentry::new_root(active.clone()),
        vfs::OpenFlags::O_RDONLY);
    TtyActiveFileOps.on_open_file(&file).expect("open active");
    assert_eq!(file.poll(), vfs::POLL_IN);
    notify_active_vt();
    assert_eq!(file.poll(), vfs::POLL_IN | vfs::POLL_PRI | vfs::POLL_ERR);
    assert_eq!(file.poll(), vfs::POLL_IN | vfs::POLL_PRI | vfs::POLL_ERR);
    let n = file.read(&mut buf).expect("read changed active");
    assert_eq!(&buf[..n], b"tty1\n");
    assert_eq!(file.poll(), vfs::POLL_IN);
}

/// `/sys/class/tty/console/active` reports the VT console master `tty0`.
#[test]
fn console_active_reports_vt_console_master() {
    let root = make_sys_devices_virtual_tty_inode();
    let dir = root.lookup("console").expect("console device dir");
    let active = dir.lookup("active").expect("console/active attr");
    let mut buf = [0u8; 16];
    let n = active.read(0, &mut buf).expect("read active");
    assert_eq!(&buf[..n], b"tty0\n");
}

/// Ordinary ttys (e.g. `ttyS0`) expose no `active` attribute — matching Linux,
/// where only `tty0`/`console` register `dev_attr_active`.
#[test]
fn serial_tty_has_no_active_attr() {
    assert!(!tty_has_active("ttyS0"));
    let root = make_sys_devices_virtual_tty_inode();
    let dir = root.lookup("ttyS0").expect("ttyS0 device dir");
    assert!(dir.lookup("active").is_err());
    assert_eq!(tty_dev_attrs("ttyS0"), &["dev", "uevent"]);
}

/// `tty0`/`console` list `active` alongside `dev`/`uevent` in the dir. # C: n/a
#[test]
fn active_devices_advertise_active_attr() {
    assert!(tty_has_active("tty0"));
    assert!(tty_has_active("console"));
    assert_eq!(tty_dev_attrs("tty0"), &["active", "dev", "uevent"]);
    assert_eq!(tty_dev_attrs("console"), &["active", "dev", "uevent"]);
}

#[test]
fn tty_devices_expose_subsystem_symlink() {
    let root = make_sys_devices_virtual_tty_inode();
    let dir = root.lookup("ttyS0").expect("ttyS0 device dir");
    let link = dir.lookup("subsystem").expect("subsystem symlink");
    assert_eq!(link.readlink().expect("readlink"), b"../../../../class/tty".to_vec());
}
