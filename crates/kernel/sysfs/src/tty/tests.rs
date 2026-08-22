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

/// `/sys/class/tty/console/active` reports EVERY registered console, preferred
/// last — not the VT alone. `systemd-getty-generator` reads this file and
/// starts `serial-getty@<name>` for each non-VC entry; while it read `tty0`
/// this kernel could not have a serial login prompt, whatever the boot line
/// said. The hosted line is empty, which is the arch default pair.
#[test]
fn console_active_reports_every_registered_console() {
    let root = make_sys_devices_virtual_tty_inode();
    let dir = root.lookup("console").expect("console device dir");
    let active = dir.lookup("active").expect("console/active attr");
    let mut buf = [0u8; 32];
    let n = active.read(0, &mut buf).expect("read active");
    assert_eq!(&buf[..n], b"ttyS0 tty0\n");
}

/// Every reported name is a tty this kernel publishes a device node for: a
/// getty generated from a name with no node dies on `No such file or
/// directory`. The aarch64 PL011 is published as `ttyS0`, so the reported name
/// is the NODE's, not the `console=` class name (`ttyAMA0`).
#[test]
fn every_reported_console_names_a_published_tty() {
    let root = make_sys_devices_virtual_tty_inode();
    let dir = root.lookup("console").expect("console device dir");
    let active = dir.lookup("active").expect("console/active attr");
    let mut buf = [0u8; 32];
    let n = active.read(0, &mut buf).expect("read active");
    let body = core::str::from_utf8(&buf[..n]).expect("utf8").trim_end();
    assert!(!body.is_empty(), "console/active must never be empty");
    for name in body.split(' ') {
        assert!(tty_dev(name).is_some(), "reported console {name} has no tty device node");
    }
}

/// The name each console class is reported under. `tty0` stays literal because
/// consumers match on it; the serial line takes the published node name.
#[test]
fn console_line_names_match_the_published_nodes() {
    assert_eq!(console_line_name(cmdline::ConsoleKind::Serial), "ttyS0");
    assert_eq!(console_line_name(cmdline::ConsoleKind::Vt(0)), "tty0");
    assert_eq!(console_line_name(cmdline::ConsoleKind::Vt(3)), "tty3");
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

/// Every numbered VT published in `/dev` also appears in the tty class and
/// reports the matching Linux `4:N` device number. The class symlink and the
/// virtual-device directory are separate production lookup paths.
#[test]
fn numbered_vts_are_published_in_both_tty_trees() {
    let class = make_sys_class_tty_inode();
    let devices = make_sys_devices_virtual_tty_inode();

    struct Names(Vec<String>);
    impl vfs::DirEmit for Names {
        fn emit(&mut self, name: &str, _ino: u64, _d: FileType, _next: u64) -> bool {
            self.0.push(String::from(name));
            true
        }
    }
    fn listed(dir: &InodeRef) -> Vec<String> {
        let mut names = Names(Vec::new());
        let mut ctx = DirContext::new(0, &mut names);
        dir.readdir(&mut ctx).expect("list tty directory");
        names.0
    }
    let class_names = listed(&class);
    let device_names = listed(&devices);

    for vt in 1..=tty::N_VT {
        let name = alloc::format!("tty{vt}");
        assert!(class_names.iter().any(|listed| listed == &name));
        assert!(device_names.iter().any(|listed| listed == &name));
        class.lookup(&name).expect("numbered VT class symlink");
        let dir = devices.lookup(&name).expect("numbered VT device directory");
        let dev = dir.lookup("dev").expect("numbered VT dev attribute");
        let mut buf = [0u8; 16];
        let n = dev.read(0, &mut buf).expect("read numbered VT dev attribute");
        assert_eq!(&buf[..n], alloc::format!("4:{vt}\n").as_bytes());
    }

    let past_last = alloc::format!("tty{}", tty::N_VT + 1);
    assert!(class.lookup(&past_last).is_err());
    assert!(devices.lookup(&past_last).is_err());
}
