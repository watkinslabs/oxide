// DVR-0015 (device-node rdev plan) + DVR-0016 (/proc/devices char registry)
// hosted proofs.

use vfs::{chrdev_major_names, default_file_ops, default_inode_ops, mk_mode, proc_devices_char,
          register_chrdev_name, seed_builtin_chrdev_names, Devt, FileType, InodeBuilder};

/// DVR-0016: the char-major name registry is live, deduped, sorted, and the
/// `/proc/devices` char render matches the Linux `%3d %s\n` shape.
#[test]
fn chrdev_name_registry_drives_proc_devices() {
    seed_builtin_chrdev_names();
    register_chrdev_name(226, "drm");
    register_chrdev_name(13, "input");
    register_chrdev_name(29, "fb");
    register_chrdev_name(226, "drm"); // exact-pair dedup

    let names = chrdev_major_names();
    assert!(names.iter().any(|(m, n)| *m == 1 && n == "mem"), "builtin mem seeded");
    assert!(names.iter().any(|(m, n)| *m == 136 && n == "pts"), "builtin pts seeded");
    assert!(names.iter().any(|(m, n)| *m == 226 && n == "drm"), "drm major appears");
    assert!(names.iter().any(|(m, n)| *m == 13 && n == "input"), "input major appears");
    assert!(names.iter().any(|(m, n)| *m == 29 && n == "fb"), "fb major appears");
    assert_eq!(names.iter().filter(|(m, n)| *m == 226 && n == "drm").count(), 1, "deduped");
    // major 5 carries two distinct names (/dev/tty + ptmx) — not major-deduped.
    assert_eq!(names.iter().filter(|(m, _)| *m == 5).count(), 2);
    // sorted by major
    let majors: Vec<u32> = names.iter().map(|(m, _)| *m).collect();
    let mut sorted = majors.clone();
    sorted.sort();
    assert_eq!(majors, sorted, "char majors sorted");

    let txt = proc_devices_char();
    assert!(txt.contains("  1 mem\n"), "render mem");
    assert!(txt.contains(" 13 input\n"), "render input right-justified to 3");
    assert!(txt.contains("226 drm\n"), "render drm");
}

/// DVR-0015: the Linux major/minor plan the driver inodes now wire, and that
/// an inode built with that rdev actually reports it.
#[test]
fn device_node_rdev_plan() {
    // (major, minor) plan: card0, renderD128, event0, fb0.
    for (maj, min) in [(226u32, 0u32), (226, 128), (13, 64), (29, 0)] {
        let d = Devt::new(maj, min);
        assert_eq!(d.major(), maj, "major round-trips");
        assert_eq!(d.minor(), min, "minor round-trips");
        let inode = InodeBuilder::new(7, mk_mode(FileType::CharDev, 0o666),
            default_inode_ops(), default_file_ops()).rdev(d.raw()).build();
        assert_eq!(inode.rdev(), d.raw(), "inode reports the wired rdev");
    }
}
