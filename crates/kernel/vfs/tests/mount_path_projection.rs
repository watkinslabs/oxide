//! Mount path projection for procfs mount reports.

mod common;

#[test]
fn project_path_under_root_keeps_global_root_view() {
    assert_eq!(vfs::mount::project_path_under_root("/proc", None).as_deref(), Some("/proc"));
}

#[test]
fn project_path_under_root_maps_exact_root_to_slash() {
    assert_eq!(vfs::mount::project_path_under_root("/run/systemd/mount-rootfs", Some("/run/systemd/mount-rootfs")).as_deref(), Some("/"));
}

#[test]
fn project_path_under_root_maps_descendant_under_root() {
    assert_eq!(vfs::mount::project_path_under_root(
        "/run/systemd/mount-rootfs/proc/kallsyms",
        Some("/run/systemd/mount-rootfs"),
    ).as_deref(), Some("/proc/kallsyms"));
}

#[test]
fn project_path_under_root_hides_outside_and_prefix_siblings() {
    assert_eq!(vfs::mount::project_path_under_root("/proc", Some("/run/systemd/mount-rootfs")), None);
    assert_eq!(vfs::mount::project_path_under_root("/run/systemd/mount-rootfs2/proc", Some("/run/systemd/mount-rootfs")), None);
}

#[test]
fn mountinfo_root_field_renders_whole_fs_root_as_slash() {
    common::install();
    let root = common::dentry("/proc");
    assert_eq!(vfs::mount::render_mount_root_field(Some(root.clone()), Some(root)).as_str(), "/");
}

#[test]
fn mountinfo_root_field_renders_bind_subroot_relative_to_sb_root() {
    common::install();
    let sb_root = common::dentry("/proc");
    let bind_root = common::dentry("/proc/sys/kernel");
    assert_eq!(
        vfs::mount::render_mount_root_field(Some(bind_root), Some(sb_root)).as_str(),
        "/sys/kernel",
    );
}

#[test]
fn mountinfo_root_field_falls_back_to_absolute_when_root_not_under_sb_root() {
    common::install();
    let sb_root = common::dentry("/proc");
    let bind_root = common::dentry("/sys/kernel");
    assert_eq!(
        vfs::mount::render_mount_root_field(Some(bind_root), Some(sb_root)).as_str(),
        "/sys/kernel",
    );
}
