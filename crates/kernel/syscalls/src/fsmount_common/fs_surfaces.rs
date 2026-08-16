#![cfg(target_os = "oxide-kernel")]

//! Where each filesystem's `/proc/fs` and `/sys/fs` surfaces are published.
//!
//! The filesystems describe their entries as data and never name a
//! pseudo-filesystem type; the trees host entries and never name a
//! filesystem's. This module is the one place that holds both, which is what
//! keeps that separation from being a fiction — and it is the mount path,
//! which is where the reference publishes a superblock's half too.
//!
//! Withdrawal is left behind here on the way in, because unmount arrives at a
//! filesystem's own superblock operations and those cannot name a tree either.

use alloc::sync::Arc;

/// Publish one f2fs mount's `/proc/fs/f2fs/<dev>` and `/sys/fs/f2fs/<dev>`
/// surfaces.
///
/// The reference claims the two subsystem directories in its module init and
/// publishes the per-mount half when the superblock is registered. There is no
/// module init here, so the claim happens once, on the first mount.
/// # C: O(attributes)
pub(crate) fn f2fs_publish_surfaces(fs: &Arc<f2fs::F2fs>) {
    use f2fs::{procfs as f2p, sysfs as f2s};
    if !sysfs::fs_subsys::is_claimed(f2s::SUBSYS) {
        let _ = sysfs::fs_subsys::claim(f2s::SUBSYS);
        for d in f2s::GLOBAL_DIRS { let _ = sysfs::fs_subsys::publish_dir(f2s::SUBSYS, d); }
        for a in f2s::global_attrs() {
            let _ = sysfs::fs_subsys::publish_attr(f2s::SUBSYS, &a.dir, a.name, a.mode,
                                                   a.show, a.store);
        }
    }
    if !procfs::fs_dir::is_claimed(f2p::FS_NAME) {
        let _ = procfs::fs_dir::claim(f2p::FS_NAME);
        // The status report is ONE file describing every mount, so it is
        // claimed with the subsystem rather than per mount.
        tracefs::register_debug_show(f2fs::stats::STATUS_PATH, f2fs::fsattr::RO,
                                     f2fs::stats::status_show());
    }
    f2fs::fsattr::set_teardown(f2fs_withdraw_surfaces);
    for a in f2s::mount_attrs(fs) {
        let _ = sysfs::fs_subsys::publish_attr(f2s::SUBSYS, &a.dir, a.name, a.mode,
                                               a.show, a.store);
    }
    for f in f2p::mount_files(fs) {
        let _ = procfs::fs_dir::publish_file(f2p::FS_NAME, &f.dir, f.name, f.mode, f.show,
                                                 f.store);
    }
    // The counters this mount accumulates are reported through the one status
    // file; the volume lock is taken inside f2fs, so a reader of a debug file
    // never decides how long the filesystem is held.
    let me = Arc::clone(fs);
    f2fs::stats::register(&f2s::mount_dir(fs.source()),
                          Arc::new(move |i: usize| me.render_status(i)));
}

/// Publish one ext4 mount's `/sys/fs/ext4/<dev>` surface.
///
/// Installed as ext4's publisher rather than called from the constructor
/// below, because the constructor is not where every ext4 mount comes from:
/// the ROOT filesystem is mounted while the machine is still coming up, long
/// before this registration runs, and it is the one filesystem whose reports
/// somebody is certain to read. The filesystem announces every mount to
/// whatever publisher is installed, and installing one here publishes the
/// mounts that arrived first as well.
/// # C: O(attributes)
pub(crate) fn ext4_publish_surfaces(st: &Arc<ext4::rootfs::RootfsState>) {
    use ext4::sysfs as e4s;
    if !sysfs::fs_subsys::is_claimed(e4s::SUBSYS) {
        let _ = sysfs::fs_subsys::claim(e4s::SUBSYS);
        for d in e4s::GLOBAL_DIRS { let _ = sysfs::fs_subsys::publish_dir(e4s::SUBSYS, d); }
        for a in e4s::global_attrs() {
            let _ = sysfs::fs_subsys::publish_attr(e4s::SUBSYS, &a.dir, a.name, a.mode,
                                                   a.show, None);
        }
    }
    for a in e4s::mount_attrs(st) {
        let _ = sysfs::fs_subsys::publish_attr(e4s::SUBSYS, &a.dir, a.name, a.mode, a.show, None);
    }
}

/// Withdraw one ext4 mount's surface at unmount. # C: O(attributes)
fn ext4_withdraw_surfaces(dev: &str) {
    let _ = sysfs::fs_subsys::withdraw(ext4::sysfs::SUBSYS, dev);
}

/// Publish one ntfs3 mount's `/proc/fs/ntfs3/<dev>/` files.
///
/// `/proc` and not `/sys` because that is where this filesystem's reports are:
/// `volinfo` is a table of seven values read positionally, which is not what a
/// sysfs attribute is, and `label` is a control read and written as text.
/// # C: O(1)
pub(crate) fn ntfs3_publish_surfaces(fs: &Arc<ntfs3::NtfsFs>) {
    use ntfs3::procfs as n3p;
    if !procfs::fs_dir::is_claimed(n3p::FS_NAME) { let _ = procfs::fs_dir::claim(n3p::FS_NAME); }
    ntfs3::fsattr::set_teardown(ntfs3_withdraw_surfaces);
    for f in n3p::mount_files(fs) {
        let _ = procfs::fs_dir::publish_file(n3p::FS_NAME, &f.dir, f.name, f.mode, f.show, f.store);
    }
}

/// Withdraw one ntfs3 mount's files at unmount. # C: O(files)
fn ntfs3_withdraw_surfaces(dev: &str) {
    let _ = procfs::fs_dir::withdraw(ntfs3::procfs::FS_NAME, dev);
}

/// Claim `/sys/fs/9p`.
///
/// The directory and nothing in it, which is what the reference has in this
/// configuration: it creates the object unconditionally as the filesystem
/// registers, and the one attribute under it — the list of cache volumes the
/// live sessions are using — exists only where a persistent cache is
/// compiled in. There is no such cache here, so a `caches` file would list
/// names for caches that do not exist. The empty directory says the
/// filesystem is present and has no cache surface; an absent one would say
/// the filesystem is not here at all.
/// # C: O(1)
pub(crate) fn ninep_claim_subsys() {
    let name = ::fs::ninep_fs::NINEP_FS_NAME;
    if !sysfs::fs_subsys::is_claimed(name) { let _ = sysfs::fs_subsys::claim(name); }
}

/// Withdraw one mount's surfaces at unmount: they report on a volume that no
/// longer exists. # C: O(attributes)
fn f2fs_withdraw_surfaces(dev: &str) {
    let _ = sysfs::fs_subsys::withdraw(f2fs::sysfs::SUBSYS, dev);
    let _ = procfs::fs_dir::withdraw(f2fs::procfs::FS_NAME, dev);
    f2fs::stats::unregister(dev);
}

/// Install ext4's publisher and its withdrawal, and publish whatever mounted
/// before this point. # C: O(pending mounts × attributes)
pub(crate) fn install_ext4_publisher() {
    ext4::surfaces::set_withdraw(ext4_withdraw_surfaces);
    ext4::surfaces::set_publisher(ext4_publish_surfaces);
}
