//! show_options: `FileSystem::show_options()` is the per-instance
//! `super_operations::show_options` (Linux `fs/*/super.c`). The VFS renders the
//! generic per-mount flags (`rw,relatime`) for `/proc/mounts`; this hook APPENDS
//! the backend's own options (tmpfs `size=`/`mode=`, ext4 `data=`, cgroup2
//! controller list). Each option carries its own leading comma, concatenated
//! directly after the generic flags. The default `mounts_line` composes the two
//! so a backend overrides `show_options` ONLY — never the whole `<src> <mnt>
//! <fstype> … 0 0` framing.

use vfs::fs::FileSystem;
use vfs::{FileType, InodeBuilder, InodeRef, default_file_ops, default_inode_ops, mk_mode};

fn tdir() -> InodeRef {
    InodeBuilder::new(1, mk_mode(FileType::Directory, 0), default_inode_ops(), default_file_ops()).build()
}

/// A backend with no `show_options` override ⇒ no fs-specific options.
struct PlainFs;
impl FileSystem for PlainFs {
    fn name(&self) -> &str { "ext4" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
}

/// A tmpfs-shaped backend that publishes `size=`/`nr_inodes=`/`mode=` like
/// Linux `shmem_show_options` — each option comma-prefixed.
struct TmpFs;
impl FileSystem for TmpFs {
    fn name(&self) -> &str { "tmpfs" }
    fn root(&self) -> Option<InodeRef> { Some(tdir()) }
    fn show_options(&self) -> String {
        String::from(",size=10240k,nr_inodes=2560,mode=755")
    }
}

#[test]
fn default_show_options_is_empty() {
    // No override ⇒ no fs-specific tail; the generic flags stand alone.
    assert_eq!(PlainFs.show_options(), "");
}

#[test]
fn mounts_line_with_no_options_is_generic_flags_only() {
    // Byte-identical to the pre-hook default — no regression for plain backends.
    assert_eq!(PlainFs.mounts_line("/"), "ext4 / ext4 rw,relatime 0 0\n");
}

#[test]
fn mounts_line_appends_show_options_after_generic_flags() {
    // The fs-specific options concatenate directly after `rw,relatime`, before
    // the ` 0 0` dump/pass fields — exactly where Linux's show_options emits.
    assert_eq!(
        TmpFs.mounts_line("/run"),
        "tmpfs /run tmpfs rw,relatime,size=10240k,nr_inodes=2560,mode=755 0 0\n",
    );
}

#[test]
fn options_sit_before_dump_pass_fields() {
    // Guard the framing: the trailing ` 0 0\n` must survive the appended tail,
    // and the procfs ro-swap anchor ` rw,` must still be present & first.
    let line = TmpFs.mounts_line("/dev/shm");
    assert!(line.ends_with(" 0 0\n"), "dump/pass fields preserved after options");
    assert_eq!(line.find(" rw,"), Some(line.find(" tmpfs ").unwrap() + " tmpfs".len()),
        "leading ` rw,` ro-swap anchor stays first in the opts field");
}
