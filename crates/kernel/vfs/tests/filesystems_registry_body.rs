//! `/proc/filesystems` and `sysfs(2)` read ONE list.
//!
//! The proc body used to be a hardcoded blob that advertised types the kernel
//! could not mount (`cgroup`, `pipefs`, `ext2`, `vfat`, …) and hid ones it
//! could (`ramfs`, `debugfs`, `fuse`, …). That is a split source of truth
//! against the registry `mount(2)` resolves through and against the list
//! `sysfs(2)` indexes: a probe that reads the file and then mounts gets a
//! different answer from each. `vfs::fs::filesystems_proc_body` renders the
//! live registry, so the two agree by construction.
//!
//! Line format mirrors `regen_filesystems_string`:
//! `"%s\t%s\n"` with an EMPTY prefix for `FS_REQUIRES_DEV` and `nodev`
//! otherwise, in registration order.

use alloc_free::*;
mod alloc_free { pub use std::string::String; pub use std::sync::Arc; }
use std::sync::Mutex;

use vfs::fs::{FsFlags, FsType, filesystems_proc_body, register_fs, registered_filesystems,
    unregister_fs};
use vfs::VfsError;

// Names carry a test-unique suffix: the registry is a process-global static and
// the hosted suite runs tests concurrently, so a generic "ext4" would collide
// with another test's registration and with the boot set.
const NODEV_NAME: &str = "t756nodev";
const DEV_NAME:   &str = "t756devfs";
static TEST_LOCK: Mutex<()> = Mutex::new(());

fn ctor(_ty: Arc<dyn vfs::FileSystemType>, _s: Option<&str>, _t: &str, _d: &str, _sb_flags: u64,
    _p: &[vfs::fs::FsParameter])
    -> Result<Arc<vfs::SuperBlock>, VfsError>
{
    Err(VfsError::Einval)
}

fn line_for(body: &str, name: &str) -> Option<String> {
    body.lines().find(|l| l.ends_with(name)).map(String::from)
}

/// The rendered body carries one line per registered type with the Linux
/// `nodev`/tab shape, and `FS_REQUIRES_DEV` is what drives the prefix.
#[test]
fn body_renders_the_live_registry_in_linux_shape() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    register_fs(FsType::new(NODEV_NAME, 0, FsFlags::empty(), Box::new(ctor))).expect("register nodev");
    register_fs(FsType::new(DEV_NAME, 0, FsFlags::FS_REQUIRES_DEV, Box::new(ctor))).expect("register dev");

    let body = filesystems_proc_body();
    let body = core::str::from_utf8(&body).expect("proc body is ASCII");

    assert_eq!(line_for(body, NODEV_NAME).as_deref(), Some(&*std::format!("nodev\t{NODEV_NAME}")),
        "a nodev fs gets the `nodev` prefix");
    assert_eq!(line_for(body, DEV_NAME).as_deref(), Some(&*std::format!("\t{DEV_NAME}")),
        "FS_REQUIRES_DEV gets an EMPTY prefix, tab only");
    assert!(body.ends_with('\n'), "every line is newline-terminated");

    // The file and the syscall index the same list: one line per registered
    // type, no more and no fewer. A hardcoded body cannot hold this.
    assert_eq!(body.lines().count(), registered_filesystems().len(),
        "one line per registered type — the file and sysfs(2) cannot disagree");

    unregister_fs(NODEV_NAME).expect("cleanup nodev");
    unregister_fs(DEV_NAME).expect("cleanup dev");
}

/// Unregistering a type removes its line: the body tracks the registry rather
/// than a snapshot taken once at boot.
#[test]
fn unregistering_a_type_drops_its_line() {
    let _guard = TEST_LOCK.lock().unwrap_or_else(|poison| poison.into_inner());
    const N: &str = "t756transient";
    register_fs(FsType::new(N, 0, FsFlags::empty(), Box::new(ctor))).expect("register");
    let body = filesystems_proc_body();
    assert!(line_for(core::str::from_utf8(&body).unwrap(), N).is_some(), "present while registered");

    unregister_fs(N).expect("unregister");
    let body = filesystems_proc_body();
    assert!(line_for(core::str::from_utf8(&body).unwrap(), N).is_none(), "gone after unregister");
}
