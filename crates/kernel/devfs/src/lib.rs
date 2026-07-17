// Devfs registry surface per `52§3` domain layer.
//
// DEVFS-PRIVATE (D1d): this table holds ONLY devfs's own `/dev` devtmpfs
// nodes + the `/etc` overlay. It is no longer a shared cross-filesystem path
// bus — procfs (`/proc`, see `procfs::reg`) and sysfs (`/sys`, see
// `sysfs::root`) own their OWN `kernfs::PseudoDir` roots. The remaining
// `register*`/`lookup*` callers are device drivers (`/dev/*`) + the `/etc`
// boot overlay; `snapshot_ns`/`unregister_subtree` serve mount-namespace
// `/dev` (CLONE_NEWNS / umount2).
//
// Owns the namespace-aware (`ns`, `path`) → `InodeRef` table that
// `register*` writes and `lookup` reads. The boot-time bootstrap
// (`devfs::init`) that POPULATES this table with /dev/console,
// /dev/tty*, /dev/null, /dev/zero, /dev/random, etc. lives in
// `kernel/src/devfs.rs` because it pulls together the kernel-side
// device implementations (ConsoleInode, NullInode, ZeroInode, …).
// `PrefixDirInode` (synthetic directory walker) likewise stays in
// `kernel/src/devfs.rs` because its `readdir` overlays ext4 entries
// via `crate::dev_ext4::read_dir` — moving that into a hook in this
// crate is future cleanup.
//
// `read_user_cstr` rides here because every kernel module that
// resolves a user path through `crate::devfs::read_user_cstr` would
// otherwise have to duplicate the bounded-strlen + USER_VA_END
// check — keeping the helper colocated with the registry it serves
// avoids that.

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

extern crate alloc;
pub mod boot;
pub mod uapi;
mod tree;

use alloc::string::String;

use vfs::InodeRef;

/// devtmpfs filesystem identity for stat(2) `st_dev`.
pub const DEVFS_FSID: u64 = 0x0102_1994_0000_0001;

/// Register `path` → `inode` in the init namespace (`ns == 0`).
/// Used by the boot bootstrap; takes a `'static` path so we don't

// Current-task mount-namespace hook. devfs is a filesystem; it must not
// depend on the scheduler — the kernel installs this at boot so device
// visibility resolves against the running task's mount namespace without a
// devfs->sched edge (which would cycle cgroup->devfs->sched). chroot is NOT
// resolved here: namei owns confined-root resolution (`pathresolve::
// resolution_root` / `root_dentry`), so by the time a path reaches this
// registry it is already mount-relative — the old string-prefix
// `chroot_resolve` (D18) was an abstraction inversion and is gone.
use core::sync::atomic::Ordering as HookOrdering;

/// Install the current-task context hook (boot, once). `_chroot_root` is
/// accepted for boot-wiring compatibility but ignored — chroot is namei's
/// job (see module note), not the devfs registry's.
/// # C: O(1)
pub fn set_current_hooks(_mount_ns: fn() -> u64, _chroot_root: fn() -> Option<String>) {}

/// clone for the common case.
/// # C: O(depth)
pub fn register(path: &'static str, inode: InodeRef) {
    tree::register(0, path, inode);
}

/// Create an empty directory chain (mount points without registered leaves).
/// # C: O(components)
pub fn register_dir(path: &str) {
    tree::register_dir(0, path);
}

/// Same as `register` but accepts an owned `String`. Used by
/// runtime mounts and overlay creation.
/// # C: O(depth)
pub fn register_owned(path: String, inode: InodeRef) {
    tree::register(0, &path, inode);
}

/// Register `path` in a specific namespace `ns`. Mount-namespace
/// fork support per `27`.
/// # C: O(depth)
pub fn register_in_ns(ns: u64, path: String, inode: InodeRef) {
    tree::register(ns, &path, inode);
}

/// Look up a mount-absolute path in the devfs registry. Tries the caller's
/// mount namespace first, then the init NS. The path is already mount-relative
/// (namei resolved any chroot/confined-root before reaching here, D18), so no
/// string-prefix translation is applied.
/// # C: O(depth)
fn lookup(path: &str) -> Option<InodeRef> {
    let namespace = vfs::mount::current_namespace();
    let cur_ns = namespace.id();
    if cur_ns != 0 {
        if let Some(i) = tree::lookup(cur_ns, path) { return Some(i); }
    }
    tree::lookup(0, path)
}

/// `/dev`-node factory carried by the drv `DEVTMPFS_HOOK` (structurally
/// identical to `drv::NodeFactory`, so the two coerce when kmain wires
/// `add_device_node` as the hook). # C: O(1)
pub type NodeFactory = alloc::sync::Arc<dyn Fn() -> InodeRef + Send + Sync>;

/// Monotonic inode-number source for `device_add`-minted `/dev` nodes. High
/// base avoids collision with the boot pseudo-device inos (`0x2000_00xx`).
static DEVNODE_INO: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0x3000_0000);

/// Mint a `/dev` node for a `drv::try_device_add` device (the `DEVTMPFS_HOOK`
/// target). `name` is the `/dev`-relative path (`"vda"`, `"input/event0"`); the
/// node lands at `/dev/<name>`. With a `factory` the device supplies its own
/// inode (bespoke `FileOps`); otherwise a plain char/block node is synthesised
/// from `dev_t` (`class == "block"` ⇒ block, else char), dispatching `open`/I/O
/// through the `vfs::devnode` `(major,minor)` registry exactly like `mknod(2)`.
/// No `dev_t` and no factory ⇒ nothing created. # C: O(depth)
pub fn add_device_node(class: &str, name: &str, dev_t: Option<(u32, u32)>, factory: Option<NodeFactory>) {
    let path = if name.starts_with('/') { String::from(name) } else { alloc::format!("/dev/{}", name) };
    let inode = match factory {
        Some(f) => f(),
        None => match dev_t {
            Some((maj, min)) => {
                let ft = if class == "block" { vfs::FileType::BlockDev } else { vfs::FileType::CharDev };
                let ino = DEVNODE_INO.fetch_add(1, HookOrdering::Relaxed);
                vfs::devnode::make_device_node_inode(
                    ino, ft, vfs::devnode::Devt::new(maj, min), 0o600, alloc::sync::Weak::new())
            }
            None => return, // neither a factory nor a dev_t: nothing to create
        },
    };
    register_owned(path, inode);
}

/// Remove a `device_add`-minted `/dev` node (`device_del` symmetry / hot-unplug).
/// `name` matches the `add_device_node` form. # C: O(depth)
pub fn del_device_node(name: &str) {
    let path = if name.starts_with('/') { String::from(name) } else { alloc::format!("/dev/{}", name) };
    // Broadcast: devtmpfs is one shared instance, so hot-unplug removes the node
    // from every mount namespace's /dev, not just ns0.
    for inode in tree::unregister_subtree_all_inodes(&path) {
        vfs::dcache::d_prune_aliases(&inode);
    }
}

/// Detach the entry at `mount_point` (and its subtree) from `mount_ns`.
/// Linux umount2(2) equivalent. Returns the count removed (0 or 1).
/// # C: O(depth)
pub fn unregister_subtree(ns: u64, mount_point: &str) -> usize {
    tree::unregister_subtree(ns, mount_point)
}

/// Deep-clone the `src_ns` tree into `dst_ns`. Used when a process
/// transitions to a new mount namespace via clone(CLONE_NEWNS) or
/// unshare.
/// # C: O(tree)
pub fn snapshot_ns(src: &vfs::mntns::MntNamespaceRef, dst: &vfs::mntns::MntNamespaceRef) {
    tree::snapshot_ns(src, dst);
}

/// Read a NUL-terminated string from user memory at `ptr`, bounded
/// at `max` bytes. Returns the slice (trimmed of NUL) borrowed
/// against the user page.
/// # SAFETY: ptr in user range; user page mapped; CPL=0 reads pass
/// through user mappings.
/// # C: O(strlen)
pub unsafe fn read_user_cstr<'a>(ptr: u64, max: usize) -> Option<&'a [u8]> {
    if ptr == 0 || ptr >= hal::USER_VA_END { return None; }
    let mut len = 0;
    while len < max {
        // SAFETY: ptr+len < ptr+max ≤ USER_VA_END (caller's responsibility for mapped page); 1-byte read.
        let b = unsafe { core::ptr::read_volatile((ptr + len as u64) as *const u8) };
        if b == 0 { break; }
        len += 1;
    }
    if len == 0 { return Some(&[]); }
    // SAFETY: same range; we've just probed every byte.
    Some(unsafe { core::slice::from_raw_parts(ptr as *const u8, len) })
}


pub mod misc;


/// FileSystem trait impl per `vfs::fs::FileSystem`. devfs is a
/// register-only namespace (no create/unlink); other ops default
/// to Erofs from the trait. Per `52§3` integration layer.
pub struct DevfsFs;

impl vfs::fs::FileSystem for DevfsFs {
    /// # C: O(1)
    fn name(&self) -> &str { "devfs" }
    /// TMPFS_MAGIC — devtmpfs shares the tmpfs superblock magic.
    /// # C: O(1)
    fn magic(&self) -> u64 { vfs::uapi::TMPFS_SUPER_MAGIC }
    /// Mount root = the `/dev` `DevDir` (a real per-component `vfs::Inode`).
    /// The path walk crosses into the devfs mount and resolves every
    /// `/dev/*` component via `DevDir::lookup` — no whole-path lookup.
    /// # C: O(1)
    fn root(&self) -> Option<vfs::InodeRef> { lookup("/dev") }
}

/// Singleton accessor for the mount-table to register.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &DevfsFs }

#[cfg(test)]
mod fs_tests {
    use super::*;
    use alloc::boxed::Box;
    use alloc::sync::Arc;

    /// devtmpfs is a singleton SB-bearing backend: the registered `devtmpfs`
    /// `file_system_type` ctor (mirroring `fsmount_common::register_filesystems`)
    /// realizes a real `DevfsFs` SuperBlock at the converted CMD_CREATE path
    /// (`FsType::mount` == fsconfig get_tree). Closes the devtmpfs half of
    /// superblock D8/D21 — `mount -t devtmpfs` is no longer an admit-noop.
    #[test]
    fn devtmpfs_fstype_realizes_devfs_sb() {
        use vfs::FileSystemType;
        use vfs::fs::{superblock_from_filesystem, FsFlags, FsType};
        // The exact ctor registered for "devtmpfs" in the syscalls crate.
        let ctor = Box::new(|ty, _s: Option<&str>, _t: &str, _d: &str| {
            let fs: Arc<dyn vfs::fs::FileSystem> = Arc::new(DevfsFs);
            superblock_from_filesystem(ty, fs, None, alloc::string::String::from("devtmpfs"))
        });
        let ty = FsType::new("devtmpfs", vfs::uapi::TMPFS_SUPER_MAGIC, FsFlags::empty(), ctor);
        // The realized SuperBlock carries the DevfsFs backend + TMPFS_MAGIC.
        let sb = ty.mount(None, "").expect("devtmpfs realizes a SuperBlock");
        assert_eq!(sb.s_magic, vfs::uapi::TMPFS_SUPER_MAGIC, "devtmpfs SB stamps TMPFS_MAGIC");
        assert_eq!(sb.s_type.name(), "devtmpfs", "SB type is registered file_system_type");
    }

    /// Stage C (D27): `populate_defaults` now self-registers the mem char
    /// devices via `drv::try_device_add`. With the devtmpfs hook wired (as kmain
    /// does at boot), the exact bespoke nodes appear at `/dev/<name>` with the
    /// right `CharDev` type + rdev — byte-identical to the old direct register.
    #[test]
    fn populate_defaults_mints_mem_nodes_via_device_add() {
        drv::set_devtmpfs_hook(add_device_node);
        crate::boot::populate_defaults();
        for (path, rdev) in [
            ("/dev/null", uapi::DEV_MEM_NULL), ("/dev/zero", uapi::DEV_MEM_ZERO), ("/dev/full", uapi::DEV_MEM_FULL),
            ("/dev/kmsg", uapi::DEV_MEM_KMSG), ("/dev/random", uapi::DEV_MEM_RANDOM), ("/dev/urandom", uapi::DEV_MEM_URANDOM),
            ("/dev/autofs", uapi::DEV_MISC_AUTOFS),
        ] {
            let i = lookup(path).unwrap_or_else(|| panic!("{} minted", path));
            assert_eq!(i.file_type(), vfs::FileType::CharDev, "{} is a char device", path);
            assert_eq!(i.rdev(), rdev, "{} carries its Linux rdev", path);
        }
    }

    #[test]
    fn try_populate_defaults_is_idempotent_for_existing_pseudo_devices() {
        drv::set_devtmpfs_hook(add_device_node);

        assert_eq!(crate::boot::try_populate_defaults(), Ok(()));
        assert_eq!(tree::unregister_subtree(0, "/dev/null"), 1);
        assert!(lookup("/dev/null").is_none(), "test removed only the devfs view");
        assert_eq!(crate::boot::try_populate_defaults(), Ok(()));
        assert!(lookup("/dev/null").is_some(), "existing device must republish a missing node");
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "mem" && d.addr == "null")
                .count(),
            1
        );
    }

    #[test]
    fn try_populate_defaults_reports_conflicting_pseudo_device() {
        drv::set_devtmpfs_hook(add_device_node);
        for dev in drv::devices()
            .into_iter()
            .filter(|d| d.bus == "mem" && d.addr == "null")
        {
            drv::device_del(&dev);
        }
        let conflict = drv::try_device_add(Arc::new(
            drv::Device::new("mem", String::from("null"), 0, 0, 0)
                .with_devnode("mem", String::from("null"), Some((1, 99))),
        ))
        .expect("conflict device registration");

        assert_eq!(crate::boot::try_populate_defaults(), Err(drv::Error::Busy));
        assert_eq!(
            drv::devices()
                .iter()
                .filter(|d| d.bus == "mem" && d.addr == "null")
                .count(),
            1
        );

        drv::device_del(&conflict);
        assert_eq!(crate::boot::try_populate_defaults(), Ok(()));
    }

    /// D17: with the ext4 overlay-union flipped OFF, the `/dev` listing must
    /// still contain the full expected node set purely from `device_add` + the
    /// boot `register`/`register_dir` sources (the rootfs ships ZERO `/dev`
    /// nodes, so the overlay merged nothing). readdir `/dev` and assert every
    /// devfs-owned node/mountpoint dir is present.
    #[test]
    fn dev_listing_complete_without_overlay() {
        drv::set_devtmpfs_hook(add_device_node);
        crate::boot::populate_defaults();
        // Collect the `/dev` directory listing (overlay is off — no adapter is
        // installed in the hosted test, and the root flag is now false).
        let dev = lookup("/dev").expect("/dev dir exists");
        let mut names: alloc::vec::Vec<alloc::string::String> = alloc::vec::Vec::new();
        struct Collect<'a>(&'a mut alloc::vec::Vec<alloc::string::String>);
        impl<'a> vfs::DirEmit for Collect<'a> {
            fn emit(&mut self, name: &str, _ino: u64, _d: vfs::FileType, _next: u64) -> bool {
                self.0.push(alloc::string::String::from(name)); true
            }
        }
        let mut actor = Collect(&mut names);
        let mut ctx = vfs::DirContext::new(0, &mut actor);
        dev.readdir(&mut ctx).expect("readdir /dev");
        // mem/misc char devices + kmsg (device_add), the std fd symlinks
        // (register), and the mount-point dirs (register_dir).
        for want in ["null", "zero", "full", "kmsg", "random", "urandom", "autofs",
                     "stdin", "stdout", "stderr", "fd", "shm", "mqueue", "pts"] {
            assert!(names.iter().any(|n| n == want), "/dev/{} present, got {:?}", want, names);
        }
    }

    /// Stage B: the `DEVTMPFS_HOOK` target mints `/dev/<name>` for both a
    /// `dev_t`-synthesised block node and a factory-supplied bespoke node.
    #[test]
    fn add_device_node_creates_dev_entries() {
        // dev_t path (block class → block device node).
        add_device_node("block", "vdtest0", Some((254, 0)), None);
        assert!(lookup("/dev/vdtest0").is_some(), "dev_t block node minted at /dev/vdtest0");
        // factory path (bespoke inode, custom FileOps).
        let f: NodeFactory = Arc::new(|| crate::misc::make_null_inode());
        add_device_node("mem", "nulltest", None, Some(f));
        assert!(lookup("/dev/nulltest").is_some(), "factory node minted at /dev/nulltest");
        // no dev_t + no factory ⇒ no node.
        add_device_node("misc", "nothing", None, None);
        assert!(lookup("/dev/nothing").is_none(), "no source ⇒ no node");
        // del removes it.
        del_device_node("vdtest0");
        assert!(lookup("/dev/vdtest0").is_none(), "del_device_node removes the node");
    }
}
