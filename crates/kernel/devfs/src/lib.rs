// Devfs registry surface per `52§3` domain layer.
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
pub mod tree;

use alloc::string::String;

use vfs::InodeRef;

/// devtmpfs filesystem identity for stat(2) `st_dev`.
pub const DEVFS_FSID: u64 = 0x0102_1994_0000_0001;

/// Register `path` → `inode` in the init namespace (`ns == 0`).
/// Used by the boot bootstrap; takes a `'static` path so we don't

// Current-task context hooks (mount-ns + chroot root). devfs is a
// filesystem; it must not depend on the scheduler — the kernel installs
// these at boot so device visibility/chroot resolve against the running
// task without a devfs->sched edge (which would cycle cgroup->devfs->sched).
use core::sync::atomic::{AtomicU64, Ordering as HookOrdering};
static MOUNT_NS_HOOK: AtomicU64 = AtomicU64::new(0);
static CHROOT_ROOT_HOOK: AtomicU64 = AtomicU64::new(0);

/// Install the current-task context hooks (boot, once).
/// # C: O(1)
pub fn set_current_hooks(mount_ns: fn() -> u64, chroot_root: fn() -> Option<String>) {
    MOUNT_NS_HOOK.store(mount_ns as usize as u64, HookOrdering::Release);
    CHROOT_ROOT_HOOK.store(chroot_root as usize as u64, HookOrdering::Release);
}
fn current_mount_ns() -> u64 {
    let p = MOUNT_NS_HOOK.load(HookOrdering::Acquire);
    if p == 0 { return 0; }
    // SAFETY: p was stored from a `fn() -> u64` via set_current_hooks.
    let f: fn() -> u64 = unsafe { core::mem::transmute(p as usize) };
    f()
}
fn current_chroot_root() -> Option<String> {
    let p = CHROOT_ROOT_HOOK.load(HookOrdering::Acquire);
    if p == 0 { return None; }
    // SAFETY: p was stored from a `fn() -> Option<String>` via set_current_hooks.
    let f: fn() -> Option<String> = unsafe { core::mem::transmute(p as usize) };
    f()
}

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

/// Look up a path. Tries caller's mount_ns first, then init NS.
/// Applies the chroot prefix (F95) before matching.
/// # C: O(depth)
pub fn lookup(path: &str) -> Option<InodeRef> {
    let resolved = chroot_resolve(path);
    let cur_ns = current_mount_ns();
    let r = if cur_ns != 0 {
        tree::lookup(cur_ns, &resolved).or_else(|| tree::lookup(0, &resolved))
    } else {
        tree::lookup(0, &resolved)
    };
    // DIAG (debug-boot): the 226/NAMESPACE blocker — does a sandbox lookup of
    // /proc/sys/kernel/domainname get chroot-prefixed so the registered key no
    // longer matches? Log path→resolved + ns + hit so we see the mangling.
    #[cfg(feature = "debug-boot")]
    if path.contains("domainname") {
        klog::write_raw(b"[mnt] DEVLK ns="); klog::write_dec_u64(cur_ns);
        klog::write_raw(if r.is_some() { b" HIT in=" } else { b" MISS in=" });
        klog::write_raw(path.as_bytes());
        klog::write_raw(b" resolved="); klog::write_raw(resolved.as_bytes());
        klog::write_raw(b"\n");
    }
    r
}

/// Like `lookup` but WITHOUT chroot translation, for a filesystem (procfs/
/// sysfs) resolving its OWN mount content. The path is already mount-absolute
/// (e.g. `/proc/sys/kernel/domainname`), reached via the mount itself, so
/// applying `chroot_resolve` would wrongly re-prefix it with the caller's
/// chroot root and break sandbox resolution (status 226/NAMESPACE). Linux's
/// proc_sys_lookup is chroot-independent for the same reason.
/// # C: O(components)
pub fn lookup_no_chroot(path: &str) -> Option<InodeRef> {
    let cur_ns = current_mount_ns();
    if cur_ns != 0 {
        if let Some(i) = tree::lookup(cur_ns, path) { return Some(i); }
    }
    tree::lookup(0, path)
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
pub fn snapshot_ns(src_ns: u64, dst_ns: u64) {
    tree::snapshot_ns(src_ns, dst_ns);
}

/// Apply the calling task's chroot root to an absolute path.
/// Relative paths and boot-context calls (no current task) pass
/// through unchanged.
/// # C: O(len)
fn chroot_resolve(path: &str) -> String {
    if path.as_bytes().first() != Some(&b'/') { return String::from(path); }
    let root = match current_chroot_root() { Some(r) => r, None => return String::from(path) };
    let mut out = root;
    if out.ends_with('/') { out.pop(); }
    out.push_str(path);
    out
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
    fn magic(&self) -> u64 { 0x0102_1994 }
    /// # C: O(N_devfs_entries)
    fn lookup(&self, path: &str) -> Option<vfs::InodeRef> { lookup(path) }
}

/// Singleton accessor for the mount-table to register.
/// # C: O(1)
pub fn instance() -> &'static dyn vfs::fs::FileSystem { &DevfsFs }
