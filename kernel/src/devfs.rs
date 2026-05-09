// Minimal devfs registry per docs/16 + docs/19. v1 stand-in
// for the full VFS / mount-tree work: a flat `&str → InodeRef`
// table holding the kernel's char devices. `sys_open` looks up
// here. Real VFS (path resolution, dentry cache, multi-mount,
// ext-style filesystems) lands as docs/16 fully wires.
//
// Registered at boot:
//   /dev/console   — kernel console, aliases the foreground VT
//   /dev/tty       — controlling terminal (per-process); v1 routes
//                    to the same ConsoleInode
//   /dev/tty0      — foreground VT alias (real Linux: dynamic; v1: tty1)
//   /dev/tty1..tty6 — distinct VT slots (v1: all share ConsoleInode)
//   /dev/ttyS0     — first serial line (v1: ConsoleInode)
//
// Once distinct VT instances + foreground tracking land, tty0
// resolves dynamically and tty1..6 each carry their own buffer.

#![cfg(target_os = "oxide-kernel")]

use alloc::string::String;
use alloc::sync::Arc;
use alloc::vec::Vec;

use sync::{Spinlock, TaskList as TaskListClass};
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

/// Per-mount-NS path → inode map. F119 / `16§R01`. Each entry is
/// scoped to a mount_ns id; init NS uses id=0. Lookup tries the
/// caller's mount_ns first, then falls back to 0 so init-NS bind
/// mounts and boot-time entries remain visible from every NS unless
/// shadowed.
pub(crate) static REGISTRY: Spinlock<Vec<(u64, String, InodeRef)>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Register a path → inode mapping in the init NS (mount_ns=0).
/// Boot-time uses this. Runtime callers from non-init mount-NS
/// should use `register_in_ns`.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N)
pub fn register(path: &'static str, inode: InodeRef) {
    register_owned(String::from(path), inode);
}

/// Owned-string variant — runtime registration in init NS.
/// # C: O(N)
pub fn register_owned(path: String, inode: InodeRef) {
    register_in_ns(0, path, inode);
}

/// Register `(path, inode)` in the given mount_ns. Idempotent within
/// that NS (last writer wins). Fires the dirent-create hook
/// (`16§R02`) so inotify watches on the parent directory see
/// IN_CREATE with the leaf name.
/// # C: O(N)
pub fn register_in_ns(ns: u64, path: String, inode: InodeRef) {
    let (parent, leaf) = match split_parent_leaf(&path) {
        Some((p, l)) => (alloc::string::String::from(p), alloc::string::String::from(l)),
        None         => (alloc::string::String::new(), alloc::string::String::new()),
    };
    let mut g = REGISTRY.lock();
    if let Some(slot) = g.iter_mut().find(|(n, p, _)| *n == ns && *p == path) {
        slot.2 = inode;
        return;
    }
    g.push((ns, path, inode));
    drop(g);
    if !parent.is_empty() {
        vfs::fire_dirent_create(&parent, &leaf);
    }
}

/// Split `/dev/pts/3` → ("/dev/pts", "3"). Returns None for paths
/// with no parent (e.g. "/" or "").
fn split_parent_leaf(path: &str) -> Option<(&str, &str)> {
    let i = path.rfind('/')?;
    if i == 0 { Some(("/", &path[1..])) }
    else      { Some((&path[..i], &path[i+1..])) }
}

/// Look up a path. Tries caller's mount_ns first, then init NS.
/// Applies the chroot prefix (F95) before matching.
/// # C: O(N)
pub fn lookup(path: &str) -> Option<InodeRef> {
    let resolved = chroot_resolve(path);
    let cur_ns = crate::sched::current()
        .map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire))
        .unwrap_or(0);
    let g = REGISTRY.lock();
    // Caller's NS first.
    if cur_ns != 0 {
        if let Some((_, _, i)) = g.iter().find(|(n, p, _)| *n == cur_ns && p.as_str() == resolved.as_str()) {
            return Some(Arc::clone(i));
        }
    }
    // Init NS fallback.
    g.iter().find(|(n, p, _)| *n == 0 && p.as_str() == resolved.as_str()).map(|(_, _, i)| Arc::clone(i))
}

/// Snapshot every (path, inode) entry in `src_ns` into `dst_ns`.
/// Used by unshare(CLONE_NEWNS) to give a fresh NS the parent's
/// view of the mount tree at unshare time. Per-mount CoW rides v2.
/// # C: O(N)
pub fn snapshot_ns(src_ns: u64, dst_ns: u64) {
    let mut g = REGISTRY.lock();
    let mut adds: Vec<(u64, String, InodeRef)> = Vec::new();
    for (ns, p, i) in g.iter() {
        if *ns == src_ns {
            adds.push((dst_ns, p.clone(), Arc::clone(i)));
        }
    }
    for (ns, p, i) in adds {
        // Insert without dedupe; src_ns shouldn't have duplicates.
        if !g.iter().any(|(n, q, _)| *n == ns && *q == p) {
            g.push((ns, p, i));
        }
    }
}

/// Apply the calling task's chroot root to an absolute path. Relative
/// paths and boot-context calls (no current task) pass through.
/// # C: O(len)
fn chroot_resolve(path: &str) -> alloc::string::String {
    use alloc::string::String;
    if !path.starts_with('/') { return String::from(path); }
    let cur = match crate::sched::current() { Some(c) => c, None => return String::from(path) };
    // SAFETY: task.root single-mutator per `13§5`; running task on this CPU is the sole writer (sys_chroot updates only on the calling task).
    let root = unsafe { (*cur.root.get()).clone() };
    if root == "/" { return String::from(path); }
    let mut out = root;
    if out.ends_with('/') { out.pop(); }
    out.push_str(path);
    out
}

/// Boot-time devfs population per docs/19. Registers the v1
/// console + tty char devices. Re-runnable: subsequent calls are
/// no-ops because re-registration is idempotent.
///
/// `/dev/console`, `/dev/tty`, `/dev/tty0`, and `/dev/ttyS0` all
/// carry vt=0 (foreground alias — resolves to the live VT at
/// every read). `/dev/tty1`..`/dev/tty6` each carry their distinct
/// vt id so processes opening a specific VT see private input
/// streams. v1 routes UART RX exclusively to VT 1; runtime VT
/// switching (Ctrl-Alt-F<n>) rides a follow-up.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(1)
pub fn init() {
    let fg: InodeRef = Arc::new(crate::dev_console::ConsoleInode::new(0));
    register("/dev/console", Arc::clone(&fg));
    register("/dev/tty",     Arc::clone(&fg));
    register("/dev/tty0",    Arc::clone(&fg));
    register("/dev/ttyS0",   fg);
    for vt in 1..=crate::tty::N_VT as u8 {
        let path: &'static str = match vt {
            1 => "/dev/tty1", 2 => "/dev/tty2", 3 => "/dev/tty3",
            4 => "/dev/tty4", 5 => "/dev/tty5", 6 => "/dev/tty6",
            _ => continue,
        };
        let inode: InodeRef = Arc::new(crate::dev_console::ConsoleInode::new(vt));
        register(path, inode);
    }

    // P3-04 misc char devices.
    register("/dev/null",    Arc::new(crate::dev_misc::NullInode)   as InodeRef);
    register("/dev/kmsg",    Arc::new(crate::dev_misc::KmsgInode)   as InodeRef);
    register("/dev/log",     Arc::new(crate::dev_misc::NullInode)   as InodeRef);
    register("/dev/zero",    Arc::new(crate::dev_misc::ZeroInode)   as InodeRef);
    register("/dev/full",    Arc::new(crate::dev_misc::FullInode)   as InodeRef);
    let rand: InodeRef = Arc::new(crate::dev_misc::RandomInode);
    register("/dev/random",  Arc::clone(&rand));
    register("/dev/urandom", rand);

    // Top-level directory inodes synthesised over the registry. Each
    // emits the leaf children under its own prefix. Must come AFTER
    // leaf registration so they are not themselves enumerated as
    // children of `/`.
    register_dir("/",         0x5000_0001);
    register_dir("/dev",      0x5000_0002);
    register_dir("/sys",      0x5000_0003);
    register_dir("/etc",      0x5000_0004);
    register_dir("/bin",      0x5000_0005);
    register_dir("/usr",      0x5000_0006);
    register_dir("/usr/bin",  0x5000_0007);
    register_dir("/proc/sys", 0x5000_0008);
}

fn register_dir(path: &'static str, ino: Ino) {
    register(path, Arc::new(PrefixDirInode { prefix: path, ino }) as InodeRef);
}

/// Synthetic directory inode: emits every registered leaf whose
/// path is `<prefix>/<name>` (single component, no further `/`).
/// `lookup(name)` reverses to `<prefix>/<name>` (or `/<name>` for
/// `prefix == "/"`).
pub struct PrefixDirInode {
    pub prefix: &'static str,
    pub ino:    Ino,
}

impl PrefixDirInode {
    fn build_child_path(&self, name: &str) -> alloc::string::String {
        let mut p = alloc::string::String::with_capacity(self.prefix.len() + 1 + name.len());
        if self.prefix == "/" { p.push('/'); }
        else { p.push_str(self.prefix); p.push('/'); }
        p.push_str(name);
        p
    }
}

impl Inode for PrefixDirInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        let p = self.build_child_path(name);
        lookup(&p).ok_or(VfsError::Enoent)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        // Phase 1: walk the devfs registry for synthetic / overlay
        // children of `self.prefix`. Inode-numbered offsets 1..=R.
        // F119: registry tuple is (ns, path, inode); filter to caller's
        // mount_ns plus init NS (0) for shared boot entries.
        let cur_ns = crate::sched::current()
            .map(|c| c.mount_ns.load(core::sync::atomic::Ordering::Acquire))
            .unwrap_or(0);
        let g = REGISTRY.lock();
        let r_len = g.len() as u64;
        let mut idx = off as usize;
        while idx < g.len() {
            let (ns, path, inode) = &g[idx];
            if (*ns == cur_ns || *ns == 0) {
                if let Some(name) = procfs::paths::child_under(self.prefix, path) {
                    let next = idx as u64 + 1;
                    if !f(next, name, inode.file_type()) {
                        return Ok(next);
                    }
                }
            }
            idx += 1;
        }
        drop(g);
        // Phase 2: overlay ext4 entries for the same prefix. Offsets
        // are R + 1..=R + N_ext4 so getdents64 resumption stays
        // monotonic across the boundary. Names that already showed
        // up via the devfs registry are skipped (devfs wins).
        let mut ext4_seen: u64 = 0;
        let mut stopped = false;
        let mut stop_off: u64 = (idx as u64).max(r_len);
        let _ = crate::dev_ext4::read_dir(self.prefix.as_bytes(), |name_bytes, dt| {
            if stopped { return; }
            ext4_seen += 1;
            // Resume past entries that earlier getdents64 returned.
            if r_len + ext4_seen <= off { return; }
            // Skip if devfs has the same name.
            let name = match core::str::from_utf8(name_bytes) {
                Ok(s) => s, Err(_) => return,
            };
            let child_path = self.build_child_path(name);
            if lookup(&child_path).is_some() { return; }
            let ftype = match dt {
                ext4::dir::DT_DIR => FileType::Directory,
                ext4::dir::DT_LNK => FileType::Symlink,
                ext4::dir::DT_CHR => FileType::CharDev,
                ext4::dir::DT_BLK => FileType::BlockDev,
                _                 => FileType::Regular,
            };
            let next = r_len + ext4_seen;
            if !f(next, name, ftype) { stopped = true; stop_off = next; }
        });
        if stopped { return Ok(stop_off); }
        Ok(r_len + ext4_seen)
    }
}

/// Read a NUL-terminated string from user memory at `ptr`,
/// bounded at `max` bytes. Returns the slice (trimmed of NUL)
/// borrowed against the user page. Caller asserts the user page
/// is mapped + CR3 is the calling task's AS.
/// # SAFETY: ptr in user range; user page mapped; CPL=0 reads
/// pass through user mappings.
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
