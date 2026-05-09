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

/// Flat path → inode map. v1 single-CPU UP with `TaskList` lock
/// class (matching the rank used elsewhere for boot-time
/// kernel-state registries).
static REGISTRY: Spinlock<Vec<(String, InodeRef)>, TaskListClass>
    = Spinlock::new(Vec::new());

/// Register a path → inode mapping (boot-time, &'static str).
/// Idempotent: last writer wins.
/// # SAFETY: caller is the boot path; single-CPU pre-init.
/// # C: O(N)
pub fn register(path: &'static str, inode: InodeRef) {
    register_owned(String::from(path), inode);
}

/// Same as `register` but accepts an owned String — used at runtime
/// for dynamically-allocated paths (e.g. `/dev/pts/<n>` per `28§5`).
/// # C: O(N)
pub fn register_owned(path: String, inode: InodeRef) {
    let mut g = REGISTRY.lock();
    if let Some(slot) = g.iter_mut().find(|(p, _)| *p == path) {
        slot.1 = inode;
    } else {
        g.push((path, inode));
    }
}

/// Look up a path. Returns `Some(inode)` on hit. Applies the calling
/// task's chroot prefix (F95) before matching against the registry.
/// # C: O(N)
pub fn lookup(path: &str) -> Option<InodeRef> {
    let resolved = chroot_resolve(path);
    let g = REGISTRY.lock();
    g.iter().find(|(p, _)| p.as_str() == resolved.as_str()).map(|(_, i)| Arc::clone(i))
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
        let g = REGISTRY.lock();
        let r_len = g.len() as u64;
        let mut idx = off as usize;
        while idx < g.len() {
            let (path, inode) = &g[idx];
            if let Some(name) = procfs::paths::child_under(self.prefix, path) {
                let next = idx as u64 + 1;
                if !f(next, name, inode.file_type()) {
                    return Ok(next);
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
