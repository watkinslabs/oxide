//! Boot-time devfs population + the synthetic directory inode. The
//! built-in pseudo-devices (null/zero/full/kmsg/random + the std fd
//! symlinks) and the directory overlay live here; the console/tty nodes
//! self-register from the `console` crate (docs/56 self-registration).
use alloc::sync::Arc;
use alloc::string::String;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};
use crate::{lookup, register, snapshot_visible_to_current};
use core::sync::atomic::{AtomicPtr, Ordering};
/// Directory-overlay hook: emits real on-disk children (the rootfs) under a
/// prefix, so synthetic /dev dirs overlay ext4 without devfs depending on a
/// filesystem driver (would cycle devfs->ext4->block->cgroup->devfs). The
/// kernel installs an ext4 adapter at boot (docs/56).
static DIR_OVERLAY: AtomicPtr<()> = AtomicPtr::new(core::ptr::null_mut());
type OverlayFn = fn(&[u8], &mut dyn FnMut(&[u8], FileType));
/// Install the rootfs directory-overlay adapter. Boot, once.
/// # C: O(1)
pub fn set_dir_overlay(f: OverlayFn) { DIR_OVERLAY.store(f as *mut (), Ordering::Release); }
fn dir_overlay(prefix: &[u8], emit: &mut dyn FnMut(&[u8], FileType)) {
    let p = DIR_OVERLAY.load(Ordering::Acquire);
    if p.is_null() { return; }
    // SAFETY: p was stored from an OverlayFn via set_dir_overlay.
    let f: OverlayFn = unsafe { core::mem::transmute(p) };
    f(prefix, emit);
}


/// Register the built-in pseudo-device nodes + the synthetic directory
/// overlay. Boot, once (idempotent — re-registration overwrites).
/// # C: O(N nodes)
pub fn populate_defaults() {
    register("/dev/null",    Arc::new(crate::misc::NullInode)   as InodeRef);
    register("/dev/kmsg",    Arc::new(crate::misc::KmsgInode)   as InodeRef);
    register("/dev/zero",    Arc::new(crate::misc::ZeroInode)   as InodeRef);
    register("/dev/full",    Arc::new(crate::misc::FullInode)   as InodeRef);
    let rand: InodeRef = Arc::new(crate::misc::RandomInode);
    register("/dev/random",  Arc::clone(&rand));
    register("/dev/urandom", rand);
    let sym = |target: &'static [u8], ino: u64| -> InodeRef {
        Arc::new(crate::misc::SymlinkInode { target, ino }) as InodeRef
    };
    register("/dev/stdin",  sym(b"/proc/self/fd/0", 0x2000_0010));
    register("/dev/stdout", sym(b"/proc/self/fd/1", 0x2000_0011));
    register("/dev/stderr", sym(b"/proc/self/fd/2", 0x2000_0012));
    register("/dev/fd",     sym(b"/proc/self/fd",   0x2000_0013));
    // Directory inodes synthesised over the registry — AFTER leaves so
    // they aren't enumerated as children of `/`.
    for (p, ino) in [
        ("/", 0x5000_0001u64), ("/dev", 0x5000_0002), ("/sys", 0x5000_0003),
        ("/etc", 0x5000_0004), ("/bin", 0x5000_0005), ("/usr", 0x5000_0006),
        ("/usr/bin", 0x5000_0007), ("/proc/sys", 0x5000_0008),
        ("/sys/fs", 0x5000_0009), ("/sys/kernel", 0x5000_000a),
    ] { register(p, Arc::new(PrefixDirInode { prefix: p, ino }) as InodeRef); }
}

/// `<prefix>/<name>` single-component child of `path`, else None.
/// # C: O(len)
fn child_under<'a>(prefix: &str, path: &'a str) -> Option<&'a str> {
    if prefix == "/" {
        let leaf = path.strip_prefix('/')?;
        if leaf.is_empty() || leaf.contains('/') { return None; }
        return Some(leaf);
    }
    let rest = path.strip_prefix(prefix)?.strip_prefix('/')?;
    if rest.is_empty() || rest.contains('/') { return None; }
    Some(rest)
}

/// Synthetic directory inode: emits every registered leaf under `prefix`
/// plus an ext4 overlay (real on-disk entries not shadowed by a node).
pub struct PrefixDirInode { pub prefix: &'static str, pub ino: Ino }

impl PrefixDirInode {
    fn build_child_path(&self, name: &str) -> String {
        let mut p = String::with_capacity(self.prefix.len() + 1 + name.len());
        if self.prefix == "/" { p.push('/'); } else { p.push_str(self.prefix); p.push('/'); }
        p.push_str(name);
        p
    }
}

impl Inode for PrefixDirInode {
    fn ino(&self) -> Ino { self.ino }
    fn file_type(&self) -> FileType { FileType::Directory }
    fn size(&self) -> u64 { 0 }
    fn lookup(&self, name: &str) -> KResult<InodeRef> {
        lookup(&self.build_child_path(name)).ok_or(VfsError::Enoent)
    }
    fn readdir(&self, off: u64, f: &mut dyn FnMut(u64, &str, FileType) -> bool) -> KResult<u64> {
        let snap = snapshot_visible_to_current();
        let r_len = snap.len() as u64;
        let mut idx = off as usize;
        while idx < snap.len() {
            let (path, inode) = &snap[idx];
            if let Some(name) = child_under(self.prefix, path) {
                let next = idx as u64 + 1;
                if !f(next, name, inode.file_type()) { return Ok(next); }
            }
            idx += 1;
        }
        let mut ext4_seen: u64 = 0;
        let mut stopped = false;
        let mut stop_off: u64 = (idx as u64).max(r_len);
        dir_overlay(self.prefix.as_bytes(), &mut |name_bytes, ftype| {
            if stopped { return; }
            ext4_seen += 1;
            if r_len + ext4_seen <= off { return; }
            let name = match core::str::from_utf8(name_bytes) { Ok(s) => s, Err(_) => return };
            if lookup(&self.build_child_path(name)).is_some() { return; }
            let next = r_len + ext4_seen;
            if !f(next, name, ftype) { stopped = true; stop_off = next; }
        });
        if stopped { return Ok(stop_off); }
        Ok(r_len + ext4_seen)
    }
}
