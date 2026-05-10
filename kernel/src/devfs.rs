// Devfs boot-time bootstrap + PrefixDirInode synthetic directory
// walker. Per `52§5`, the registry surface (register*, lookup,
// unregister_subtree, snapshot_ns, read_user_cstr) lives in
// `crates/devfs`. This file owns the kernel-runtime parts that
// can't move: the boot bootstrap that calls register() for
// /dev/console + tty + dev_misc + dirent inodes, and
// PrefixDirInode whose readdir overlays ext4 entries via
// `ext4::rootfs::read_dir`.

#![cfg(target_os = "oxide-kernel")]

use alloc::sync::Arc;
use vfs::{FileType, Ino, Inode, InodeRef, KResult, VfsError};

// Re-export the registry surface so existing `crate::devfs::*`
// callers (xattr_overlay, syscall_glue_*, dev_ext4, …) compile
// unchanged. Stage C will rewrite imports to `devfs::*`.
pub use ::devfs::{
    lookup, read_user_cstr, register, register_in_ns, register_owned,
    snapshot_ns, snapshot_visible_to_current, unregister_subtree,
};

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
    let fg: InodeRef = Arc::new(crate::dev::console::ConsoleInode::new(0));
    register("/dev/console", Arc::clone(&fg));
    register("/dev/tty",     Arc::clone(&fg));
    register("/dev/tty0",    Arc::clone(&fg));
    register("/dev/ttyS0",   fg);
    // /dev/tty1..tty63 per Linux MAX_NR_CONSOLES (vt::MAX_NR_CONSOLES).
    for vt in 1..=tty::live::N_VT as u8 {
        let mut path = alloc::string::String::with_capacity(10);
        path.push_str("/dev/tty");
        if vt >= 10 { path.push((b'0' + (vt / 10)) as char); }
        path.push((b'0' + (vt % 10)) as char);
        let inode: InodeRef = Arc::new(crate::dev::console::ConsoleInode::new(vt));
        register_owned(path, inode);
    }

    // P3-04 misc char devices.
    register("/dev/null",    Arc::new(devfs::misc::NullInode)   as InodeRef);
    register("/dev/kmsg",    Arc::new(devfs::misc::KmsgInode)   as InodeRef);
    register("/dev/log",     Arc::new(devfs::misc::NullInode)   as InodeRef);
    register("/dev/zero",    Arc::new(devfs::misc::ZeroInode)   as InodeRef);
    register("/dev/full",    Arc::new(devfs::misc::FullInode)   as InodeRef);
    let rand: InodeRef = Arc::new(devfs::misc::RandomInode);
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
        ::devfs::lookup(&p).ok_or(VfsError::Enoent)
    }
    fn readdir(
        &self,
        off: u64,
        f: &mut dyn FnMut(u64, &str, FileType) -> bool,
    ) -> KResult<u64> {
        // Phase 1: walk the devfs registry for synthetic / overlay
        // children of `self.prefix`.
        let snap = snapshot_visible_to_current();
        let r_len = snap.len() as u64;
        let mut idx = off as usize;
        while idx < snap.len() {
            let (path, inode) = &snap[idx];
            if let Some(name) = procfs::paths::child_under(self.prefix, path) {
                let next = idx as u64 + 1;
                if !f(next, name, inode.file_type()) {
                    return Ok(next);
                }
            }
            idx += 1;
        }
        // Phase 2: overlay ext4 entries for the same prefix. Offsets
        // are R + 1..=R + N_ext4 so getdents64 resumption stays
        // monotonic across the boundary.
        let mut ext4_seen: u64 = 0;
        let mut stopped = false;
        let mut stop_off: u64 = (idx as u64).max(r_len);
        let _ = ext4::rootfs::read_dir(self.prefix.as_bytes(), |name_bytes, dt| {
            if stopped { return; }
            ext4_seen += 1;
            if r_len + ext4_seen <= off { return; }
            let name = match core::str::from_utf8(name_bytes) {
                Ok(s) => s, Err(_) => return,
            };
            let child_path = self.build_child_path(name);
            if ::devfs::lookup(&child_path).is_some() { return; }
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
