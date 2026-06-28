//! FileSystem trait — per `docs/16` mount-table abstraction.
//!
//! Each FS backend (ext4 rootfs, devfs, procfs, tmpfs) implements
//! this trait. The kernel mount table (`vfs::mount`, R67) holds an
//! `Arc<dyn FileSystem>` per mount point and routes path lookup to
//! the longest-prefix-match instance.
//!
//! work fns per `docs/53§3`: no `SyscallArgs`, no
//! `sched::current()`, returns `KResult<T>` with typed `T`.

extern crate alloc;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use crate::inode::InodeRef;
use crate::superblock::{SuperBlock, SuperOps};
use crate::types::VfsError;

/// `KResult<T>` is the VFS error envelope. Aliased here for
/// convenience inside trait bodies.
pub type KResult<T> = core::result::Result<T, VfsError>;

bitflags::bitflags! {
    /// `file_system_type::fs_flags` (Linux `include/linux/fs.h`). A
    /// type-LEVEL property of the backend (NOT a per-mount `MNT_*` bit):
    /// it governs how the VFS mounts and classifies the fs. Numeric
    /// values match Linux exactly. Subset for v1; expand alongside their
    /// first real consumer.
    #[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
    pub struct FsFlags: u32 {
        /// fs is backed by a block device — `mount(2)` needs a `dev`
        /// source (`mount_bdev`). Cleared on pseudo / in-memory fses
        /// (`mount_nodev`), which `/proc/filesystems` then tags `nodev`.
        const FS_REQUIRES_DEV       = 1;
        /// On-disk mount options are an opaque binary blob, not a comma
        /// string (Linux `FS_BINARY_MOUNTDATA`).
        const FS_BINARY_MOUNTDATA   = 2;
        /// fs name carries a `.subtype` suffix (`fuse.sshfs`).
        const FS_HAS_SUBTYPE        = 4;
        /// Mountable by a non-init user-namespace root (Linux
        /// `FS_USERNS_MOUNT`: tmpfs, proc, sysfs, …).
        const FS_USERNS_MOUNT       = 8;
        /// fanotify permission events are refused on this fs.
        const FS_DISALLOW_NOTIFY_PERM = 16;
        /// fs understands vfs idmappings (`FS_ALLOW_IDMAP`).
        const FS_ALLOW_IDMAP        = 32;
        /// `->rename` performs the `d_move` itself; the VFS must NOT
        /// (Linux `FS_RENAME_DOES_D_MOVE`, e.g. NFS).
        const FS_RENAME_DOES_D_MOVE = 32768;
    }
}

/// Append the decimal digits of `n` to `s` (no_std, no `format!`).
/// # C: O(log10 n)
fn push_u32(s: &mut String, n: u32) {
    if n == 0 { s.push('0'); return; }
    let mut buf = [0u8; 10];
    let mut i = buf.len();
    let mut v = n;
    while v > 0 { i -= 1; buf[i] = b'0' + (v % 10) as u8; v /= 10; }
    // SAFETY: buf[i..] holds only ASCII '0'..='9', valid UTF-8.
    s.push_str(unsafe { core::str::from_utf8_unchecked(&buf[i..]) });
}

/// Filesystem instance per `16§2`. One impl per backend; one or
/// more instances per kernel (each registered to a mount point).
pub trait FileSystem: Send + Sync {
    /// Human-readable FS-type name. `"ext4"`, `"tmpfs"`, `"devfs"`,
    /// `"procfs"`. Used for `/proc/mounts` and error messages.
    /// # C: O(1)
    fn name(&self) -> &str;

    /// Superblock `s_magic` (linux/magic.h) reported by `statfs(2)` /
    /// `fstatfs(2)` `f_type`. systemd & friends detect fs type by this
    /// magic (cgroup2=0x63677270, tmpfs=0x01021994, proc=0x9fa0, …), so
    /// every real backend must override. `0` = "no opinion": the statfs
    /// classifier then falls through to its path-prefix table.
    /// # C: O(1)
    fn magic(&self) -> u64 { 0 }

    /// `file_system_type::fs_flags` for this backend (Linux
    /// `include/linux/fs.h`). Default `empty()` = a pseudo / in-memory fs:
    /// not block-device-backed, so `/proc/filesystems` tags it `nodev`.
    /// On-disk backends override with [`FsFlags::FS_REQUIRES_DEV`] (ext4,
    /// ext2/3, vfat, iso9660); pseudo fses that nonetheless want
    /// userns-mountability set [`FsFlags::FS_USERNS_MOUNT`].
    /// # C: O(1)
    fn fs_flags(&self) -> FsFlags { FsFlags::empty() }

    /// fs is backed by a block device (`mount(2)` requires a `dev` source).
    /// Mirrors Linux's `fs_flags & FS_REQUIRES_DEV` predicate used by
    /// `mount_bdev` vs `mount_nodev` and by `filesystems_proc_show`.
    /// # C: O(1)
    fn requires_dev(&self) -> bool { self.fs_flags().contains(FsFlags::FS_REQUIRES_DEV) }

    /// `->rename` drives `d_move` itself, so the VFS rename path must skip
    /// the generic dentry move (Linux `FS_RENAME_DOES_D_MOVE`). # C: O(1)
    fn rename_does_d_move(&self) -> bool {
        self.fs_flags().contains(FsFlags::FS_RENAME_DOES_D_MOVE)
    }

    /// One `/proc/filesystems` row for this backend, byte-identical to
    /// Linux `filesystems_proc_show` (`fs/filesystems.c`): a leading
    /// `"nodev"` for non-`FS_REQUIRES_DEV` fses (else empty), a TAB, the fs
    /// name, and `'\n'`. Replaces the hardcoded `/proc/filesystems` table:
    /// the `nodev` column is now DERIVED from `fs_flags`, not a string
    /// literal. # C: O(len name)
    fn proc_filesystems_line(&self) -> String {
        let mut s = String::new();
        if self.requires_dev() { /* FS_REQUIRES_DEV ⇒ no "nodev" prefix */ }
        else { s.push_str("nodev"); }
        s.push('\t');
        s.push_str(self.name());
        s.push('\n');
        s
    }

    /// `s_blocksize` (Linux `super_block::s_blocksize`) the mount reports as
    /// `statfs(2)` `f_bsize`. On-disk backends override from their parsed
    /// superblock (ext4 `1024 << s_log_block_size`, 1–64 KiB); pseudo /
    /// in-memory fses keep the 4096 page default. # C: O(1)
    fn block_size(&self) -> u32 { 4096 }

    /// Per-instance `super_operations` (Linux `sb->s_op`). `Some(_)` installs a
    /// backend-specific `SuperOps` — e.g. ext4 reports live on-disk block /
    /// inode accounting through its own `statfs` — instead of the generic
    /// `FsBackedSuperOps` (which reports only `f_type`/`f_bsize`). `None` keeps
    /// the generic adapter. Consulted once by [`SuperBlock::for_backend`] at
    /// fill_super. # C: O(1)
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> { None }

    /// Root inode of this mounted filesystem — the `super_block::s_root`
    /// of `docs/16§2`. The dentry path-walk (`docs/16§3`) switches to this
    /// inode when it crosses into the mount, then resolves every component
    /// below it via `Inode::lookup` (`d_lookup → i_op->lookup → d_add`).
    /// Every real backend overrides this (or publishes a per-mount root via
    /// `mount::register_bind`'s `m.root`); `None` only for a marker fs whose
    /// root inode is carried by the mount table instead.
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { None }

    /// Create a new regular file at `path` with permission `mode`.
    /// Default: read-only FS returns `Erofs`.
    /// # C: depends on FS.
    fn create(&self, path: &str, mode: u32) -> KResult<InodeRef> {
        let _ = (path, mode);
        Err(VfsError::Erofs)
    }

    /// Create an anonymous (`O_TMPFILE`) regular inode on THIS fs. `dir`
    /// is the directory (relative to this mount) the file would live in —
    /// disk FSes use it to pick an allocation group; in-memory FSes
    /// ignore it. The inode has no directory entry (nlink=0) and is
    /// reclaimed when its last fd drops. Must be dispatched on the fs that
    /// actually backs the path: `O_TMPFILE` on /run|/tmp|/dev/shm is tmpfs,
    /// not the ext4 rootfs. Default: read-only/unsupported FS returns Erofs.
    /// # C: depends on FS.
    fn create_anonymous(&self, dir: &str, mode: u32) -> KResult<InodeRef> {
        let _ = (dir, mode);
        Err(VfsError::Erofs)
    }

    /// Remove the regular file at `path`. Default: `Erofs`.
    /// # C: depends on FS.
    fn unlink(&self, path: &str) -> KResult<()> {
        let _ = path;
        Err(VfsError::Erofs)
    }

    /// Hardlink `target` to `link` within this filesystem. Both paths are
    /// absolute during the mount-table transition; mature backends may treat
    /// them as mount-relative once every caller passes stripped names.
    /// Default: read-only / unsupported FS returns `Erofs`.
    /// # C: depends on FS.
    fn link(&self, target: &str, link: &str) -> KResult<()> {
        let _ = (target, link);
        Err(VfsError::Erofs)
    }

    /// Materialize an unnamed inode, e.g. `linkat(fd, "", path,
    /// AT_EMPTY_PATH)`, into this filesystem. Backends must reject inodes
    /// from another filesystem with `Exdev`.
    /// # C: depends on FS.
    fn link_inode(&self, inode: InodeRef, link: &str) -> KResult<()> {
        let _ = (inode, link);
        Err(VfsError::Erofs)
    }

    /// Rename `from` to `to`. Both paths are relative to this FS.
    /// Default: `Erofs`.
    /// # C: depends on FS.
    fn rename(&self, from: &str, to: &str) -> KResult<()> {
        let _ = (from, to);
        Err(VfsError::Erofs)
    }

    /// Resolve a mount-relative `path` to its inode by walking from this
    /// FS root via `Inode::lookup`. `None` if any component is missing or
    /// the FS publishes no `root()`. Helper for [`exchange`]/[`whiteout`].
    /// # C: O(N components)
    fn lookup_path(&self, path: &str) -> Option<InodeRef> {
        let mut cur = self.root()?;
        for comp in path.split('/').filter(|c| !c.is_empty() && *c != ".") {
            cur = cur.lookup(comp).ok()?;
        }
        Some(cur)
    }

    /// `RENAME_EXCHANGE`: atomically swap the two existing paths `a` and
    /// `b`. Both must already exist (Linux `ENOENT` otherwise). Default is
    /// a non-atomic 3-step via `rename` through a fresh temp name in `a`'s
    /// directory, rolled back on partial failure; a backend with a
    /// journalled dirent swap should override for true atomicity.
    /// # C: O(N components)
    fn exchange(&self, a: &str, b: &str) -> KResult<()> {
        if self.lookup_path(a).is_none() || self.lookup_path(b).is_none() {
            return Err(VfsError::Enoent);
        }
        // Pick a temp name that does not currently exist on this FS.
        let mut tmp = alloc::string::String::new();
        let mut n: u32 = 0;
        loop {
            tmp.clear();
            tmp.push_str(a);
            tmp.push_str(".oxexch");
            push_u32(&mut tmp, n);
            if self.lookup_path(&tmp).is_none() { break; }
            n = n.checked_add(1).ok_or(VfsError::Eexist)?;
            if n > 65536 { return Err(VfsError::Eexist); }
        }
        self.rename(a, &tmp)?;                 // a -> tmp
        if let Err(e) = self.rename(b, a) {    // b -> a
            let _ = self.rename(&tmp, a);      // rollback: tmp -> a
            return Err(e);
        }
        if let Err(e) = self.rename(&tmp, b) { // tmp -> b
            let _ = self.rename(a, b);         // rollback: a -> b
            let _ = self.rename(&tmp, a);      //           tmp -> a
            return Err(e);
        }
        Ok(())
    }

    /// `RENAME_WHITEOUT`: rename `from` to `to`, then plant a whiteout at
    /// `from` — an overlayfs whiteout is a character device with rdev 0/0
    /// (`mknod_child(S_IFCHR|0, 0)`). On whiteout-create failure the rename
    /// is rolled back. Default works on any backend whose dir inode honours
    /// `mknod_child`; others surface that inode's error (e.g. `Erofs`).
    /// # C: O(N components)
    fn whiteout(&self, from: &str, to: &str) -> KResult<()> {
        const S_IFCHR: u16 = 0x2000;
        self.rename(from, to)?;
        // Parent dir + basename of `from` (now vacated by the rename).
        let from = from.strip_suffix('/').unwrap_or(from);
        let (parent, name) = match from.rfind('/') {
            Some(i) => (&from[..i], &from[i + 1..]),
            None    => ("", from),
        };
        let pino = match self.lookup_path(parent) {
            Some(p) => p, None => { let _ = self.rename(to, from); return Err(VfsError::Enoent); }
        };
        if let Err(e) = pino.mknod_child(name, S_IFCHR, 0) {
            let _ = self.rename(to, from); // rollback the move
            return Err(e);
        }
        Ok(())
    }

    /// Back-stamp the owning `SuperBlock` (Linux `fill_super` setting up
    /// `s_fs_info ↔ sb`). Called by [`SuperBlock::for_backend`] once the SB is
    /// built, BEFORE `d_make_root`, so the backend's per-mount state can hand
    /// the `Weak<SuperBlock>` to its inodes (their `i_sb()` then resolves and
    /// `fsid()` derives from `sb.s_dev` instead of a hardcoded constant).
    /// Default no-op for backends not yet SB-aware (registry-based pseudo-fs).
    /// # C: O(1)
    fn set_sb(&self, _sb: Weak<SuperBlock>) {}

    /// Filesystem-specific mount options for `/proc/mounts` &
    /// `/proc/self/mountinfo`, mirroring Linux `super_operations::show_options`
    /// (`fs/*/super.c`). The VFS renders the generic per-mount flags first
    /// (`rw`/`ro`, `relatime`, …); this hook then APPENDS the backend's own
    /// options — tmpfs `size=`/`nr_inodes=`/`mode=`, ext4 `data=ordered`,
    /// cgroup2 controller list, etc. Each option carries its own leading comma
    /// exactly as Linux emits them via `seq_puts(m, ",size=…")`, so the result
    /// concatenates directly after the generic flags with no separator fixup.
    /// Default `""` = no fs-specific options. # C: O(len opts)
    fn show_options(&self) -> String { String::new() }

    /// `/proc/mounts`-style description: `<src> <mnt> <fstype> <opts> 0 0`.
    /// Source and fstype default to the fs name; `<opts>` is the generic
    /// `rw,relatime` per-mount flags followed by [`Self::show_options`] (the
    /// procfs reader swaps the leading ` rw,` → ` ro,` for a read-only mount,
    /// Linux's per-mount `MNT_RDONLY` rendering). Backends with extra options
    /// override `show_options` ONLY — not this whole line — so the
    /// `<src> <mnt> <fstype> … 0 0` framing stays in one place. # C: O(1)
    fn mounts_line(&self, mount_point: &str) -> String {
        let mut s = String::new();
        s.push_str(self.name());
        s.push(' ');
        s.push_str(mount_point);
        s.push(' ');
        s.push_str(self.name());
        s.push_str(" rw,relatime");
        s.push_str(&self.show_options());
        s.push_str(" 0 0\n");
        s
    }
}
