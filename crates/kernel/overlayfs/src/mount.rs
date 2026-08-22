//! The filesystem itself, from an option string to a root inode.
//!
//! Almost everything that can go wrong with an overlay goes wrong here rather
//! than later: a work directory inside the writable layer, a layer that is not
//! a directory, a writable layer that is read-only, a feature asked for that
//! the layers cannot support. Each is refused at mount time, because the
//! alternative is a mount that appears to work and then loses data on the
//! first write.

extern crate alloc;

use alloc::string::{String, ToString};
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::AtomicBool;
use syscall::errno::Errno;
use vfs::fs::FileSystem;
use vfs::inode_ops::CreateCtx;
use vfs::types::{FileType, S_IFREG};
use vfs::{InodeRef, KResult, SbStatFs, SuperOps};

use crate::config::{Config, XinoMode};
use crate::err::to_vfs;
use crate::inode::make_inode;
use crate::layers::{dirs_disjoint, Layer, LayerStack, OvlEntry, OvlPath};
use crate::limits::NAME_MAX;
use crate::params;
use crate::uapi::{INDEXDIR_NAME, VOLATILE_DIRTY_NAME, WORKDIR_NAME};
use crate::xino;

pub use crate::uapi::OVERLAYFS_SUPER_MAGIC;

/// A mounted overlay.
pub struct OverlayFs {
    stack: Arc<LayerStack>,
    root: InodeRef,
}

/// How a layer path is turned into a directory. The mount layer supplies it,
/// so this crate needs nothing from the path-walking machinery and can be
/// driven from a test with layers that are not mounted anywhere.
pub type Resolve<'a> = &'a dyn Fn(&str) -> Result<InodeRef, Errno>;

impl OverlayFs {
    /// Build a mount from an option string.
    ///
    /// `resolve` turns each named path into the directory it stands for.
    /// `trusted_xattr` says whether the caller may write the private markers
    /// where the default puts them, which decides whether the features that
    /// need them are available or refused.
    /// # C: O(layers)
    pub fn open(data: &str, resolve: Resolve, trusted_xattr: bool) -> Result<Arc<OverlayFs>, Errno> {
        let parsed = params::parse(data)?;
        let mut config = parsed.config;
        params::verify(&mut config, parsed.set, trusted_xattr)?;
        check_paths(&config)?;

        let upper = match &config.upperdir {
            Some(p) => Some(dir(resolve, p)?),
            None => None,
        };
        if upper.is_none() && config.lowerdirs.len() < 2 {
            // A single lower layer and nothing to write to is not an overlay:
            // it would present the layer unchanged, and every write would fail
            // in a way the caller cannot distinguish from a broken mount.
            return Err(Errno::Einval);
        }

        let (workdir, indexdir) = match (&upper, &config.workdir) {
            (Some(_), Some(w)) => work_dirs(resolve, w, config.index, config.is_volatile())?,
            _ => (None, None),
        };
        let stack = build(config, upper, workdir, indexdir, resolve)?;
        let root = make_inode(&stack, stack.root.clone(), None, "");
        Ok(Arc::new(OverlayFs { stack, root }))
    }

    /// The root of the merged tree. # C: O(1)
    pub fn root_inode(&self) -> InodeRef { self.root.clone() }
    /// The layers behind it. # C: O(1)
    pub fn layers(&self) -> &Arc<LayerStack> { &self.stack }
    /// Can anything be written to this mount? # C: O(1)
    pub fn writable(&self) -> bool { self.stack.writable() }
}

/// The path checks that need no layer resolved, so a mount naming an
/// impossible combination fails before anything is built. # C: O(layers)
fn check_paths(config: &Config) -> Result<(), Errno> {
    if config.lowerdirs.is_empty() && config.upperdir.is_none() { return Err(Errno::Einval); }
    if let (Some(u), Some(w)) = (&config.upperdir, &config.workdir) {
        // Either inside the other lets the work directory's contents appear in
        // the overlay, or half-built objects appear as its contents.
        if !dirs_disjoint(u, w) { return Err(Errno::Einval); }
    }
    for l in &config.lowerdirs {
        if let Some(u) = &config.upperdir {
            // A layer that is also the writable layer would have every write
            // to it appear as a change to a layer that is supposed to be
            // fixed, and would make a lookup find its own output.
            if !dirs_disjoint(u, &l.name) { return Err(Errno::Einval); }
        }
        if let Some(w) = &config.workdir {
            if !dirs_disjoint(w, &l.name) { return Err(Errno::Einval); }
        }
    }
    Ok(())
}

/// Resolve one layer path, refusing anything that is not a directory. # C: O(1)
fn dir(resolve: Resolve, path: &str) -> Result<InodeRef, Errno> {
    let i = resolve(path)?;
    if i.file_type() != FileType::Directory { return Err(Errno::Enotdir); }
    Ok(i)
}

/// Create the work directory, and the index directory when the mount keeps
/// one.
///
/// The index REPLACES the work directory rather than sitting beside it: an
/// object being copied up is linked into the index by the same rename that
/// puts it in place, and the two cannot be on different directories for that
/// to be one operation.
/// # C: O(work incompat entries)
fn work_dirs(resolve: Resolve, base: &str, index: bool, volatile: bool)
    -> Result<(Option<InodeRef>, Option<InodeRef>), Errno> {
    let b = dir(resolve, base)?;
    let work = subdir(&b, WORKDIR_NAME)?;
    refuse_incompatible(&work)?;
    if volatile { create_volatile_marker(&work)?; }
    if !index { return Ok((Some(work), None)); }
    let idx = subdir(&b, INDEXDIR_NAME)?;
    Ok((Some(idx.clone()), Some(idx)))
}

/// Refuse a work directory carrying an incompatibility from an earlier mount.
/// # C: O(directory entries)
fn refuse_incompatible(work: &InodeRef) -> Result<(), Errno> {
    let name = VOLATILE_DIRTY_NAME.split('/').next().ok_or(Errno::Einval)?;
    match work.lookup(name) {
        Ok(i) if i.file_type() != FileType::Directory || !i.i_op().dir_is_empty(&i) => {
            Err(Errno::Einval)
        }
        Ok(_) | Err(vfs::VfsError::Enoent) => Ok(()),
        Err(e) => Err(crate::err::to_errno(e)),
    }
}

/// Publish the marker which makes an unflushed upper incompatible with reuse.
/// # C: O(path components)
fn create_volatile_marker(work: &InodeRef) -> Result<(), Errno> {
    let mut dir = work.clone();
    let mut parts = VOLATILE_DIRTY_NAME.split('/').peekable();
    while let Some(name) = parts.next() {
        if parts.peek().is_some() {
            dir = subdir(&dir, name)?;
            continue;
        }
        return match dir.lookup(name) {
            Ok(_) => Ok(()),
            Err(vfs::VfsError::Enoent) => dir
                .create_child(name, S_IFREG as u32, &CreateCtx::root())
                .map(|_| ()).map_err(crate::err::to_errno),
            Err(e) => Err(crate::err::to_errno(e)),
        };
    }
    Err(Errno::Einval)
}

/// Get or create a subdirectory of the work base. # C: O(1)
fn subdir(base: &InodeRef, name: &str) -> Result<InodeRef, Errno> {
    match base.lookup(name) {
        Ok(i) if i.file_type() == FileType::Directory => Ok(i),
        Ok(_) => Err(Errno::Enotdir),
        Err(_) => base.mkdir(name, WORKDIR_MODE, &CreateCtx::root()).map_err(crate::err::to_errno),
    }
}

/// The work directory is created unreadable: nothing outside the filesystem
/// has any business in it, and an object half-built there must not be
/// openable by name.
const WORKDIR_MODE: u32 = vfs::types::S_IFDIR as u32;

/// Assemble the stack from the resolved layers. # C: O(layers)
fn build(config: Config, upper: Option<InodeRef>, workdir: Option<InodeRef>,
         indexdir: Option<InodeRef>, resolve: Resolve) -> Result<Arc<LayerStack>, Errno> {
    let upper_layer = upper.as_ref().map(|u| Layer::new(u.clone(), 0, 0, false));
    let mut lower = Vec::new();
    let mut root = OvlEntry { upper: upper.clone(), upper_alias: upper.is_some(),
                              ..OvlEntry::default() };
    for (i, l) in config.lowerdirs.iter().enumerate() {
        let inode = dir(resolve, &l.name)?;
        let layer = Layer::new(inode.clone(), i + 1, (i + 1) as u32, l.data_only);
        root.lower.push(OvlPath { layer: layer.clone(), inode });
        lower.push(layer);
    }
    let one_fs = same_filesystem(&upper, &root);
    Ok(Arc::new(LayerStack {
        xino: xino_mode(&config, one_fs),
        config, upper: upper_layer, lower, workdir, indexdir,
        namelen: NAME_MAX,
        noxattr: AtomicBool::new(false),
        root,
    }))
}

/// Are every layer's objects numbered in one space already? # C: O(layers)
fn same_filesystem(upper: &Option<InodeRef>, root: &OvlEntry) -> bool {
    let first = upper.as_ref().or(root.lower.first().map(|p| &p.inode));
    let Some(f) = first else { return true };
    let id = f.i_sb().map(|s| s.s_dev);
    if id.is_none() { return false; }
    upper.iter().chain(root.lower.iter().map(|p| &p.inode))
        .all(|i| i.i_sb().map(|s| s.s_dev) == id)
}

/// How inode numbers are reported, given what the layers turned out to be.
///
/// `auto` is best effort and silent; `on` is the same effort but the mount
/// warns rather than quietly reporting numbers that can collide.
/// # C: O(1)
fn xino_mode(config: &Config, one_fs: bool) -> xino::Mode {
    if one_fs { return xino::Mode::SameFs; }
    match config.xino {
        XinoMode::Off => xino::Mode::Off,
        XinoMode::Auto | XinoMode::On => xino::Mode::Bits(XINO_BITS),
    }
}

/// Bits reserved for the layer tag. Enough for every layer a real stack has,
/// and it leaves the whole 32-bit inode range every filesystem in practice
/// uses untouched.
const XINO_BITS: u32 = 8;

impl FileSystem for OverlayFs {
    fn name(&self) -> &str { "overlay" }
    fn magic(&self) -> u64 { OVERLAYFS_SUPER_MAGIC }
    fn root(&self) -> Option<InodeRef> { Some(self.root.clone()) }
    fn show_options(&self) -> String {
        params::show(&self.stack.config, self.stack.xino.same_fs())
    }
    fn super_ops(&self) -> Option<Arc<dyn SuperOps>> {
        Some(Arc::new(OverlaySuper { stack: self.stack.clone() }))
    }
}

/// The superblock operations of a mounted overlay.
struct OverlaySuper { stack: Arc<LayerStack> }

impl SuperOps for OverlaySuper {
    /// Report the WRITABLE layer's numbers, since that is where anything
    /// written actually goes; a read-only overlay reports the topmost lower
    /// layer's. Reporting the merge's own would tell `df` a number no
    /// filesystem has.
    /// # C: O(1)
    fn statfs(&self) -> KResult<SbStatFs> {
        let real = self.stack.upper.as_ref().map(|l| l.root.clone())
            .or_else(|| self.stack.lower.first().map(|l| l.root.clone()));
        let mut st = match real.and_then(|r| r.i_sb()) {
            Some(sb) => sb.statfs().unwrap_or_default(),
            None => SbStatFs::default(),
        };
        st.f_type = OVERLAYFS_SUPER_MAGIC;
        st.f_namelen = self.stack.namelen as u64;
        Ok(st)
    }

    fn show_options(&self) -> String {
        params::show(&self.stack.config, self.stack.xino.same_fs())
    }
}

/// Build a mount, reporting the failure as the VFS spells it. # C: O(layers)
pub fn open_vfs(data: &str, resolve: Resolve, trusted_xattr: bool)
    -> KResult<Arc<OverlayFs>> {
    OverlayFs::open(data, resolve, trusted_xattr).map_err(to_vfs)
}

/// The name this filesystem is mounted by.
pub const FS_NAME: &str = "overlay";

/// The second name Linux registers for the same filesystem, kept because
/// existing tooling writes it. # C: O(1)
pub const FS_NAME_LEGACY: &str = "overlayfs";

/// Placeholder so the unused import of the string type is justified where a
/// caller wants the mount's identity as one. # C: O(1)
pub fn identity() -> String { FS_NAME.to_string() }

#[cfg(test)]
#[path = "mount/tests.rs"]
mod tests;
