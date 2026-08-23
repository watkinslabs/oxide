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
use alloc::vec;
use core::sync::atomic::AtomicBool;
use syscall::errno::Errno;
use vfs::file_ops::{DirContext, DirEmit};
use vfs::fs::FileSystem;
use vfs::inode_ops::CreateCtx;
use vfs::types::{FileType, S_IFREG};
use vfs::{InodeRef, KResult, SbStatFs, SuperOps};

use crate::config::{Config, XinoMode};
use crate::err::{to_errno, to_vfs};
use crate::inode::{make_inode, node::ovl_of};
use crate::layers::{dirs_disjoint, Layer, LayerStack, OvlEntry, OvlPath};
use crate::limits::NAME_MAX;
use crate::params;
use crate::uapi::{FB_HEADER_LEN, INDEXDIR_NAME, OVERLAY_FILEID_V0, OVERLAY_FILEID_V1, VOLATILE_DIRTY_NAME,
                  WORKDIR_NAME};
use crate::{fh, marker, origin};
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
        Self::open_with_cred(data, resolve, trusted_xattr, &vfs::Cred::root())
    }
    /// Build a mount while retaining the fs_context opener credential. # C: O(layers)
    pub fn open_with_cred(data: &str, resolve: Resolve, trusted_xattr: bool,
        creator_cred: &vfs::Cred) -> Result<Arc<OverlayFs>, Errno> {
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
            (Some(_), Some(w)) => work_dirs(resolve, w, config.index, config.is_volatile(), creator_cred)?,
            _ => (None, None),
        };
        let stack = build(config, upper, workdir, indexdir, resolve, creator_cred.clone())?;
        verify_index(&stack)?;
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
fn work_dirs(resolve: Resolve, base: &str, index: bool, volatile: bool, creator_cred: &vfs::Cred)
    -> Result<(Option<InodeRef>, Option<InodeRef>), Errno> {
    let b = dir(resolve, base)?;
    let work = subdir(&b, WORKDIR_NAME, creator_cred)?;
    refuse_incompatible(&work)?;
    if volatile { create_volatile_marker(&work, creator_cred)?; }
    if !index { return Ok((Some(work), None)); }
    let idx = subdir(&b, INDEXDIR_NAME, creator_cred)?;
    Ok((Some(idx.clone()), Some(idx)))
}

/// Remove index entries whose origin, upper object, or stored origin marker no
/// longer agrees. Linux does this before publishing the overlay root so a
/// crashed copy-up cannot make a later lookup return an unrelated object.
/// # C: O(index entries · layers)
fn verify_index(stack: &Arc<LayerStack>) -> Result<(), Errno> {
    let Some(index) = &stack.indexdir else { return Ok(()) };
    struct Names(Vec<String>);
    impl DirEmit for Names {
        fn emit(&mut self, name: &str, _ino: u64, _ty: FileType, _next: u64) -> bool {
            self.0.push(name.to_string()); true
        }
    }
    let mut names = Names(Vec::new());
    let mut ctx = DirContext::new(0, &mut names);
    index.readdir(&mut ctx).map_err(to_errno)?;
    for name in names.0 {
        let valid = fh::from_index_name(&name).ok()
            .and_then(|record| origin::decode(stack, &record).map(|_| record))
            .and_then(|record| index.lookup(&name).ok().map(|upper| (record, upper)))
            .and_then(|(record, upper)| marker::get(&stack.config, &upper, crate::uapi::Marker::Origin)
                .filter(|stored| fh::same(stored, &record)).map(|_| ()))
            .is_some();
        if !valid {
            stack.with_access_ctx(|ctx| index.unlink_child_with_ctx(&name, ctx)).map_err(to_errno)?;
        }
    }
    Ok(())
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
fn create_volatile_marker(work: &InodeRef, creator_cred: &vfs::Cred) -> Result<(), Errno> {
    let mut dir = work.clone();
    let mut parts = VOLATILE_DIRTY_NAME.split('/').peekable();
    while let Some(name) = parts.next() {
        if parts.peek().is_some() {
            dir = subdir(&dir, name, creator_cred)?;
            continue;
        }
        return match dir.lookup(name) {
            Ok(_) => Ok(()),
            Err(vfs::VfsError::Enoent) => {
                let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: creator_cred, umask: 0 };
                dir.create_child(name, S_IFREG as u32, &ctx)
                    .map(|_| ()).map_err(crate::err::to_errno)
            }
            Err(e) => Err(crate::err::to_errno(e)),
        };
    }
    Err(Errno::Einval)
}

/// Get or create a subdirectory of the work base. # C: O(1)
fn subdir(base: &InodeRef, name: &str, creator_cred: &vfs::Cred) -> Result<InodeRef, Errno> {
    match base.lookup(name) {
        Ok(i) if i.file_type() == FileType::Directory => Ok(i),
        Ok(_) => Err(Errno::Enotdir),
        Err(_) => {
            let ctx = CreateCtx { idmap: &vfs::IDENTITY, cred: creator_cred, umask: 0 };
            base.mkdir(name, WORKDIR_MODE, &ctx).map_err(crate::err::to_errno)
        }
    }
}

/// The work directory is created unreadable: nothing outside the filesystem
/// has any business in it, and an object half-built there must not be
/// openable by name.
const WORKDIR_MODE: u32 = vfs::types::S_IFDIR as u32;

/// Assemble the stack from the resolved layers. # C: O(layers)
fn build(config: Config, upper: Option<InodeRef>, workdir: Option<InodeRef>,
         indexdir: Option<InodeRef>, resolve: Resolve, creator_cred: vfs::Cred) -> Result<Arc<LayerStack>, Errno> {
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
        config, creator_cred, upper: upper_layer, lower, workdir, indexdir,
        namelen: NAME_MAX,
        noxattr: AtomicBool::new(false),
        root,
        inode_cache: sync::Spinlock::new(alloc::collections::BTreeMap::new()),
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
    /// Linux's overlay export payload is the on-disk origin record: its
    /// length is carried in the record header, so the capacity probe reserves
    /// the largest valid record and the encoder returns its actual length.
    /// # C: O(1)
    fn export_fid_len(&self, _connectable: bool, _is_dir: bool) -> u32 {
        if self.stack.config.nfs_export { (FB_HEADER_LEN + fh::MAX_FID_LEN) as u32 } else { 0 }
    }

    /// Encode the real upper or lower identity selected by overlay's export
    /// rules. Connectable handles are intentionally unsupported by Linux.
    /// # C: O(layers)
    fn export_encode_fh_raw(&self, inode: &InodeRef, parent: Option<(u64, u32)>, buf: &mut [u8])
        -> (u32, i32)
    {
        if parent.is_some() || !self.stack.config.nfs_export { return (0, -1); }
        let Some(ovl) = ovl_of(inode) else { return (0, -1) };
        let entry = ovl.entry();
        let (real, is_upper) = match (&entry.upper, entry.lower.first(), entry.indexed) {
            (Some(_upper), Some(lower), true) => (lower.inode.clone(), false),
            (Some(upper), _, _) => (upper.clone(), true),
            (None, Some(lower), _) => (lower.inode.clone(), false),
            _ => return (0, -1),
        };
        let Some(record) = origin::encode(&self.stack.config, &real, is_upper) else { return (0, -1) };
        if record.len() > buf.len() { return (0, -1); }
        buf[..record.len()].copy_from_slice(&record);
        (record.len() as u32, OVERLAY_FILEID_V1)
    }

    /// Overlay records are self-sized and accept only the two Linux overlay
    /// file-id types; the inner backing fid type is validated during decode.
    /// # C: O(1)
    fn export_fid_len_for_type(&self, handle_type: i32) -> Option<u32> {
        (handle_type == OVERLAY_FILEID_V0 || handle_type == OVERLAY_FILEID_V1)
            .then_some((FB_HEADER_LEN + fh::MAX_FID_LEN) as u32)
    }

    /// Validate the record framing before the filesystem decoder sees it.
    /// # C: O(1)
    fn export_fid_len_for_type_raw(&self, bytes: &[u8], handle_type: i32) -> bool {
        (handle_type == OVERLAY_FILEID_V0 || handle_type == OVERLAY_FILEID_V1)
            && fh::check(bytes).is_ok()
            && bytes.len() == bytes[2] as usize
    }

    /// Parse the overlay record and retain it for upper/lower resolution.
    /// # C: O(1)
    fn export_decode_fh_raw(&self, bytes: &[u8], handle_type: i32)
        -> Result<vfs::export::fid::ExportFid, syscall::errno::Errno>
    {
        if !self.export_fid_len_for_type_raw(bytes, handle_type) { return Err(Errno::Estale); }
        let record = fh::decode(bytes).map_err(|e| e.errno())?;
        Ok(vfs::export::fid::ExportFid {
            fid: vfs::export::fid::Fid { ino: 0, generation: 0, parent: None },
            raw: bytes[..record.fid.len() + FB_HEADER_LEN].to_vec(),
        })
    }

    /// Rebuild the merged inode from its persistent upper/lower origin.
    /// # C: O(layers + index lookup)
    fn fh_to_dentry_raw(&self, _sb: &vfs::SuperBlock,
                        fid: &vfs::export::fid::ExportFid) -> Option<InodeRef>
    {
        let record = fh::decode(&fid.raw).ok()?;
        let (layer, real) = if record.is_upper {
            let l = self.stack.upper.as_ref()?;
            (l.clone(), origin::decode_in(&self.stack.config, l, &fid.raw)?.inode)
        } else {
            let p = origin::decode(&self.stack, &fid.raw)?;
            (p.layer, p.inode)
        };
        if real.file_type() == FileType::Directory {
            return decode_path(self, &layer, &real, record.is_upper, 0);
        }
        Some(make_inode(&self.stack, entry_for(self, &layer, &real, record.is_upper, &fid.raw), None, ""))
    }

    /// Return the shared overlay parent kept by a decoded directory inode.
    /// # C: O(1)
    fn get_parent(&self, _sb: &vfs::SuperBlock, dir: &InodeRef) -> Option<InodeRef> {
        crate::inode::node::ovl_of(dir)?.parent.as_ref()?.inode()
    }

    /// Overlay's own handles are decodable only when NFS export is enabled.
    /// # C: O(1)
    fn export_can_decode_fh(&self) -> bool { self.stack.config.nfs_export }

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

/// Assemble one decoded real object, including the persistent index link.
/// # C: O(1) expected
fn entry_for(this: &OverlaySuper, layer: &Arc<Layer>, real: &InodeRef, is_upper: bool,
             record: &[u8]) -> OvlEntry {
    if is_upper {
        let lower = origin::get(&this.stack.config, real, crate::uapi::Marker::Origin)
            .and_then(|r| origin::decode(&this.stack, &r));
        return OvlEntry { upper: Some(real.clone()), lower: lower.into_iter().collect(), upper_alias: true,
                          ..OvlEntry::default() };
    }
    let mut entry = OvlEntry { lower: vec![OvlPath { layer: layer.clone(), inode: real.clone() }],
                               ..OvlEntry::default() };
    if let Some(index) = &this.stack.indexdir {
        if let Ok(name) = fh::index_name(record) {
            if let Ok(upper) = index.lookup(&name) {
                if !crate::whiteout::is_device(&upper) {
                    entry.upper = Some(upper); entry.indexed = true;
                }
            }
        }
    }
    entry
}

/// Rebuild the connected overlay parent chain required by directory export.
/// # C: O(depth · entries)
fn decode_path(this: &OverlaySuper, layer: &Arc<Layer>, real: &InodeRef, is_upper: bool,
               depth: usize) -> Option<InodeRef> {
    if depth >= vfs::export::MAX_RECONNECT_DEPTH { return None; }
    if real.ino() == layer.root.ino() { return Some(make_inode(&this.stack, this.stack.root.clone(), None, "")); }
    let sb = real.i_sb()?;
    let parent_real = sb.s_op.get_parent(&sb, real)?;
    let parent = decode_path(this, layer, &parent_real, is_upper, depth + 1)?;
    let name = vfs::export::get_name(&parent_real, real.ino())?;
    let parent_state = crate::inode::node::ovl_of(&parent)?.shared()?;
    let record = origin::encode(&this.stack.config, real, is_upper)?;
    Some(make_inode(&this.stack, entry_for(this, layer, real, is_upper, &record),
                    Some(parent_state), &name))
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
