// The pstore filesystem: one flat directory in which every surviving record
// is a read-only file whose contents are the captured data, and in which
// unlinking a file erases the record from the persistent region.
//
// The directory is a VIEW, built at mount time from the backend's
// enumeration. The backend's zones are the only truth about what exists; a
// file is how one is read, and removing the file is how one is erased.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::sync::{Arc, Weak};
use alloc::vec::Vec;

use sync::{Kernfs as PstoreClass, Spinlock};
use vfs::superblock::SuperBlock;
use vfs::{CookieEntry, DirContext, FileOps, FileType, Ino, Inode, InodeBuilder, InodeOps,
    InodeRef, KResult, Timespec64, VfsError, mk_mode};

use crate::psinfo;
use crate::ram::BACKEND_NAME;
use crate::record::{file_name, Record, RecordId};
use crate::uapi::PSTOREFS_MAGIC;

/// Inode numbers for the mount root and its record files.
static INO: vfs::pseudo_ino::RegionAllocator =
    vfs::pseudo_ino::RegionAllocator::new(&vfs::pseudo_ino::PSTORE);

/// `S_IFDIR | 0750` — the reference's mount root: readable by root only,
/// because a crash dump carries whatever the kernel was printing.
const ROOT_PERM: u16 = 0o750;
/// `S_IFREG | 0444` — a record is captured data, never written through here.
const FILE_PERM: u16 = 0o444;

/// A record file's backing state: the bytes, and which record erasing it
/// removes.
struct RecordFile {
    id: RecordId,
    body: Vec<u8>,
}

struct RecordFileOps;

impl FileOps for RecordFileOps {
    /// # C: O(len buf)
    fn read(&self, inode: &Inode, off: u64, buf: &mut [u8]) -> KResult<usize> {
        let f = inode.private::<RecordFile>().ok_or(VfsError::Einval)?;
        let off = off as usize;
        if off >= f.body.len() { return Ok(0); }
        let avail = &f.body[off..];
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        Ok(n)
    }
    /// # C: O(1)
    fn write(&self, _inode: &Inode, _off: u64, _buf: &[u8]) -> KResult<usize> {
        Err(VfsError::Erofs)
    }
}

/// The mount root's children, keyed by filename.
struct Tree {
    children: BTreeMap<String, InodeRef>,
}

/// One pstore mount.
pub struct PstoreFs {
    tree: Arc<Root>,
}

struct Root {
    ino: Ino,
    tree: Spinlock<Tree, PstoreClass>,
    inode: Spinlock<Weak<Inode>, PstoreClass>,
}

struct RootInodeOps;

fn root_of(inode: &Inode) -> KResult<&Root> {
    inode.private::<Root>().ok_or(VfsError::Einval)
}

impl InodeOps for RootInodeOps {
    /// # C: O(log N)
    fn lookup(&self, inode: &Inode, name: &str) -> KResult<InodeRef> {
        let r = root_of(inode)?;
        let g = r.tree.lock();
        g.children.get(name).cloned().ok_or(VfsError::Enoent)
    }

    /// Unlinking a record file erases the record from the persistent region,
    /// which is the only way to free a zone for the next crash. The file goes
    /// only if the erase succeeded — a name left behind after a failed erase
    /// would claim the record is gone when it is not. # C: O(log N)
    fn unlink(&self, inode: &Inode, name: &str) -> KResult<()> {
        let r = root_of(inode)?;
        // Which record to erase comes from the FILE, not from re-parsing its
        // name: the inode carries the identity it was published with, so the
        // name is a label and cannot be a second source of truth about it.
        let id = {
            let g = r.tree.lock();
            let child = g.children.get(name).ok_or(VfsError::Enoent)?;
            child.private::<RecordFile>().ok_or(VfsError::Enoent)?.id
        };
        let b = psinfo::backend().ok_or(VfsError::Eperm)?;
        b.erase(id)?;
        r.tree.lock().children.remove(name);
        Ok(())
    }
}

struct RootFileOps;

impl FileOps for RootFileOps {
    /// # C: O(N log N)
    fn iterate(&self, inode: &Inode, ctx: &mut DirContext) -> KResult<()> {
        let r = root_of(inode)?;
        let mut kids: Vec<CookieEntry> = {
            let g = r.tree.lock();
            g.children.iter()
                .map(|(k, v)| CookieEntry::new(k.clone(), v.ino(), v.file_type()))
                .collect()
        };
        vfs::emit_by_cookie(&mut kids, ctx)
    }
}

impl Root {
    fn new() -> Arc<Root> {
        Arc::new(Root {
            ino: INO.alloc(),
            tree: Spinlock::new(Tree { children: BTreeMap::new() }),
            inode: Spinlock::new(Weak::new()),
        })
    }

    fn as_inode(self: &Arc<Root>) -> InodeRef {
        let mut g = self.inode.lock();
        if let Some(i) = g.upgrade() { return i; }
        let inode = InodeBuilder::new(
            self.ino,
            mk_mode(FileType::Directory, ROOT_PERM),
            Arc::new(RootInodeOps),
            Arc::new(RootFileOps),
        )
        .fsid(PSTOREFS_MAGIC)
        .nlink(2)
        .private(Arc::clone(self) as Arc<dyn core::any::Any + Send + Sync>)
        .build();
        *g = Arc::downgrade(&inode);
        inode
    }

    fn publish(self: &Arc<Root>, records: Vec<Record>) {
        let mut g = self.tree.lock();
        for r in records {
            let name = file_name(r.id, BACKEND_NAME);
            if g.children.contains_key(&name) { continue; }
            let t = Timespec64 { sec: r.sec as i64, nsec: r.nsec };
            let len = r.body.len() as u64;
            let inode = InodeBuilder::new(
                INO.alloc(),
                mk_mode(FileType::Regular, FILE_PERM),
                vfs::default_inode_ops(),
                Arc::new(RecordFileOps),
            )
            .fsid(PSTOREFS_MAGIC)
            .size(len)
            .times(t, t, t)
            .private(Arc::new(RecordFile { id: r.id, body: r.body }))
            .build();
            g.children.insert(name, inode);
        }
    }
}

/// Build one pstore mount: install what the options asked for, then publish
/// every record the backend holds.
///
/// A mount with no backend is a mount with no records — not a failure. The
/// reference says so explicitly, and a machine whose region could not be
/// reserved must still be able to mount `/sys/fs/pstore`.
/// # C: O(region length)
pub fn mount(data: &str, pinned: &[vfs::fs::FsParameter]) -> KResult<Arc<PstoreFs>> {
    if let Some(v) = crate::kmsg::kmsg_bytes_for_mount(data, pinned) {
        crate::kmsg::set_kmsg_bytes(v);
    }
    let root = Root::new();
    root.publish(psinfo::records());
    Ok(Arc::new(PstoreFs { tree: root }))
}

impl vfs::fs::FileSystem for PstoreFs {
    /// # C: O(1)
    fn name(&self) -> &str { "pstore" }
    /// # C: O(1)
    fn magic(&self) -> u64 { PSTOREFS_MAGIC }
    /// # C: O(1)
    fn root(&self) -> Option<InodeRef> { Some(self.tree.as_inode()) }
    /// # C: O(1)
    fn show_options(&self) -> String { crate::kmsg::show_options() }
    /// # C: O(1)
    fn set_sb(&self, _sb: Weak<SuperBlock>) -> vfs::fs::KResult<()> { Ok(()) }
}

#[cfg(test)]
#[path = "tests/fs.rs"]
mod tests;
