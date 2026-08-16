//! An inode's attribute region, assembled from its two halves.

use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::node::Inode;
use crate::xattr;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// The whole attribute region of `inode`, inline part first.
    ///
    /// The two halves are joined before anything is read out of them because
    /// a record may begin in the inline part and end in the block; searching
    /// them separately would lose it and report a corrupt tail.
    /// # C: O(region bytes)
    pub fn xattr_area(&self, inode: &Inode, ino: u32) -> Result<Vec<u8>, Errno> {
        let inline = match inode.inline_xattr_span() {
            Some((at, len)) => {
                let n = self.read_inode_ref(ino)?.1;
                n.block.get(at..at + len).ok_or(Errno::Eio)?.to_vec()
            }
            None => Vec::new(),
        };
        let block = self.read_xattr_node(inode, ino)?;
        Ok(xattr::joined(&inline, block.as_deref()))
    }

    /// One attribute's value, by the name a caller passes. # C: O(region bytes)
    pub fn get_xattr(&self, inode: &Inode, ino: u32, name: &str) -> Result<Vec<u8>, Errno> {
        let (index, rest) = xattr::split_name(name).ok_or(Errno::Eopnotsupp)?;
        let area = self.xattr_area(inode, ino)?;
        xattr::get(&area, index, rest).map_err(|_| Errno::Eio)?.ok_or(Errno::Enodata)
    }

    /// Every attribute name, zero-terminated, in the order they are stored.
    /// # C: O(region bytes)
    pub fn list_xattr(&self, inode: &Inode, ino: u32) -> Result<Vec<u8>, Errno> {
        let area = self.xattr_area(inode, ino)?;
        xattr::names(&area).map_err(|_| Errno::Eio)
    }
}
