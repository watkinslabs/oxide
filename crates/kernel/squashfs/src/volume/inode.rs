//! Turning an inode reference into a parsed inode.
//!
//! An inode reference names a metadata block and an offset inside it. The
//! sixteen bytes common to every type come first; the type word in them says
//! how many more bytes follow and what they mean. The BASIC and EXTENDED forms
//! of a type are different lengths with different field orders, so the type
//! word is read before anything after it is believed.

use alloc::vec::Vec;

use sectors::SectorSource;
use syscall::errno::Errno;

use crate::limits::SYMLINK_MAX;
use crate::superblock::{inode_block, inode_offset};
use crate::uapi::{itype, size, INVALID_FRAG, INVALID_XATTR};

use super::meta::Cursor;
use super::Volume;

/// A file's tail, when it shares a block with other files' tails.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Fragment {
    /// Byte address of the fragment block on the medium.
    pub block: u64,
    /// The fragment block's own length word, still encoded.
    pub size_word: u32,
    /// Where this file's tail starts inside the DECOMPRESSED fragment block.
    pub offset: u32,
}

/// What a parsed inode is, beyond the fields every type carries.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Kind {
    Dir {
        /// Metadata block of the directory listing, relative to the directory
        /// table.
        start_block: u32,
        /// Offset of the listing within that block.
        offset: u16,
        /// Inode number of the parent, which this filesystem stores because it
        /// does not store a `..` entry.
        parent: u32,
        /// The name index, when the directory carries one.
        index: Option<DirIndexLoc>,
    },
    Reg {
        /// Byte address of the file's first whole block.
        start: u64,
        /// One still-encoded length word per whole block, in file order. Read
        /// at parse time because a block's ADDRESS is the sum of every length
        /// before it: walking the list per read would decompress the same
        /// metadata blocks once per block of the file.
        blocks: Vec<u32>,
        fragment: Option<Fragment>,
    },
    Symlink { target: Vec<u8> },
    Device,
    Fifo,
    Socket,
}

/// Where a directory's name index lives, and how many entries it has.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct DirIndexLoc {
    pub cursor: Cursor,
    pub count: u16,
}

/// One inode of a mounted volume.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Inode {
    pub ino: u32,
    pub type_word: u16,
    /// Permission and set-id bits only. The FILE TYPE is carried by
    /// [`Inode::type_word`]; an image whose stored mode already names a type is
    /// refused, because two answers to what a thing is cannot both be trusted.
    pub perm: u16,
    pub uid: u32,
    pub gid: u32,
    pub mtime: u32,
    pub nlink: u32,
    pub size: u64,
    pub rdev: u32,
    pub xattr: u32,
    pub kind: Kind,
}

/// Bits of a stored mode that name a file TYPE.
const S_IFMT: u16 = 0o170000;

fn u16_at(b: &[u8], off: usize) -> u16 { u16::from_le_bytes([b[off], b[off + 1]]) }
fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    w.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(w)
}

impl<S: SectorSource> Volume<S> {
    /// Where an inode reference points, in the metadata stream. # C: O(1)
    pub(super) fn inode_cursor(&self, reference: u64) -> Cursor {
        Cursor::new(self.sb.inode_table_start + inode_block(reference),
                    inode_offset(reference) as usize)
    }

    /// Read and parse one inode.
    /// # C: O(inode bytes + symlink bytes)
    pub fn read_inode(&self, reference: u64) -> Result<Inode, Errno> {
        let mut cur = self.inode_cursor(reference);
        let base = self.read_meta(&mut cur, size::BASE_INODE)?;
        let type_word = u16_at(&base, 0);
        let mode = u16_at(&base, 2);
        if mode & S_IFMT != 0 { return Err(Errno::Eio); }
        let ino = u32_at(&base, 12);
        if ino == 0 { return Err(Errno::Einval); }
        let mut node = Inode {
            ino,
            type_word,
            perm: mode,
            uid: self.id_of(u16_at(&base, 4))?,
            gid: self.id_of(u16_at(&base, 6))?,
            mtime: u32_at(&base, 8),
            nlink: 1,
            size: 0,
            rdev: 0,
            xattr: INVALID_XATTR,
            kind: Kind::Fifo,
        };
        // Every type re-reads from the START of the inode, because the tail
        // layouts overlap the sixteen common bytes rather than following them.
        let mut cur = self.inode_cursor(reference);
        match type_word {
            itype::REG => self.parse_reg(&mut node, &mut cur)?,
            itype::LREG => self.parse_lreg(&mut node, &mut cur)?,
            itype::DIR => self.parse_dir(&mut node, &mut cur)?,
            itype::LDIR => self.parse_ldir(&mut node, &mut cur)?,
            itype::SYMLINK | itype::LSYMLINK => self.parse_symlink(&mut node, &mut cur)?,
            itype::BLKDEV | itype::CHRDEV => self.parse_dev(&mut node, &mut cur, false)?,
            itype::LBLKDEV | itype::LCHRDEV => self.parse_dev(&mut node, &mut cur, true)?,
            itype::FIFO | itype::SOCKET => self.parse_ipc(&mut node, &mut cur, false)?,
            itype::LFIFO | itype::LSOCKET => self.parse_ipc(&mut node, &mut cur, true)?,
            _ => return Err(Errno::Einval),
        }
        Ok(node)
    }

    fn parse_reg(&self, node: &mut Inode, cur: &mut Cursor) -> Result<(), Errno> {
        let b = self.read_meta(cur, size::REG_INODE)?;
        node.size = u64::from(u32_at(&b, 28));
        let fragment = self.tail(node.size, u32_at(&b, 20), u32_at(&b, 24))?;
        node.kind = Kind::Reg {
            start: u64::from(u32_at(&b, 16)),
            blocks: self.read_block_list(cur, node.size, fragment.is_some())?,
            fragment,
        };
        Ok(())
    }

    fn parse_lreg(&self, node: &mut Inode, cur: &mut Cursor) -> Result<(), Errno> {
        let b = self.read_meta(cur, size::LREG_INODE)?;
        node.size = u64_at(&b, 24);
        node.nlink = u32_at(&b, 40);
        node.xattr = u32_at(&b, 52);
        let fragment = self.tail(node.size, u32_at(&b, 44), u32_at(&b, 48))?;
        node.kind = Kind::Reg {
            start: u64_at(&b, 16),
            blocks: self.read_block_list(cur, node.size, fragment.is_some())?,
            fragment,
        };
        Ok(())
    }

    /// A file's tail, if it has one.
    ///
    /// A file whose length is a whole multiple of the block size has no tail
    /// to pack, so an inode that names a fragment anyway is self-inconsistent
    /// and is refused. Reading its fragment would return a real block of some
    /// other file's bytes.
    fn tail(&self, file_size: u64, frag: u32, offset: u32) -> Result<Option<Fragment>, Errno> {
        if frag == INVALID_FRAG { return Ok(None); }
        if file_size & u64::from(self.sb.block_size - 1) == 0 { return Err(Errno::Einval); }
        let (block, size_word) = self.fragment_entry(frag)?;
        Ok(Some(Fragment { block, size_word, offset }))
    }

    /// One fragment table entry: where the shared block is and how long it is.
    /// # C: O(1)
    pub(super) fn fragment_entry(&self, frag: u32) -> Result<(u64, u32), Errno> {
        if frag >= self.sb.fragments { return Err(Errno::Eio); }
        let byte = frag as usize * size::FRAGMENT_ENTRY;
        let mut cur = self.fragment_cursor(byte)?;
        let b = self.read_meta(&mut cur, size::FRAGMENT_ENTRY)?;
        Ok((u64_at(&b, 0), u32_at(&b, 8)))
    }

    fn parse_dir(&self, node: &mut Inode, cur: &mut Cursor) -> Result<(), Errno> {
        let b = self.read_meta(cur, size::DIR_INODE)?;
        node.nlink = u32_at(&b, 20);
        node.size = u64::from(u16_at(&b, 24));
        node.kind = Kind::Dir {
            start_block: u32_at(&b, 16),
            offset: u16_at(&b, 26),
            parent: u32_at(&b, 28),
            index: None,
        };
        Ok(())
    }

    fn parse_ldir(&self, node: &mut Inode, cur: &mut Cursor) -> Result<(), Errno> {
        let b = self.read_meta(cur, size::LDIR_INODE)?;
        node.nlink = u32_at(&b, 16);
        node.size = u64::from(u32_at(&b, 20));
        node.xattr = u32_at(&b, 36);
        let count = u16_at(&b, 32);
        node.kind = Kind::Dir {
            start_block: u32_at(&b, 24),
            offset: u16_at(&b, 34),
            parent: u32_at(&b, 28),
            // The index follows the inode, so its cursor is wherever reading
            // the inode left off.
            index: if count == 0 { None } else { Some(DirIndexLoc { cursor: *cur, count }) },
        };
        Ok(())
    }

    fn parse_symlink(&self, node: &mut Inode, cur: &mut Cursor) -> Result<(), Errno> {
        let b = self.read_meta(cur, size::SYMLINK_INODE)?;
        node.nlink = u32_at(&b, 16);
        let len = u64::from(u32_at(&b, 20));
        if len == 0 || len > SYMLINK_MAX { return Err(Errno::Einval); }
        node.size = len;
        let target = self.read_meta(cur, len as usize)?;
        if node.type_word == itype::LSYMLINK {
            let x = self.read_meta(cur, size::BLOCK_LIST_ENTRY)?;
            node.xattr = u32_at(&x, 0);
        }
        node.kind = Kind::Symlink { target };
        Ok(())
    }

    fn parse_dev(&self, node: &mut Inode, cur: &mut Cursor, extended: bool) -> Result<(), Errno> {
        let want = if extended { size::LDEV_INODE } else { size::DEV_INODE };
        let b = self.read_meta(cur, want)?;
        node.nlink = u32_at(&b, 16);
        node.rdev = u32_at(&b, 20);
        if extended { node.xattr = u32_at(&b, 24); }
        node.kind = Kind::Device;
        Ok(())
    }

    fn parse_ipc(&self, node: &mut Inode, cur: &mut Cursor, extended: bool) -> Result<(), Errno> {
        let want = if extended { size::LIPC_INODE } else { size::IPC_INODE };
        let b = self.read_meta(cur, want)?;
        node.nlink = u32_at(&b, 16);
        if extended { node.xattr = u32_at(&b, 20); }
        node.kind = match node.type_word {
            itype::SOCKET | itype::LSOCKET => Kind::Socket,
            _ => Kind::Fifo,
        };
        Ok(())
    }
}
