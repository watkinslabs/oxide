//! Driving a replay: what has to be true before the first write, and in what
//! order the chain's blocks are put back.
//!
//! One ordering constraint dominates everything else. Replay WRITES — it
//! rewrites nodes, it may create an inode, it may add a directory entry — and
//! every one of those writes is taken from the tail of a log. The chain being
//! replayed sits at exactly those tails, because that is where the crashed
//! mount left it. So before anything is written, every block the chain names
//! is marked live and every log standing over one is moved to a fresh
//! segment. Skipping that reads half a chain and then overwrites the rest.
//!
//! The chain's own node blocks are garbage once replayed: their addresses go
//! into live nodes written elsewhere, and nothing points at the originals. The
//! one exception is an attribute node, which recovery adopts where it lies.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::{DATA_EXIST, EXTRA_ATTR, INLINE_XATTR, PIN_FILE};
use crate::uapi::*;
use crate::volume::dnode::{put16, put32, put64};
use crate::volume::namei::ftype_byte;
use crate::volume::Volume;

use super::marks;
use super::scan::Found;

/// What a mount's recovery pass did.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Replayed {
    /// Node blocks of the chain that were put back.
    pub nodes: u32,
    /// Inodes whose stored fields were restored.
    pub inodes: u32,
    /// Directory entries re-added.
    pub dentries: u32,
    /// Data blocks pointed at again.
    pub blocks: u32,
}

/// The outcome of looking for a crash's tail.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Recovery {
    /// Nothing followed the checkpoint.
    Clean,
    /// A chain was found and replayed.
    Replayed(Replayed),
    /// A chain was found and the mount may not write.
    Skipped,
}

impl<S: SectorSource> Volume<S> {
    /// Replay everything an `fsync` promised since the last checkpoint, and
    /// checkpoint the result.
    /// # C: O(chain length) blocks
    pub fn recover(&mut self) -> Result<Recovery, Errno> {
        self.writable_or_err()?;
        let found = self.scan_fsync_chain()?;
        if found.is_empty() { return Ok(Recovery::Clean); }
        self.load_segments()?;
        self.protect_chain(&found)?;
        let live = self.resolve_inodes(&found)?;
        let last_dentry = last_dentry_of(&found, &live);
        let mut done = Replayed::default();
        for f in &found {
            if !live.contains(&f.ino) { continue; }
            let rec = self.read_main_block(f.addr)?;
            if f.is_inode {
                self.recover_inode_meta(f.ino, &rec)?;
                done.inodes += 1;
            }
            if f.dent && last_dentry.get(&f.ino) == Some(&f.addr) && self.recover_dentry(f.ino, &rec)? {
                done.dentries += 1;
            }
            done.blocks += self.recover_node_data(f.ino, f)?;
            done.nodes += 1;
        }
        for f in &found {
            if f.ofs == marks::xattr_node_offset() { continue; }
            self.release_block(f.addr)?;
        }
        self.dirty = true;
        self.commit()?;
        Ok(Recovery::Replayed(done))
    }

    /// Keep the chain and everything it names out of the allocator's reach,
    /// then move every log that is standing on one of those blocks.
    /// # C: O(chain length) blocks
    fn protect_chain(&mut self, found: &[Found]) -> Result<(), Errno> {
        let mut protected: Vec<u32> = Vec::new();
        for f in found {
            protected.push(f.addr);
            if f.ofs == marks::xattr_node_offset() { continue; }
            let rec = self.read_main_block(f.addr)?;
            // The array's start differs by shape: an inode's is pushed down by
            // its extra attributes. Reading a direct node's layout out of an
            // inode would take header words for addresses and mark unrelated
            // blocks live, which loses them until a checker runs.
            let (base, count) = if f.is_inode {
                let Some(i) = crate::node::inode::parse(&rec, self.sb.feature) else { continue };
                // An inode holding its file's BYTES has no address array: the
                // same region holds the contents. Reading them as addresses
                // marks live whatever the file's own text happens to decode
                // to, which takes a block out of the allocator's hands and
                // raises the count for a block nothing points at.
                if i.inline_data() || i.inline_dentry() { continue; }
                (i.addr_base(), i.addrs_per_inode())
            } else {
                (0usize, DEF_ADDRS_PER_BLOCK)
            };
            for i in 0..count {
                let Some(a) = le32(&rec, base + i * 4) else { break };
                if !crate::node::is_hole(a) && self.sb.valid_main_blkaddr(a) { protected.push(a); }
            }
        }
        for &a in &protected { self.update_seg(a, true)?; }
        for log in 0..NR_CURSEG_PERSIST_TYPE {
            let segno = self.curseg[log].segno;
            let stands_on = protected
                .iter()
                .any(|&a| self.sb.segno_of(a) == Some(segno));
            if stands_on { self.open_segment(log)?; }
        }
        Ok(())
    }

    /// Which of the chain's inodes recovery can put blocks back into.
    ///
    /// An inode the checkpoint never saw exists only in the chain, and only a
    /// block carrying BOTH the inode shape and the dentry mark may be used to
    /// create it — that mark is the crashed mount's statement that the file
    /// was new and its whole identity is in this block.
    /// # C: O(chain length) blocks
    fn resolve_inodes(&mut self, found: &[Found]) -> Result<BTreeSet<u32>, Errno> {
        let mut live = BTreeSet::new();
        for f in found {
            if live.contains(&f.ino) { continue; }
            if self.read_inode(f.ino).is_ok() { live.insert(f.ino); continue; }
            if !(f.is_inode && f.dent) { continue; }
            let rec = self.read_main_block(f.addr)?;
            self.create_recovered_inode(f.ino, &rec)?;
            live.insert(f.ino);
        }
        Ok(live)
    }

    /// Put back an inode the checkpoint has no entry for.
    ///
    /// Only the identity is taken from the recovered block: size, block count,
    /// link count, attribute node and every stored address are reset, because
    /// each of those is restored — or deliberately not — by the passes that
    /// follow, and taking them here would name nodes the table cannot resolve.
    /// # C: O(1 block)
    fn create_recovered_inode(&mut self, ino: u32, rec: &[u8]) -> Result<(), Errno> {
        let mut block = alloc::vec![0u8; BLKSIZE];
        block[..I_EXT].copy_from_slice(&rec[..I_EXT]);
        let inline = rec[I_INLINE] & (INLINE_XATTR | EXTRA_ATTR);
        block[I_INLINE] = inline;
        put64(&mut block, I_SIZE, 0);
        put64(&mut block, I_BLOCKS, 1);
        put32(&mut block, I_LINKS, 1);
        put32(&mut block, I_XATTR_NID, 0);
        if inline & EXTRA_ATTR != 0 {
            let extra = le16(rec, I_EXTRA_ISIZE).unwrap_or(0);
            put16(&mut block, I_EXTRA_ISIZE, extra);
            let end = I_EXTRA_ISIZE + extra as usize;
            if end <= BLKSIZE && end > I_EXTRA_ISIZE {
                block[I_EXTRA_ISIZE..end].copy_from_slice(&rec[I_EXTRA_ISIZE..end]);
            }
            put32(&mut block, I_INODE_CHECKSUM, 0);
        }
        marks::set_flag(&mut block, marks::flag_word(0, false, false, true));
        self.write_node(ino, ino, block, crate::volume::curseg::Kind::FileNode)?;
        self.valid_inode_count += 1;
        Ok(())
    }

    /// Restore the fields a recovered inode block carries.
    ///
    /// Deliberately NOT restored: the link count, the block count, the
    /// attribute node and the stored addresses. Those describe the file's
    /// shape, which the address replay decides; taking them from a block
    /// written before the replay would double-count or orphan blocks.
    /// # C: O(1 block)
    fn recover_inode_meta(&mut self, ino: u32, rec: &[u8]) -> Result<(), Errno> {
        let keep = [
            (I_MODE, 2usize), (I_UID, 4), (I_GID, 4), (I_SIZE, 8),
            (I_ATIME, 8), (I_CTIME, 8), (I_MTIME, 8),
            (I_ATIME_NSEC, 4), (I_CTIME_NSEC, 4), (I_MTIME_NSEC, 4),
            (I_ADVISE, 1), (I_FLAGS, 4),
        ];
        let mut block = self.inode_bytes(ino)?;
        for (at, len) in keep { block[at..at + len].copy_from_slice(&rec[at..at + len]); }
        let hints = PIN_FILE | DATA_EXIST;
        block[I_INLINE] = (block[I_INLINE] & !hints) | (rec[I_INLINE] & hints);
        self.put_inode(ino, block)
    }

    /// Re-add the directory entry a recovered inode names, when it is missing.
    /// # C: O(directory depth) blocks
    fn recover_dentry(&mut self, ino: u32, rec: &[u8]) -> Result<bool, Errno> {
        let pino = le32(rec, I_PINO).ok_or(Errno::Eio)?;
        let len = le32(rec, I_NAMELEN).ok_or(Errno::Eio)? as usize;
        if len == 0 || len > NAME_LEN { return Err(Errno::Eio); }
        let name: Vec<u8> = rec[I_NAME..I_NAME + len].to_vec();
        let Ok(dir) = self.read_inode(pino) else { return Ok(false) };
        if let Ok(e) = self.lookup(&dir, pino, &name) {
            if e.ino == ino { return Ok(false); }
        }
        let mode_word = le16(rec, I_MODE).ok_or(Errno::Eio)?;
        self.add_dentry(pino, &name, ino, ftype_byte(mode_word))?;
        Ok(true)
    }
}

/// The LAST inode block of each file in the chain, which is the only one whose
/// name is still current. An earlier one may name a directory entry a later
/// rename replaced. # C: O(chain length)
fn last_dentry_of(found: &[Found], live: &BTreeSet<u32>) -> BTreeMap<u32, u32> {
    let mut out = BTreeMap::new();
    for f in found {
        if f.is_inode && f.dent && live.contains(&f.ino) { out.insert(f.ino, f.addr); }
    }
    out
}

#[cfg(test)]
#[path = "../../tests/recover/protect.rs"]
mod tests;
