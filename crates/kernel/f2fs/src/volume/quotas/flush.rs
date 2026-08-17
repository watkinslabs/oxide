//! Putting changed records back into their files, at checkpoint.

use alloc::vec::Vec;

use crate::quota::{self, Dqblk};
use crate::uapi::{BLKSIZE, I_SIZE, MAX_QUOTAS};
use crate::volume::dnode::put64;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::volume::Volume;

/// Whether a record has nothing left to say: no limits, and nothing in use.
///
/// Such a record is removed rather than kept, the way the reference drops a
/// record whose last reference goes while it holds nothing. Keeping it would
/// make a quota file grow once per identity that ever allocated a byte and
/// never shrink.
/// # C: O(1)
fn unused_record(d: &Dqblk) -> bool {
    d.bhardlimit == 0
        && d.bsoftlimit == 0
        && d.ihardlimit == 0
        && d.isoftlimit == 0
        && d.curspace == 0
        && d.curinodes == 0
}

impl<S: SectorSource> Volume<S> {
    /// Write every changed record back into its file.
    ///
    /// Runs at checkpoint, with the rest of the volume's counts. A record the
    /// tree has no slot for GETS one: the first allocation by an identity is
    /// exactly the case with no slot, so a checkpoint that dropped it would
    /// leave every new uid, gid and project unaccounted for good. A record
    /// with nothing left in it is removed instead of written, which is what
    /// keeps the file from keeping a slot for every identity that ever
    /// touched the volume.
    /// # C: O(dirty ids * file bytes)
    pub(crate) fn flush_quotas(&mut self) -> Result<(), Errno> {
        if self.dq_dirty.is_empty() { return Ok(()); }
        let dirty: Vec<(usize, u32)> = self.dq_dirty.iter().copied().collect();
        for kind in 0..MAX_QUOTAS {
            let ids: Vec<u32> = dirty.iter().filter(|(k, _)| *k == kind).map(|(_, i)| *i).collect();
            if ids.is_empty() { continue; }
            let ino = self.quota_setup[kind].ino;
            if ino == 0 { continue; }
            // The header is HELD, not re-read. It is brought in when the kind
            // is acquired, and the reference keeps it as a field of the live
            // quota state rather than going back to the file for it at commit
            // — which is what keeps a whole quota-file read out from under
            // every checkpoint. A kind holding no header was never acquired, so
            // it has nothing dirty to write.
            let Some(mut info) = self.dq_info_held(kind) else { continue };
            let mut file = self.read_quota_file(ino)?;
            let mut touched = false;
            for id in ids {
                let Some(d) = self.dquots.get(&(kind, id)).cloned() else { continue };
                let r = if unused_record(&d) {
                    quota::tree::delete(&mut file, &mut info, id)
                } else {
                    quota::tree::write_or_create(&mut file, &mut info, id, &d)
                };
                r.map_err(|e| e.errno())?;
                touched = true;
            }
            if touched {
                // The header carries the block count and both free lists, so
                // a tree that grew and a header that did not describes a file
                // whose new blocks nothing can find again.
                quota::info::store(&mut file, &info).map_err(|e| e.errno())?;
                self.quota_info[kind] = Some(info);
                self.write_quota_file(ino, &file)?;
            }
        }
        self.dq_dirty.clear();
        Ok(())
    }

    /// Put a quota file's bytes back.
    ///
    /// Written through the ordinary file path, so the blocks it occupies are
    /// allocated and accounted like any other — except for the charge, which
    /// `is_quota_file` suppresses.
    /// # C: O(file bytes)
    fn write_quota_file(&mut self, ino: u32, bytes: &[u8]) -> Result<(), Errno> {
        for (i, chunk) in bytes.chunks(BLKSIZE).enumerate() {
            self.write_one_block(ino, i as u64, 0, chunk)?;
        }
        // A tree that grew put blocks PAST the inode's recorded length, and a
        // read of the file stops at that length: the header would hand back
        // more blocks than the file has, and the next mount would refuse its
        // own quota file as corrupt. The block count moves with it, because a
        // file that occupies blocks it does not admit to is what a check
        // reports as a leak.
        let len = bytes.len() as u64;
        if self.read_inode(ino)?.size < len {
            let blocks = self.count_blocks(ino)?;
            self.stamp_inode(ino, |b| {
                put64(b, I_SIZE, len);
                Self::set_iblocks(b, blocks);
            })?;
        }
        // Placed here rather than left to the next flush point: this is called
        // from inside the checkpoint, PAST the point that would have placed
        // it, and the checkpoint that records these counts is the same one
        // that has to be able to find the blocks holding them.
        self.flush_data_pages(ino)
    }
}
