//! A file's bytes, in both directions.
//!
//! Two lengths govern every read. `size` is what the allocation covers;
//! `valid_size` is how far the file has actually been written. Bytes between
//! the two exist on the medium but were never written by anyone — they are the
//! previous owner's — so a read of them returns ZEROS. Returning what is there
//! hands one user's data to another.

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::uapi::MAX_NUM_CLUSTER;

use super::Volume;

impl<S: SectorSource> Volume<S> {
    /// Reserve clusters through the requested range without changing the
    /// visible file size. # C: O(clusters allocated)
    pub fn preallocate_file(&mut self, entry: &mut super::DirEntry, offset: u64, len: u64,
                            now: crate::time::Stamp) -> Result<(), Errno> {
        if entry.set.is_dir() { return Err(Errno::Eisdir); }
        if !self.writable { return Err(Errno::Erofs); }
        let end = offset.checked_add(len).ok_or(Errno::Efbig)?;
        if end > self.geo.max_bytes() { return Err(Errno::Efbig); }
        if len == 0 || end <= entry.set.stream.size { return Ok(()); }
        let mut chain = self.chain_of(&entry.set);
        let needed = self.geo.clusters_for(end);
        if needed > chain.size {
            let more = needed - chain.size;
            self.alloc_clusters(&mut chain, more, false)?;
        }
        entry.set.stream.start_cluster = if chain.is_empty() { 0 } else { chain.dir };
        entry.set.stream.flags = chain.flags;
        entry.set.stream.size = u64::from(chain.size) * self.geo.cluster_bytes();
        entry.set.file.modify = now;
        self.write_entry_set(entry)
    }

    /// Read from a file, returning how many bytes were read.
    ///
    /// A read stops at the file's length: the tail of the last cluster is not
    /// part of the file, and returning it appends whatever the medium last
    /// held there.
    /// # C: O(bytes read)
    pub fn read_file(&self, entry: &super::DirEntry, offset: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        if entry.set.is_dir() { return Err(Errno::Eisdir); }
        let size = entry.set.stream.valid_size;
        if offset >= size { return Ok(0); }
        let want = core::cmp::min(buf.len() as u64, size - offset) as usize;
        if want == 0 { return Ok(0); }
        let chain = self.chain_of(&entry.set);
        self.read_at(&chain, offset, &mut buf[..want])?;
        Ok(want)
    }

    /// The whole of a file. # C: O(file bytes)
    pub fn read_whole(&self, entry: &super::DirEntry) -> Result<alloc::vec::Vec<u8>, Errno> {
        let len = usize::try_from(entry.set.stream.valid_size).map_err(|_| Errno::Einval)?;
        let mut out = alloc::vec![0u8; len];
        let got = self.read_file(entry, 0, &mut out)?;
        out.truncate(got);
        Ok(out)
    }

    /// Write to a file, growing it if the write reaches past its end.
    ///
    /// Returns the file's length afterwards. A write that begins past the
    /// current end leaves a gap, and the gap is ZEROED rather than left as
    /// whatever the freshly allocated clusters held.
    /// # C: O(bytes written + clusters allocated)
    pub fn write_file(&mut self, entry: &mut super::DirEntry, offset: u64, buf: &[u8],
                      now: crate::time::Stamp) -> Result<u64, Errno> {
        if entry.set.is_dir() { return Err(Errno::Eisdir); }
        if !self.writable { return Err(Errno::Erofs); }
        if buf.is_empty() { return Ok(entry.set.stream.valid_size); }
        let end = offset.checked_add(buf.len() as u64).ok_or(Errno::Efbig)?;
        if end > self.geo.max_bytes() { return Err(Errno::Efbig); }

        let old_valid = entry.set.stream.valid_size;
        let mut chain = self.chain_of(&entry.set);
        let needed = self.geo.clusters_for(end);
        if needed > chain.size {
            if needed > MAX_NUM_CLUSTER { return Err(Errno::Efbig); }
            let more = needed - chain.size;
            self.alloc_clusters(&mut chain, more, false)?;
        }

        // The gap between the old end and this write is zeroed before the
        // write lands, so a reader of that span never sees the clusters' old
        // contents.
        if offset > old_valid { self.zero_span(&chain, old_valid, offset - old_valid)?; }
        self.write_at(&chain, offset, buf)?;

        entry.set.stream.start_cluster = if chain.is_empty() { 0 } else { chain.dir };
        entry.set.stream.flags = chain.flags;
        entry.set.stream.valid_size = core::cmp::max(old_valid, end);
        // The allocation covers whole clusters, and the recorded size says so:
        // a size smaller than the allocation makes the last cluster look free
        // to a checker.
        entry.set.stream.size = core::cmp::max(entry.set.stream.size,
                                           u64::from(chain.size) * self.geo.cluster_bytes());
        entry.set.file.modify = now;
        entry.set.file.access = crate::time::without_centiseconds(now);
        entry.set.file.attr = crate::attrs::mark_archived(entry.set.file.attr);
        self.write_entry_set(entry)?;
        Ok(entry.set.stream.valid_size)
    }

    /// Set a file's length, in either direction.
    ///
    /// Growing ALLOCATES and zeroes: exFAT records a valid size, so a longer
    /// file whose tail was never written would otherwise read the clusters'
    /// old contents.
    /// # C: O(clusters changed)
    pub fn truncate_file(&mut self, entry: &mut super::DirEntry, len: u64, now: crate::time::Stamp)
        -> Result<(), Errno> {
        if entry.set.is_dir() { return Err(Errno::Eisdir); }
        if !self.writable { return Err(Errno::Erofs); }
        if len > self.geo.max_bytes() { return Err(Errno::Efbig); }
        let old = entry.set.stream.valid_size;
        let mut chain = self.chain_of(&entry.set);
        if len > old {
            let needed = self.geo.clusters_for(len);
            if needed > chain.size {
                let more = needed - chain.size;
                self.alloc_clusters(&mut chain, more, false)?;
            }
            self.zero_span(&chain, old, len - old)?;
        } else if len < old {
            let keep = self.geo.clusters_for(len);
            self.truncate_chain(&mut chain, keep)?;
        }
        entry.set.stream.start_cluster = if chain.is_empty() { 0 } else { chain.dir };
        entry.set.stream.flags = chain.flags;
        entry.set.stream.valid_size = len;
        entry.set.stream.size = u64::from(chain.size) * self.geo.cluster_bytes();
        entry.set.file.modify = now;
        entry.set.file.access = crate::time::without_centiseconds(now);
        entry.set.file.attr = crate::attrs::mark_archived(entry.set.file.attr);
        self.write_entry_set(entry)
    }

    /// Fill a span of a run with zeros. # C: O(len)
    pub(crate) fn zero_span(&self, chain: &crate::chain::Chain, offset: u64, len: u64)
        -> Result<(), Errno> {
        let per = usize::try_from(self.geo.cluster_bytes()).map_err(|_| Errno::Einval)?;
        let zeros = alloc::vec![0u8; per];
        let mut done = 0u64;
        while done < len {
            let take = core::cmp::min(per as u64, len - done);
            self.write_at(chain, offset + done, &zeros[..take as usize])?;
            done += take;
        }
        Ok(())
    }
}
