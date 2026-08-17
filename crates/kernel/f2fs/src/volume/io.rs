//! A file's bytes.
//!
//! Two sources, and which one a file uses is a per-inode flag rather than a
//! per-volume one: a small file's data lives INSIDE the inode block, in the
//! space the address array would otherwise occupy. Reading such a file through
//! the address array reads its own bytes as block addresses.
//!
//! A hole reads as zeroes, not as an error and not as whatever the address
//! zero happens to hold.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::flags::DATA_EXIST;
use crate::limits::MAX_IO_BYTES;
use crate::node::Inode;
use crate::uapi::BLKSIZE;

use super::map::Mapped;
use super::Volume;

/// One unpacked cluster, and the file block its first byte belongs to.
struct Plain {
    first: u64,
    data: Vec<u8>,
}

/// What a caller sees when a cluster cannot be unpacked.
///
/// A codec this build does not carry is `EOPNOTSUPP` — the data is intact and
/// another reader could have it. Anything else means the cluster does not
/// describe itself, which is an I/O error.
/// # C: O(1)
fn compress_errno(e: crate::compress::CompressError) -> Errno {
    match e {
        crate::compress::CompressError::UnsupportedAlgorithm(_)
        | crate::compress::CompressError::UnknownAlgorithm(_) => Errno::Eopnotsupp,
        _ => Errno::Eio,
    }
}

impl<S: SectorSource> Volume<S> {
    /// Read from `inode` at byte offset `off` into `buf`.
    ///
    /// Reads stop at the file's size: the last block is whole on the medium
    /// and its tail is padding, so returning it would return bytes the file
    /// does not have.
    /// # C: O(bytes read)
    pub fn read_file(&self, inode: &Inode, ino: u32, off: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        let got = self.read_file_inner(inode, ino, off, buf)?;
        // What the APPLICATION asked for, which is not what the medium moved:
        // a read served from inline data or from a hole touches no block at
        // all, and one that spans a compressed cluster unpacks more blocks
        // than it returns. Both figures are wanted, so the application's is
        // taken here and the medium's at the blocks themselves.
        self.io_account(crate::stats::iostat::Io::AppBufferedRead, got as u64,
                        inode.compressed());
        Ok(got)
    }

    /// # C: O(bytes read)
    pub(super) fn read_file_inner(&self, inode: &Inode, ino: u32, off: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        // The writer of an open span must see its own writes, which live in
        // the shadow inode rather than in this one.
        if self.is_atomic_file(ino) { return self.atomic_read_file(inode, ino, off, buf); }
        if off >= inode.size { return Ok(0); }
        // A verity file's stored size is its DATA size; its blocks run past it
        // and hold the hash tree and the descriptor. Every ordinary read is
        // clamped to the data, or the tree is served as file content.
        if inode.verity() && !crate::verity::location::is_data(inode.size, off, buf.len() as u64) {
            return Err(Errno::Eio);
        }
        let want = buf.len().min((inode.size - off) as usize).min(MAX_IO_BYTES);
        if want == 0 { return Ok(0); }
        if inode.inline_data() { return self.read_inline(inode, ino, off, &mut buf[..want]); }
        // An encrypted file's blocks hold ciphertext. Without the key there is
        // nothing to return but the ciphertext, which would be the wrong bytes
        // rather than no bytes.
        let crypt = self.crypt_require_key(inode, ino)?;
        // The window the CALLER asked for, fetched before it is served block
        // by block below. The same blocks either way; the difference is that a
        // contiguous run of them goes to the medium once instead of once per
        // block, and the loop below then finds them in the mapping.
        let first = off / BLKSIZE as u64;
        let last = (off + want as u64 - 1) / BLKSIZE as u64;
        self.readahead_data(inode, ino, first, (last - first + 1) as usize);
        let mut done = 0usize;
        while done < want {
            let pos = off + done as u64;
            let index = pos / BLKSIZE as u64;
            let skew = (pos % BLKSIZE as u64) as usize;
            let take = (BLKSIZE - skew).min(want - done);
            // THE MAPPING FIRST, the node tree second. A buffered write that
            // has not been placed yet has no address at all — its slot holds a
            // reservation, which the tree reports as a hole — so asking the
            // tree first would answer a write this filesystem had already
            // accepted with zeroes. The mapping holds plaintext, already
            // attested where the file is sealed, so nothing below is owed.
            if let Some(page) = self.data_cache.peek(ino, index) {
                buf[done..done + take].copy_from_slice(&page[skew..skew + take]);
                done += take;
                continue;
            }
            match self.map_cluster_block(inode, ino, index)? {
                // A hole in a verity file's DATA is not padding: the tree
                // holds a hash for that block, and the zeroes a hole returns
                // have to match it. Serving them unchecked would let an image
                // drop a block address and have the reader hand back zeroes
                // the tree never attested to.
                Mapped::Hole => {
                    if inode.verity() {
                        let zeroes = alloc::vec![0u8; BLKSIZE];
                        if !self.verity_check(inode, ino, index, &zeroes)? {
                            return Err(Errno::Eio);
                        }
                    }
                    buf[done..done + take].fill(0);
                    done += take;
                }
                Mapped::At(addr) => {
                    let block = self.read_data_page(inode, ino, index, addr, crypt.as_deref())?;
                    buf[done..done + take].copy_from_slice(&block[skew..skew + take]);
                    done += take;
                }
                // A compressed cluster unpacks as a whole, so as much of the
                // request as falls inside it is served from one decompression
                // rather than one per block.
                Mapped::Compressed => {
                    // A cluster unpacks into a buffer the size of the whole
                    // cluster plus whatever the algorithm needs to work in —
                    // the largest single allocation any read makes, and the one
                    // the reference takes from the virtual allocator and
                    // injects at.
                    if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::Vmalloc) {
                        return Err(Errno::Enomem);
                    }
                    let plain = self.read_cluster(inode, ino, index)?;
                    let at = (index - plain.first) as usize * BLKSIZE + skew;
                    let n = (plain.data.len() - at).min(want - done);
                    if n == 0 { return Err(Errno::Eio); }
                    buf[done..done + n].copy_from_slice(&plain.data[at..at + n]);
                    done += n;
                }
            }
        }
        Ok(want)
    }

    /// One page of a file's data, as the reader gets it: PLAINTEXT, attested.
    ///
    /// The one place a file's data block becomes a page, and therefore the one
    /// place the file mapping is consulted and filled. Everything a reader is
    /// owed happens on the way in and is what the mapping keeps: decryption
    /// comes first because contents are enciphered in UNITS that may be
    /// smaller than a block and the tree attests to the plaintext, and the
    /// verity check comes after it for the same reason.
    ///
    /// Accounting is inside the fetch rather than around it. A page the
    /// mapping answered moved no bytes at the device, and a figure that
    /// counted it would report traffic the mapping exists to avoid.
    /// # C: O(1) held, O(BLKSIZE) otherwise
    pub(crate) fn read_data_page(&self, inode: &Inode, ino: u32, index: u64, addr: u32,
                                 crypt: Option<&crate::crypto::Info>) -> Result<Vec<u8>, Errno> {
        if inode.verity() { return self.fill_data_page_attested(inode, ino, index, addr, crypt); }
        self.fill_data_page(ino, index, addr, crypt)
    }

    /// The same page WITHOUT the attestation — the read half of a
    /// read-modify-write.
    ///
    /// A sealed file is never written: the write is refused above this layer,
    /// so the two readers can never disagree about a page of file DATA. What
    /// this exists for is the hash tree a file is being sealed with, whose
    /// blocks are written through the ordinary block writer and which the
    /// tree does not attest to — checking one against the tree refuses the
    /// sealing itself.
    /// # C: O(1) held, O(BLKSIZE) otherwise
    pub(crate) fn read_data_page_unattested(&self, ino: u32, index: u64, addr: u32,
                                            crypt: Option<&crate::crypto::Info>)
        -> Result<Vec<u8>, Errno> {
        self.fill_data_page(ino, index, addr, crypt)
    }

    /// The page, decrypted and filed, with no attestation anywhere in it.
    ///
    /// Two callers and one reason for the split: this is the reader a
    /// read-modify-write uses, and a read-modify-write happens underneath a node
    /// write. A single reader taking an `attest` flag would put the whole
    /// attestation — the tree climb, the descriptor's own index walk, the page
    /// lock each of them can block on — statically underneath every partial
    /// block write in the filesystem, for a flag that is always false there.
    /// # C: O(1) held, O(BLKSIZE) otherwise
    pub(crate) fn fill_data_page(&self, ino: u32, index: u64, addr: u32,
                                 crypt: Option<&crate::crypto::Info>) -> Result<Vec<u8>, Errno> {
        self.page_get_fault()?;
        self.data_cache.read(ino, index, || {
            self.account_page_fetch();
            self.read_main_plain(addr, crypt, index)
        })
    }

    /// The page a reader of a SEALED file gets: checked against the tree before
    /// any of it reaches the caller — and before it is filed, so a page served
    /// later carries the same attestation as one served now. That is why sealing
    /// a file drops its pages: everything filed before the seal was filed
    /// without one.
    /// # C: O(1) held, O(BLKSIZE + levels) otherwise
    fn fill_data_page_attested(&self, inode: &Inode, ino: u32, index: u64, addr: u32,
                               crypt: Option<&crate::crypto::Info>) -> Result<Vec<u8>, Errno> {
        self.page_get_fault()?;
        self.data_cache.read(ino, index, || {
            self.account_page_fetch();
            let block = self.read_main_plain(addr, crypt, index)?;
            if !self.verity_check(inode, ino, index, &block)? { return Err(Errno::Eio); }
            Ok(block)
        })
    }

    /// Whether a caller asking the mapping for a page is to be told there is no
    /// memory for one.
    ///
    /// The mapping is asked for a page BEFORE the medium is: the lookup can
    /// fail for want of a page as easily as the read can fail for want of a
    /// block, and the reference injects at the lookup for that reason. Both
    /// readers below consult it, and neither may skip it — a site wired into
    /// only one of them is a site that fires for an ordinary file and not for
    /// a sealed one, which is worse than not having it.
    /// # C: O(1)
    fn page_get_fault(&self) -> Result<(), Errno> {
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::PageGet) {
            return Err(Errno::Enomem);
        }
        Ok(())
    }

    /// What a page that had to be FETCHED costs the report.
    ///
    /// Inside the fetch rather than around it: a page the mapping answered moved
    /// no bytes at the device, and a figure that counted it would report traffic
    /// the mapping exists to avoid.
    /// # C: O(1)
    fn account_page_fetch(&self) {
        self.io_account(crate::stats::iostat::Io::FsDataRead, BLKSIZE as u64, false);
        self.io_read_folio(0);
    }

    /// Where a block lives, asked of its CLUSTER rather than of the block.
    ///
    /// Only the FIRST slot of a compressed cluster carries the sentinel. The
    /// slots after it hold the compressed image, which are perfectly ordinary
    /// addresses, so resolving one of those blocks on its own address hands
    /// back a block of the IMAGE as if it were file content — plausible bytes,
    /// no error anywhere, and only for a read that does not start at a cluster
    /// boundary. A sequential read from the start of the file never asks,
    /// because the sentinel it meets first serves the whole cluster, which is
    /// why this survived: every read the tests did began at offset zero.
    ///
    /// A compressed file's clusters are not all compressed — one the file's
    /// size stops part way through is stored plain — so the question is put to
    /// the cluster's head rather than assumed from the inode's flag.
    /// # C: O(indirection depth) blocks
    pub(super) fn map_cluster_block(&self, inode: &Inode, ino: u32, index: u64) -> Result<Mapped, Errno> {
        if !inode.compressed() { return self.map_block(inode, ino, index); }
        let g = crate::compress::Geometry::new(
            inode.compress_algorithm,
            inode.log_cluster_size,
            inode.compress_flag,
        )
        .map_err(compress_errno)?;
        let head = g.first_block(index);
        if head == index { return self.map_block(inode, ino, index); }
        if crate::node::is_compressed(self.stored_addr(inode, ino, head)?) {
            return Ok(Mapped::Compressed);
        }
        self.map_block(inode, ino, index)
    }

    /// Unpack the compressed cluster that block `index` belongs to.
    ///
    /// The cluster's addresses are read RAW: the first is the sentinel that
    /// marks the run, and interpreting it would hide the very thing that says
    /// where the cluster starts. Everything the reference validates before
    /// decoding — the codec, the cluster width, the layout of the run — is
    /// checked by the geometry and the layout walk, so a malformed cluster is
    /// an error rather than plausible bytes.
    /// # C: O(cluster bytes)
    fn read_cluster(&self, inode: &Inode, ino: u32, index: u64) -> Result<Plain, Errno> {
        let g = crate::compress::Geometry::new(
            inode.compress_algorithm,
            inode.log_cluster_size,
            inode.compress_flag,
        )
        .map_err(compress_errno)?;
        let first = g.first_block(index);
        let mut addrs = alloc::vec::Vec::with_capacity(g.blocks());
        for i in 0..g.blocks() as u64 {
            addrs.push(self.stored_addr(inode, ino, first + i)?);
        }
        let live = crate::compress::data_blocks(&addrs).map_err(compress_errno)?;
        let mut image = alloc::vec::Vec::with_capacity(live.len() * BLKSIZE);
        for &a in live {
            if !self.sb.valid_main_blkaddr(a) { return Err(Errno::Eio); }
            // A block this mount already holds is not read again, and — the
            // point of holding it — is not charged as traffic either: nothing
            // went to the device, so a figure that counted it would report I/O
            // the cache exists to avoid.
            if let Some(cached) = self.compress_cache.load(a) {
                image.extend_from_slice(&cached);
                continue;
            }
            let block = self.read_main_block(a)?;
            // Offered AFTER the read rather than instead of it: the cache is
            // filled by what the medium actually returned, so a block that
            // could not be read leaves nothing behind to be served later.
            self.compress_cache.store(a, ino, &block);
            image.extend_from_slice(&block);
            // A compressed cluster's stored blocks are file data and are also
            // compressed data, so they are charged to both — the compressed
            // figure answers what share of the traffic was compressed, which a
            // partition of the total could not.
            self.io_account(crate::stats::iostat::Io::FsDataRead, BLKSIZE as u64, true);
            self.io_read_folio(0);
        }
        // A cluster that will not decompress, or whose checksum disagrees with
        // its bytes, is recorded: it is one file's problem rather than a
        // structural one, but it is still damage the next mount must know about.
        let cluster = crate::compress::decompress_cluster(&g, &image)
            .map_err(|e| { self.note_error(crate::errrec::Error::FailDecompression); compress_errno(e) })?;
        // A checksum the file asked for and that does not match means the
        // bytes are not the bytes that were written; handing them back would
        // be worse than refusing.
        if let crate::compress::Chksum::Mismatch { .. } = cluster.chksum {
            self.note_error(crate::errrec::Error::FailDecompression);
            return Err(Errno::Eio);
        }
        Ok(Plain { first, data: cluster.data })
    }

    /// Read a file whose data lives in its own inode block.
    ///
    /// The flag saying the data is inline and the flag saying data EXISTS are
    /// separate: an inline file that has never been written carries the first
    /// and not the second, and its region holds whatever the inode's address
    /// array held.
    /// # C: O(bytes read)
    fn read_inline(&self, inode: &Inode, ino: u32, off: u64, buf: &mut [u8])
        -> Result<usize, Errno> {
        if !inode.has(DATA_EXIST) { buf.fill(0); return Ok(buf.len()); }
        let n = self.read_inode_ref(ino)?.1;
        let (at, len) = inode.inline_data_span();
        let start = at + off as usize;
        let avail = len.saturating_sub(off as usize);
        let take = buf.len().min(avail);
        let src = n.block.get(start..start + take).ok_or(Errno::Eio)?;
        buf[..take].copy_from_slice(src);
        buf[take..].fill(0);
        Ok(buf.len())
    }

    /// The whole of a file. # C: O(file bytes)
    pub fn read_whole(&self, inode: &Inode, ino: u32) -> Result<Vec<u8>, Errno> {
        let len = usize::try_from(inode.size).map_err(|_| Errno::Efbig)?;
        if len > MAX_IO_BYTES { return Err(Errno::Efbig); }
        let mut out = vec![0u8; len];
        let got = self.read_file(inode, ino, 0, &mut out)?;
        out.truncate(got);
        Ok(out)
    }

    /// The target of a symbolic link.
    ///
    /// A link's target is its file content, so a short one is inline and a
    /// long one is not — the same two paths as any other file, which is why
    /// this is the file reader rather than a second one.
    /// # C: O(target bytes)
    pub fn read_link(&self, inode: &Inode, ino: u32) -> Result<Vec<u8>, Errno> {
        let mut bytes = self.read_whole(inode, ino)?;
        // A stored target may carry its terminator; a path with a trailing
        // zero byte in it resolves to nothing.
        if let Some(pos) = bytes.iter().position(|&b| b == 0) { bytes.truncate(pos); }
        if bytes.is_empty() { return Err(Errno::Eio); }
        Ok(bytes)
    }
}
