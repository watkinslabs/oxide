//! A file's blocks, fetched before they are asked for.
//!
//! What readahead buys is not fewer bytes — the same blocks are read either
//! way — but fewer REQUESTS: a read that spans a contiguous run of a file
//! goes to the medium once for the run instead of once per block. A window
//! is resolved to addresses, the addresses are split into runs, and each run
//! is one transfer.
//!
//! Advisory throughout. Nothing here reports an error, nothing here refuses a
//! read the caller went on to make, and nothing here fetches a block outside
//! the window it was given. A readahead that fails leaves the mapping exactly
//! as it found it and the demand read does the work — and, crucially, reports
//! the failure itself, which is the only place it may be reported.

use alloc::vec;
use alloc::vec::Vec;

use syscall::errno::Errno;

use sectors::SectorSource;

use crate::crypto::Info;
use crate::node::Inode;
use crate::opts::MemoryMode;
use crate::uapi::BLKSIZE;

use super::super::map::Mapped;
use super::super::Volume;
use super::window::{runs, MAX_RA_BLOCKS};

impl<S: SectorSource> Volume<S> {
    /// Fill the mapping with up to `nr` blocks of `ino` from block `start`.
    ///
    /// The kinds of file that get nothing are the kinds where a window means
    /// something other than a run of blocks: a file whose data is inside its
    /// own inode has no blocks to fetch, and one whose key is absent has
    /// nothing to serve. A compressed file has clusters rather than blocks
    /// and is fetched as clusters.
    /// # C: O(nr) blocks, O(runs) transfers
    pub fn readahead_data(&self, inode: &Inode, ino: u32, start: u64, nr: usize) {
        if nr == 0 || inode.inline_data() { return; }
        if inode.compressed() {
            self.readahead_compressed(inode, ino, start, nr);
            return;
        }
        self.readahead_plain(inode, ino, start, nr);
    }

    /// Fill compressed clusters through the ordinary file-page cache.
    ///
    /// Linux widens a compressed readahead window to the cluster boundaries,
    /// gathers the cluster's pages, reads its stored image, and completes
    /// those pages after decompression. The compressed-block cache remains an
    /// optimization underneath that owner; it is not the file's answer.
    /// # C: O(nr) blocks, O(clusters) decompressions
    fn readahead_compressed(&self, inode: &Inode, ino: u32, start: u64, nr: usize) {
        // Readahead is advisory. Do not consume an armed demand-side
        // allocation fault while speculating; the subsequent fault must still
        // reach the reader that actually asks for the cluster.
        if self.fault_info().armed(crate::fault::Fault::Vmalloc) { return; }
        let Ok(g) = crate::compress::Geometry::new(inode.compress_algorithm,
                                                    inode.log_cluster_size,
                                                    inode.compress_flag) else { return };
        let blocks = inode.size.div_ceil(BLKSIZE as u64);
        if start >= blocks { return; }
        let end = start.saturating_add(nr as u64).min(blocks);
        let mut first = g.first_block(start);
        while first < end {
            match self.map_block(inode, ino, first) {
                Ok(Mapped::Compressed) => {
                    // Linux's memory=low mode disables the preallocated
                    // decompression path. Demand reads still allocate their
                    // temporary cluster buffer; uncompressed clusters in a
                    // compressed file retain ordinary readahead.
                    if !compressed_readahead_allowed(self.options().memory, live_memory_watermark()) {
                        return;
                    }
                    if self.read_cluster_for_readahead(inode, ino, first).is_err() { return; }
                }
                Ok(_) => self.readahead_plain(inode, ino, first,
                                               g.blocks().min((blocks - first) as usize)),
                Err(_) => return,
            }
            first = first.saturating_add(g.blocks() as u64);
        }
    }

    /// Plain-file readahead owner, also used for uncompressed clusters in a
    /// compressed file. # C: O(nr) blocks, O(runs) transfers
    fn readahead_plain(&self, inode: &Inode, ino: u32, start: u64, nr: usize) {
        // The last block of a file is whole on the medium; what stops
        // readahead is the file's SIZE, so a window past the end fetches
        // nothing rather than reading padding into the mapping.
        let blocks = inode.size.div_ceil(BLKSIZE as u64);
        if start >= blocks { return; }
        // The read that asked for this window resolved the key at its entry;
        // a window whose record is absent is fetched as nothing rather than
        // resolved from underneath the fetch.
        let crypt = match self.crypt_info_held(inode, ino) { Ok(c) => c, Err(_) => return };
        let want = nr.min(MAX_RA_BLOCKS).min((blocks - start) as usize);
        let addrs = self.ra_window(inode, ino, start, want);
        for run in runs(&addrs) {
            let first = start + run.at as u64;
            let Ok(bytes) = self.read_run_plain(run.addr, run.len, crypt.as_deref(), first)
                else { return };
            if !self.file_run(inode, ino, first, run.len, &bytes) { return }
        }
    }

    /// Resolve one window to the addresses readahead will fetch.
    ///
    /// A slot the mapping already holds resolves to nothing, so a window over
    /// pages that are already there costs no transfer at all — the reference
    /// skips an up-to-date page the same way, and for the same reason: the
    /// page it would fetch is the page it would then have to throw away.
    ///
    /// A hole resolves to nothing too. Readahead may not invent the zeroes a
    /// hole reads as: the mapping would then hold a page for a block the file
    /// does not have, and a write that later allocates it has nothing that
    /// says the held page is stale.
    /// # C: O(nr) walks
    fn ra_window(&self, inode: &Inode, ino: u32, start: u64, nr: usize) -> Vec<Option<u32>> {
        let mut out = Vec::with_capacity(nr);
        for i in 0..nr as u64 {
            let index = start + i;
            if self.data_cache.holds(ino, index) { out.push(None); continue; }
            match self.map_block(inode, ino, index) {
                Ok(Mapped::At(addr)) => out.push(Some(addr)),
                // A walk that fails stops the window rather than punching a
                // gap in it: the failure is the node tree's, and the blocks
                // after it are no more reachable than this one.
                Ok(_) => out.push(None),
                Err(_) => { out.push(None); break; }
            }
        }
        out
    }

    /// Read `len` consecutive blocks from `addr` as ONE transfer, handing
    /// back their plaintext.
    ///
    /// The run is contiguous both on the medium and in the file, which is
    /// what makes one encryption context cover all of it: data unit numbers
    /// advance with the file's blocks, so the run's first unit number and the
    /// run's length describe every unit in it. A run assembled any other way
    /// would decrypt every block after the first with the wrong number.
    /// # C: O(len * BLKSIZE)
    fn read_run_plain(&self, addr: u32, len: usize, crypt: Option<&Info>, first_index: u64)
        -> Result<Vec<u8>, Errno> {
        if len == 0 { return Err(Errno::Einval); }
        let last = u64::from(addr) + len as u64 - 1;
        if !self.sb_main_contains(addr) || last >= self.sb.max_blkaddr() { return Err(Errno::Eio); }
        if !self.sb.valid_main_blkaddr(last as u32) { return Err(Errno::Eio); }
        if crate::fault::time_to_inject(&self.fault, crate::fault::Fault::ReadIo) {
            return Err(Errno::Eio);
        }
        let first_unit = crypt.map(|c| self.first_unit(c, first_index));
        let ctx = crypt.zip(first_unit).and_then(|(c, u)| c.crypt_ctx(u));
        let mut buf = vec![0u8; len * BLKSIZE];
        self.source.read_sectors_crypt(u64::from(addr), &mut buf, ctx.as_ref())?;
        if let (Some(c), Some(u)) = (crypt, first_unit) {
            if !c.uses_inline_crypto() {
                c.crypt_contents(u, &mut buf, false).map_err(|e| e.errno())?;
            }
        }
        Ok(buf)
    }

    /// File a fetched run into the mapping, block by block.
    ///
    /// A sealed file's pages are attested BEFORE they are filed, exactly as a
    /// demand read attests them: a page filed here without its check would be
    /// served later by a reader that believes the check has already happened,
    /// which is the one way readahead could turn a corrupt file into a silent
    /// one. A block that fails stops the fill and is not filed — the demand
    /// read meets the same block and reports the error itself.
    /// # C: O(len) blocks
    fn file_run(&self, inode: &Inode, ino: u32, first: u64, len: usize, bytes: &[u8]) -> bool {
        for j in 0..len {
            let index = first + j as u64;
            let block = &bytes[j * BLKSIZE..(j + 1) * BLKSIZE];
            if inode.verity() {
                match self.verity_check(inode, ino, index, block) {
                    Ok(true) => {}
                    _ => return false,
                }
            }
            let _ = self.data_cache.read(ino, index, || Ok(Vec::from(block)));
            // Charged as the medium's traffic because that is what it is: the
            // blocks moved here are the blocks the demand read then does NOT
            // move, and the demand read charges only its misses.
            self.io_account(crate::stats::iostat::Io::FsDataRead, BLKSIZE as u64,
                            inode.compressed());
            self.io_read_folio(0);
        }
        true
    }
}

/// Whether speculative compressed decompression may take temporary/cache
/// memory. Linux's compressed-page path declines when the free-page count has
/// fallen below the published low watermark; a demand read still proceeds and
/// reports its own allocation failure. # C: O(1)
pub(crate) fn compressed_readahead_allowed(mode: MemoryMode,
                                            watermark: Option<(u64, u64)>) -> bool {
    if mode == MemoryMode::Low { return false; }
    watermark.is_none_or(|(free, low)| free >= low)
}

/// Read the PMM's one published free-memory observation. Hosted F2FS tests
/// have no live PMM and deliberately retain the normal advisory behavior.
/// # C: O(1)
fn live_memory_watermark() -> Option<(u64, u64)> {
    let pmm = pmm::setup::pmm_static()?;
    let free = pmm.free_pages();
    let snapshot = pmm::setup::watermark_snapshot(free)?;
    Some((free, snapshot.zone.low))
}
