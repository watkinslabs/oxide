//! The runs an activation hands over, and whether one is where it should be.

use alloc::vec::Vec;

/// One run of consecutive blocks: where it is in the file, where it is on the
/// medium, and how long it is.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Extent {
    pub lblk: u64,
    pub pblk: u32,
    pub blocks: u64,
}

/// What an activation reports back.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct SwapMap {
    /// The runs, in file order.
    pub extents: Vec<Extent>,
    /// Blocks the area holds, the header block excluded.
    pub pages: u64,
    /// One past the last block of the file the area covers.
    pub max: u64,
    /// The distance between the lowest and highest block the area touches,
    /// the header block excluded — what a seek-cost estimate is made from.
    pub span: u64,
    /// Runs that had to be moved to sit on a section boundary.
    pub not_aligned: u32,
}

/// Whether a run begins on a section boundary and fills whole sections.
///
/// Both halves matter: a run that starts mid-section shares that section with
/// something else, and one that ends mid-section leaves the tail free for
/// something else to be put in.
/// # C: O(1)
pub fn section_aligned(pblk: u32, main_blkaddr: u32, blocks: u64, blks_per_sec: u32) -> bool {
    if blks_per_sec == 0 { return true; }
    let per = u64::from(blks_per_sec);
    let off = u64::from(pblk.saturating_sub(main_blkaddr));
    off % per == 0 && blocks % per == 0
}

/// Round `blocks` up to a whole number of sections. # C: O(1)
pub fn roundup_sections(blocks: u64, blks_per_sec: u32) -> u64 {
    if blks_per_sec == 0 { return blocks; }
    let per = u64::from(blks_per_sec);
    blocks.div_ceil(per) * per
}

impl SwapMap {
    /// Record a run, joining it to the previous one when the two are
    /// consecutive in the file AND on the medium.
    ///
    /// Joining is not cosmetic: the paging code walks this list per access,
    /// and a file laid out as one run reported as thousands costs that walk
    /// every time.
    /// # C: O(1)
    pub fn push(&mut self, lblk: u64, pblk: u32, blocks: u64) {
        if let Some(last) = self.extents.last_mut() {
            if last.lblk + last.blocks == lblk
                && u64::from(last.pblk) + last.blocks == u64::from(pblk)
            {
                last.blocks += blocks;
                return;
            }
        }
        self.extents.push(Extent { lblk, pblk, blocks });
    }

    /// The block address `lblk` resolves to, or `None` when the area does not
    /// cover it. # C: O(runs)
    pub fn resolve(&self, lblk: u64) -> Option<u32> {
        let e = self.extents.iter().find(|e| lblk >= e.lblk && lblk < e.lblk + e.blocks)?;
        u32::try_from(u64::from(e.pblk) + (lblk - e.lblk)).ok()
    }

    /// Finish the map: the header block is the file's first block and is not
    /// part of the area, which is what makes `pages` one short of `max`.
    /// # C: O(1)
    pub fn seal(&mut self, cur: u64, lowest: Option<u32>, highest: u32) {
        // A file that yielded nothing still reports one block, so the caller
        // reports an empty area rather than a successful one of no size.
        let max = if cur == 0 { 1 } else { cur };
        self.max = max;
        self.pages = max - 1;
        self.span = match lowest {
            Some(low) => 1 + u64::from(highest) - u64::from(low),
            None => 0,
        };
    }
}
