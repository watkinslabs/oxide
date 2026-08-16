//! Node ids nothing is using, kept in memory so allocating one is not a scan.
//!
//! Without this, taking a node id means walking the node table from a cursor
//! and reading a table block for every id considered — once per file created,
//! once per indirect node grown. The table is thousands of blocks on a real
//! volume and the cursor only moves forward, so a volume whose free ids are
//! behind the cursor reads the whole table to find the first one.
//!
//! The cache turns that into a bounded, resuming WALK whose results are kept:
//! a pass reads a few table blocks, records every free id it saw in a free
//! map, and hands ids out of that. What makes it correct rather than merely
//! fast is that the map is only ever trusted for blocks that have actually
//! been read, and the journal — which overrides the table — is folded in on
//! every pass.
//!
//! Module manifest:
//! - `limits`: what the cache will hold, and the memory budget it holds it in.
//! - `bitmap`: which ids of each table block are free, a block at a time.
//! - `state`:  the ids held, the two states one can be in, and handing one out.
//! - `scan`:   filling the cache from a table block, the journal, and the map.

pub mod limits;
pub mod bitmap;
pub mod state;
pub mod scan;

pub use bitmap::{nat_ofs, start_nid, Bitmaps};
pub use limits::{DEF_RAM_THRESHOLD, FREE_NID_PAGES, MAX_FREE_NIDS, SHRINK_NID_BATCH_SIZE};
pub use scan::Plan;
pub use state::{Corrupt, FreeNids, NidState};
