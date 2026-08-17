//! Blocks fetched before a reader asks for them.
//!
//! Three mechanisms over three mappings, because the three hold different
//! things and are indexed differently: a file's data pages by block index, the
//! node blocks by node id, the metadata blocks by address. One mechanism over
//! one mapping could not serve all three — a node id is not a block address,
//! and the table an address resolves through decides which copy is current.
//!
//! All three are ADVISORY. None of them reports an error, none of them refuses
//! a read the caller went on to make, and none of them fetches outside the
//! window it was handed. What each one buys is requests: a resolved window
//! collapses into contiguous runs, and each run is one transfer where the
//! demand path would have issued one per block.
//!
//! Module manifest:
//! - `window`: the arithmetic — windows, runs, and which address a metadata
//!             index names. No volume, no medium.
//! - `data`:   a file's blocks and a compressed file's clusters.
//! - `node`:   a node's siblings, while their parent is in hand.
//! - `meta`:   the four kinds of metadata window.

#[path = "readahead/window.rs"]
pub mod window;
#[path = "readahead/data.rs"]
pub mod data;
#[path = "readahead/node.rs"]
pub mod node;
#[path = "readahead/meta.rs"]
pub mod meta;

pub use window::{RaMeta, MAX_RA_NODE};

#[cfg(test)]
#[path = "../tests/readahead/count.rs"]
mod count;

#[cfg(test)]
#[path = "../tests/readahead/fetch.rs"]
mod fetch_tests;
