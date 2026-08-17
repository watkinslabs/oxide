//! A file's own pages — the per-inode mapping a file's DATA is read through
//! AND written through.
//!
//! Keyed by `(inode number, file page index)`, which is the key the rest of
//! the kernel's page cache is keyed by and the key the reference files a
//! file's data under. That choice is the whole design, and it is not the one
//! the other two mappings in this filesystem made:
//!
//! - The metadata mapping and the compressed-block cache are keyed by BLOCK
//!   ADDRESS, because a metadata block lives at a fixed address and a stored
//!   compressed image is asked for by the address the cluster reader has in
//!   hand.
//! - A file's page is asked for by OFFSET, and its address moves. Every write
//!   is out of place and the cleaner relocates live blocks, so an
//!   address-keyed mapping of file data would have to be invalidated on every
//!   move of bytes that did not change — and, worse, would answer a read of
//!   the new address with nothing while holding the identical bytes under the
//!   old one. Keying by offset makes a relocation invisible to the mapping,
//!   which is what it should be.
//!
//! What is held is PLAINTEXT, decrypted on the way in and enciphered on the
//! way out, and attested on the way in where the file is sealed. That is what
//! a reader gets and it is where the reference does both: caching ciphertext
//! would make every hit pay the cipher again, and checking the tree per ACCESS
//! rather than per fill would hash the same page on every read of it.
//!
//! COHERENT BY INVALIDATION, at the points where a file's contents at an
//! offset stop being what the mapping holds. Every content change in this
//! filesystem either lands at a NEW address, which one notification covers,
//! or is one of the two writers that change a block WHERE IT LIES:
//!
//! | event | site |
//! |---|---|
//! | a block's address changes | the one mapping-change notification every out-of-place writer funnels through |
//! | a file is shortened | the range invalidation the tail trim already makes, since a whole subtree goes without per-address notice |
//! | a pinned file's block is rewritten in place | the in-place writer |
//! | a file's blocks are erased in place | the secure-erase loop |
//! | an inode number is about to be reused | the inode free |
//! | a file is sealed behind a hash tree | the seal, because everything filed before it was filed unattested |
//!
//! The one writer that must NOT invalidate is writeback itself: it is putting
//! the page it holds at a new address, so the page and the address agree
//! afterwards and forgetting it would drop the bytes a reader is entitled to.
//!
//! A file with an atomic-write span open is read out of its shadow inode and
//! is not filed here at all; the commit that hands the shadow's blocks to the
//! file goes through the address notification like any other writer.
//!
//! ONLY the plain data path is filed here. A compressed file's unpacked
//! cluster is not: the cluster writer SKIPS the address update for a slot
//! whose stored value does not change — the head slot holds the same sentinel
//! before and after a rewrite — so the per-address notification does not fire
//! for the cluster's first page, and filing unpacked pages without a
//! cluster-wide invalidation beside it would serve the pre-rewrite bytes. The
//! compressed blocks themselves are already held, keyed by address.
//!
//! A page here may be DIRTY. A buffered write reserves the volume's space and
//! the owner's quota, records a RESERVATION in the file's node, and leaves the
//! bytes here; the address is chosen later, when the page is written back.
//! Until then the page is the only copy of those bytes, which is why a read
//! consults this mapping before it consults the node tree, and why eviction of
//! a dirty page is refused by the layer below.
//!
//! NODE blocks are held the same way and for the same reason, in their own
//! mapping keyed by node id (`node`). A node is changed where it is changed
//! and placed later, which is what lets a checkpoint choose one run of
//! addresses for every node a transaction touched instead of one address per
//! change.
//!
//! Module manifest:
//! - `cache`:  the mapping itself — read, write, flush, invalidate, count.
//! - `target`: where a dirty page goes when the MACHINE's flusher or reclaim
//!             reaches it, as opposed to this filesystem's own flush points.
//! - `node`:   the same pair for NODE blocks, keyed by node id.

mod cache;
mod node;
mod target;

pub use cache::Cache;
pub use node::{NodeCache, NodeHost, NodeTarget};
pub use target::{DataHost, Target};

#[cfg(test)]
#[path = "tests/filemap.rs"]
mod tests;
