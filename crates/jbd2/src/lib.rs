// JBD2 — ext4 journal block device — `docs/17` JBD2 minimum.
//
// On-disk layout (Linux fs/jbd2):
// - Each journal block carries a 12-byte header at offset 0:
//     u32 h_magic      = 0xC03B3998
//     u32 h_blocktype  ∈ {1=descriptor,2=commit,3=sb_v1,4=sb_v2,5=revoke}
//     u32 h_sequence
// - Block 0 of the journal file = journal superblock (v1 or v2).
// - Descriptor blocks list which target fs blocks the following
//   data blocks correspond to.
// - Commit block terminates one transaction; everything between
//   the previous descriptor and this commit is durable.
//
// v1 scope: parse + replay. Transaction emit (write side) lives
// alongside this crate's `Transaction` type for callers (Mount).

#![no_std]
#![forbid(unsafe_op_in_unsafe_fn)]

#[cfg(any(test, feature = "hosted"))]
extern crate std;

extern crate alloc;

pub mod block_header;
pub use block_header::{BlockHeader, BlockType, JBD2_MAGIC};

pub mod superblock;
pub use superblock::{JournalSuperblock, JournalSuperblockError};

pub mod descriptor;
pub use descriptor::{DescriptorEntry, DescriptorTag, DescriptorIter,
                     TAG_FLAG_ESCAPE, TAG_FLAG_SAME_UUID, TAG_FLAG_DELETED, TAG_FLAG_LAST};

pub mod replay;
pub use replay::{replay, JournalLogReader, ReplayError, ReplayStats};
