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
// Parse, replay, and transaction emission share the same feature-selected tag
// and checksum formats so the recovery and steady-state paths cannot drift.


#[cfg(any(test, feature = "hosted"))]
extern crate std;


pub mod block_header;
pub use block_header::{BlockHeader, BlockType, JBD2_MAGIC};

pub mod superblock;
pub use superblock::{JournalSuperblock, JournalSuperblockError};

pub mod checksum;
pub use checksum::ChecksumMode;

pub mod descriptor;
pub use descriptor::{DescriptorEntry, DescriptorTag, DescriptorIter,
                     TAG_FLAG_ESCAPE, TAG_FLAG_SAME_UUID, TAG_FLAG_DELETED, TAG_FLAG_LAST};

pub mod replay;
pub use replay::{replay, JournalLogReader, ReplayError, ReplayStats};

pub mod emit;
pub use emit::{
    StagedBlock, LogCursor, EmitError, TransactionError,
    descriptor_capacity, descriptor_capacity_for,
    transaction_block_count, transaction_block_count_for,
    build_descriptor_block, build_descriptor_block_for,
    emit_transaction, emit_transaction_for,
    build_commit_block, build_commit_block_for, escape_journal_payload,
};
