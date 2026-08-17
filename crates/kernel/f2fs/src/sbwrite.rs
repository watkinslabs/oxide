//! Writing the superblock back.
//!
//! Nothing about a volume changes the superblock often — a label, the
//! extension list, a resize, a repair — but every one of those is a change a
//! crash must not be able to lose halfway. Two copies exist for that reason,
//! and the order they are written in is the whole guarantee: the copy that is
//! NOT currently believed goes first, so a crash between the two writes leaves
//! the believed copy intact and the volume mounts exactly as it did before.
//! Writing the believed copy first would put a torn superblock in the position
//! every mount reads.
//!
//! The bytes are kept as bytes. A superblock carries fields this build does
//! not read — a password salt, an error record, timestamps a formatter wrote —
//! and rebuilding the copy from the parsed fields would zero every one of
//! them. A change is a patch to the copy that was read, never a re-encode.
//!
//! Module manifest:
//! - `raw`:    both copies read, which one is believed, and whether one is bad.
//! - `edit`:   the field changes: label, extension list, resize, salt.
//! - `commit`: the copies a commit writes, in which order, and the checksum.

pub mod raw;
pub mod edit;
pub mod commit;

pub use commit::{commit_super, copies, refuses};
pub use raw::{read_raw, RawSuper};
