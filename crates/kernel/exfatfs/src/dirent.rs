//! Directory entries, and the SETS they come in.
//!
//! A name on exFAT is not one record. It is a file entry, a stream extension
//! entry and one or more name entries, written consecutively, and the file
//! entry carries both a count of how many follow it and a checksum over all of
//! them. Reading one of the three alone tells you nothing usable; writing one
//! without recomputing the checksum leaves a set every other implementation
//! rejects.
//!
//! Module manifest:
//! - `kind`:   what a type byte means, and which class it falls in.
//! - `file`:   the first entry: attributes, timestamps, the set's checksum.
//! - `stream`: the second: length, hash, first cluster, allocation flags.
//! - `set`:    a whole set, parsed and built, with its checksum.
//! - `meta`:   the entries that describe the volume rather than a file.

pub mod kind;
pub mod file;
pub mod stream;
pub mod set;
pub mod meta;

pub use kind::{class_of, is_deleted, is_in_use, EntryKind};
pub use file::FileEntry;
pub use stream::StreamEntry;
pub use set::{EntrySet, SetError};
pub use meta::{BitmapEntry, UpcaseEntry, VolumeLabel};
