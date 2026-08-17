//! The quota file's own radix tree: finding, making, changing and removing
//! the record an identity is accounted in.
//!
//! The file is a tree keyed by the identity itself, and it owns its own free
//! space — two lists threaded through the same blocks, both headed in the
//! file's header. Every operation that moves one of them changes the header,
//! so the mutating entry points take it by reference and the caller stores it
//! back.
//!
//! Module manifest:
//! - `block`:  one block, its header, and the two free lists.
//! - `find`:   walking to a record, reading it, rewriting it in place.
//! - `create`: growing a path and a slot for an identity with neither.
//! - `delete`: removing a record and giving back what held it.
//! - `scan`:   the next identity at or after a given one.

pub mod block;
pub mod find;
pub mod create;
pub mod delete;
pub mod scan;

pub use find::{block_entries, find_entry, find_in_block, read, write};
pub use create::{insert, write_or_create};
pub use delete::delete;
pub use scan::{next_id, next_record};
