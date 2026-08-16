//! Creating, deleting and renaming names in a directory.
//!
//! Everything here is a pure function over a directory's BYTES. Nothing
//! touches a medium, so the whole decision surface — which slots a name may go
//! in, what a growth is allowed to do to a fixed root, the order the records
//! of one group are written, the order the records of one group are DELETED,
//! and what `.` and `..` hold — is exercised by `cargo test` against images in
//! memory. The layer that reads and writes clusters is `volume::dirops`, and
//! it decides nothing.
//!
//! Module manifest:
//! - `limits`: the ceilings a directory and a name are bounded by.
//! - `find`:   the free-slot run, and finding an entry by its eleven bytes.
//! - `build`:  the records one new name occupies, in write order.
//! - `remove`: the offsets one deletion writes, in write order.
//! - `dots`:   the two entries a new directory begins with, and reading them.

pub mod limits;
pub mod find;
pub mod build;
pub mod remove;
pub mod dots;

pub use limits::{FAT_MAX_DIR_ENTRIES, FAT_MAX_DIR_SIZE};
pub use find::{find_free_run, find_short, is_free_record, FreeRun};
pub use build::{build_group, Group};
pub use remove::deletion_order;
pub use dots::{dir_is_empty, dot_records, find_dotdot, DOT, DOTDOT};

#[cfg(test)]
#[path = "namei/tests.rs"]
mod tests;
