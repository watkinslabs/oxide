//! Create, unlink, rename and link over a merged tree.
//!
//! Every one of these has to produce an end state that a LATER mount reads the
//! same way, using only what a single layer can do atomically. Deleting a name
//! that exists below cannot remove it, so the writable layer gets a whiteout
//! in its place. Creating a name where a whiteout stands cannot just replace
//! it, or a crash mid-way leaves the deleted lower object visible again — so
//! the new object is built in the work directory and exchanged in. And a
//! directory that merges cannot simply be renamed, because its lower half
//! stays where it was: either a record of where that half lives is written, or
//! the rename is refused so the caller copies by hand.
//!
//! Module manifest:
//! - `plan`:   the decisions each operation turns on, as pure functions.
//! - `create`: create, mkdir, mknod, symlink and link.
//! - `remove`: unlink and rmdir, with the whiteout that replaces a lower name.
//! - `rename`: moving a name, and what has to be recorded for it to survive.

pub mod plan;
pub mod create;
pub mod remove;
pub mod rename;

pub use plan::{can_move, needs_whiteout, rename_plan, RenamePlan};
pub use create::{create, link};
pub use remove::remove;
pub use rename::rename;

#[cfg(test)]
#[path = "dirops/tests.rs"]
mod tests;
