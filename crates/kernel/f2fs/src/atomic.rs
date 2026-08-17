//! Atomic writes: a span of writes that either all become visible or none do.
//!
//! Between START and COMMIT the file's bytes change for the writer and for
//! nobody else, and a crash anywhere in between leaves the file exactly as it
//! was. Neither is achievable by writing into the file and undoing it: undoing
//! needs somewhere to have kept the old blocks, and a crash is precisely when
//! nothing is running to undo anything.
//!
//! So the writes go somewhere else. A COW inode — an inode with no name, parked
//! in the checkpoint's orphan list so a crash reclaims it — collects the new
//! blocks under the same block indexes the file uses. The file itself is not
//! touched at all: its addresses, its blocks and its node tree are what they
//! were. COMMIT then MOVES each block from the COW inode's index into the
//! file's, which is a node rewrite and not a copy, and the old block is
//! released as the new one lands.
//!
//! Two consequences worth stating, because getting either wrong is silent:
//!
//! - **A read inside the span must consult the COW inode first.** The writer is
//!   promised it can read back what it wrote; the file's own addresses still
//!   name the old bytes.
//! - **Bytes are produced as the FILE's, not the COW inode's.** On an encrypted
//!   file the block is enciphered under the file's own key and its own block
//!   index, because that block will be the file's. Enciphering it as the COW
//!   inode's would make the commit hand the file blocks it cannot decrypt.
//!
//! Module manifest:
//! - `state`:  what a span carries while it is open.
//! - `policy`: who may start, commit and abort one, as pure decisions.
//! - `start`:  opening a span, and the COW inode it needs.
//! - `io`:     reads and writes inside an open span.
//! - `commit`: moving the blocks across, and undoing a move that failed.

pub mod state;
pub mod policy;
pub mod start;
pub mod io;
pub mod commit;

pub use policy::{AtomicFacts, AtomicGate};
pub use state::AtomicFile;

#[cfg(test)]
#[path = "tests/atomic.rs"]
mod tests;
