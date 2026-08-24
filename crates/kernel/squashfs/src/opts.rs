//! What a mount was asked for, and what it reports back.
//!
//! `show` must round-trip through `parse`, or a `remount` of a working mount
//! fails on the string the mount itself produced.

use alloc::string::{String, ToString};

use syscall::errno::Errno;
use vfs::fs::{FsParamSpec, FsParamType};

/// What a failed read does.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Errors {
    /// Report the error to the caller and carry on.
    Continue,
    /// Treat a failed read as unrecoverable. An image whose owner asked for
    /// this would rather stop than serve a page it could not verify.
    Panic,
}

/// One mount's option set.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Options {
    pub errors: Errors,
}

impl Options {
    /// # C: O(1)
    pub fn defaults() -> Self { Self { errors: Errors::Continue } }
}

impl Default for Options {
    fn default() -> Self { Self::defaults() }
}

/// The name a decompressor-thread-count option goes by.
///
/// Selecting the decompressor's concurrency is a build-time choice, and a
/// build that did not make it refuses the option instead of accepting a number
/// it will not act on. Accepting and ignoring it is what makes a mount claim a
/// property it does not have.
const THREADS: &str = "threads";

/// Apply a comma-separated option string.
///
/// An unknown name is `EINVAL`, as is a known name this build cannot honour.
/// # C: O(string bytes)
pub fn parse(mut opts: Options, data: &str) -> Result<Options, Errno> {
    for item in data.split(',') {
        let item = item.trim();
        if item.is_empty() { continue; }
        let (key, value) = match item.split_once('=') {
            Some((k, v)) => (k.trim(), Some(v.trim())),
            None => (item, None),
        };
        match (key, value) {
            ("errors", Some("continue")) => opts.errors = Errors::Continue,
            ("errors", Some("panic")) => opts.errors = Errors::Panic,
            (THREADS, _) => return Err(Errno::Einval),
            // `ro` is what every read-only mount is given and is already this
            // filesystem's only mode, so it is accepted and changes nothing.
            ("ro", None) => {}
            _ => return Err(Errno::Einval),
        }
    }
    Ok(opts)
}

/// Render an option set in a form [`parse`] accepts. # C: O(1)
pub fn show(opts: Options) -> String {
    match opts.errors {
        Errors::Continue => ",errors=continue".to_string(),
        Errors::Panic => ",errors=panic".to_string(),
    }
}

/// Parameters the registered filesystem can consume. `threads` remains
/// intentionally absent: this build has no decompressor worker owner, and a
/// parameter table must not claim a concurrency mode that no read path uses.
pub const SQUASHFS_PARAMS: &[FsParamSpec] = &[
    FsParamSpec::value("errors", FsParamType::String),
];

#[cfg(test)]
#[path = "tests/opts.rs"]
mod tests;
