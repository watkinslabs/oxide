//! Whether a line and a volume can both be true.
//!
//! Module manifest:
//! - `mount`:   the clauses a fresh mount trips, one at a time.
//! - `quota`:   the two accounting arrangements across a remount.
//! - `remount`: what a running mount may and may not be reconfigured to.
//! - `path`:    that the pass runs on every path a volume is mounted by.

use super::*;

mod mount;
mod quota;
mod remount;
mod path;

use crate::opts::facts::Facts;
use crate::opts::{Options, Spec};

/// A big, plain, writable volume: nothing in its shape refuses anything.
pub fn plain() -> Facts { Facts::plain(0, 100_000) }

/// Run a fresh mount's line against `facts`, reporting the settled options.
pub fn at_mount(facts: &Facts, line: &str) -> Result<Options, Errno> {
    crate::consistency::resolve(facts, line).map(|(o, _)| o)
}

/// The same, keeping the spec so a clause that CLEARS a request can be seen.
pub fn at_mount_spec(facts: &Facts, line: &str) -> Result<(Options, Spec), Errno> {
    crate::consistency::resolve(facts, line)
}
