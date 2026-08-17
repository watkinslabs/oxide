//! The options whose grammar is a module of its own.
//!
//! Module manifest:
//! - `bounds`:  the range each valued option's argument must fall in.
//! - `crypt`:   the dummy policy's spellings and its conflict rule.
//! - `jquota`:  quota files named on the line, and the two arrangements.
//! - `inject`:  the two fault-injection options, end to end.

mod bounds;
mod crypt;
mod jquota;
mod inject;
