//! The mount options, from the string a container runtime writes to the
//! configuration the mount runs with.
//!
//! Two separate grammars meet here. The option string itself is split on
//! commas that a backslash may escape, because a layer path may contain one.
//! The `lowerdir=` value is then split again on colons, where a single colon
//! separates merged layers and a double colon starts the data-only ones — a
//! distinction that decides whether a name can ever resolve into a layer.
//!
//! Module manifest:
//! - `split`:  commas, colons, and the backslash that hides either.
//! - `parse`:  one option string into a configuration and what it named.
//! - `verify`: the combinations that are refused, and those quietly adjusted.
//! - `show`:   that configuration back into the tail `/proc/mounts` carries.

pub mod split;
pub mod parse;
pub mod verify;
pub mod show;

pub use split::{next_opt, split_lowerdirs, unescape, LowerSpec};
pub use parse::{parse, Parsed};
pub use verify::verify;
pub use show::show;

#[cfg(test)]
#[path = "params/tests.rs"]
mod tests;
