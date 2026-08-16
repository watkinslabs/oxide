//! What a mount was asked for, and what it reports back.
//!
//! FAT stores no owner, no permission bits and no character set, so almost
//! everything a user sees is a MOUNT decision rather than something on the
//! medium. An option string that is parsed and then dropped is therefore not
//! a cosmetic loss: `codepage=` decides which characters a name spells,
//! `shortname=` decides whether a lowercase name round-trips, and `tz=`
//! decides which instant every timestamp on the volume means.
//!
//! Module manifest:
//! - `values`: the option set, and the two defaults each type starts from.
//! - `parse`:  one `-o` string into that set.
//! - `show`:   that set back into the tail `/proc/mounts` carries.

pub mod values;
pub mod parse;
pub mod show;

pub use values::{Errors, Nfs, Options, MSDOS_NAME_MAX, VFAT_NAME_MAX};
pub use parse::parse;
pub use show::show;

#[cfg(test)]
#[path = "opts/tests.rs"]
mod tests;
