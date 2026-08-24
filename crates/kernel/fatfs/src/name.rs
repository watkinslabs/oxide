//! Names: the eleven bytes, the long name beside them, and which two names
//! are one.
//!
//! FAT stores every name twice — once in eleven bytes of a code page, once in
//! UTF-16 across as many preceding records as it takes — and the two are tied
//! together by a checksum over the eleven bytes. Neither is authoritative on
//! its own: an 8.3-only reader sees the short one, and a name that spells
//! itself in 8.3 has no long form at all.
//!
//! Module manifest:
//! - `cp437`:    the default code page's three translation tables.
//! - `codepage`: a code page, and the two directions across it.
//! - `flags`:    display and creation modes, case bits, lengths.
//! - `short`:    reading the 8.3 name out of a record.
//! - `shortgen`: writing one, uniquely, for a long name.
//! - `lfn`:      building the long-name slots.
//! - `compare`:  which two names are the same name.
//! - `msdos`:    the 8.3-only rules, where a name that will not fit is refused.

pub mod cp437;
pub mod cp850;
pub mod cp852;
pub mod cp855;
pub mod cp857;
pub mod cp860;
pub mod cp861;
pub mod cp862;
pub mod cp863;
pub mod cp864;
pub mod cp865;
pub mod cp866;
pub mod codepage;
pub mod flags;
pub mod short;
pub mod shortgen;
pub mod lfn;
pub mod compare;
pub mod msdos;

#[cfg(test)]
#[path = "name/tests.rs"]
mod tests;

pub use codepage::{by_number, CodePage, CP437, CP850, CP852, CP855, CP857, CP860, CP861, CP862, CP863, CP864, CP865, CP866, DEFAULT_CODEPAGE};
pub use flags::{shortname_mode, CASE_LOWER_BASE, CASE_LOWER_EXT, SFN_DEFAULT, SFN_MSDOS,
                SHORT_BASE_LEN, SHORT_NAME_LEN};
pub use lfn::{build_slots, encode, Encoded};
pub use short::decode;
pub use shortgen::{create, ShortName};
