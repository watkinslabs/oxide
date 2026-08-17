//! Case-insensitive name resolution, as a contract over bytes.
//!
//! Module manifest:
//! - `fixture`:  the loaded encodings every case here folds through.
//! - `encoding`: which encoding numbers and flag bits mount, and which refuse.
//! - `name`:     folding, hashing and matching one query name.
//! - `lookup`:   which passes a lookup makes.

#[path = "casefold/fixture.rs"]
mod fixture;
#[path = "casefold/encoding.rs"]
mod encoding;
#[path = "casefold/name.rs"]
mod name;
#[path = "casefold/lookup.rs"]
mod lookup;
