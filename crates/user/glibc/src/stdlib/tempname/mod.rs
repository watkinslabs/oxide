//! tempname — shared temp-name generation for mkstemp/mkostemp/mkstemps/
//! mkdtemp/mktemp (docs/59§6 G7). Mirrors glibc `sysdeps/posix/tempname.c`
//! (`__gen_tempname` → `try_tempname_len`), read from the gnulib sync
//! `lib/tempname.c` (identical algorithm, same upstream file).
//!
//! Module manifest:
//!   value   — pure random_value → base-62 letters, bias policy, ersatz mixer
//!   entropy — getrandom(2) draw + clock/pid fallback (freestanding only)
//!   gen     — template X-run rewrite + EEXIST retry loop (freestanding only)
//!   tests   — hosted unit tests pinning `value`
pub mod value;
#[cfg(feature = "freestanding")]
pub mod entropy;
#[cfg(feature = "freestanding")]
pub mod gen;
#[cfg(test)]
mod tests;
