//! string — glibc-ABI mem*/str* (docs/59§3, §6 G4). Family-grouped small
//! files (tight groups per §3); scalar reference impls, IFUNC SIMD
//! variants a post-rtld refinement (G12+).
pub mod chr;
pub mod cmp;
pub mod cpy;
pub mod dup;
pub mod len;
pub mod mem;
