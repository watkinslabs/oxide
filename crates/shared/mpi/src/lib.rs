// Multi-precision natural-number arithmetic (base 2^64), for the kernel's
// public-key arithmetic: Diffie-Hellman and RSA both reduce to modular
// exponentiation over big-endian byte strings supplied by userspace.
//
// Module manifest:
// - num:   the `Mpi` value — limb representation, big-endian import/export,
//          ordering, bit access. Owns the normalization invariant.
// - shift: limb-vector shift primitives (used by import/export and by the
//          divisor normalization the division algorithm needs).
// - addsub: limb-vector addition and subtraction.
// - mul:   schoolbook multiplication.
// - div:   truncated division with remainder (Knuth algorithm D).
// - powm:  modular exponentiation — the only operation the callers actually
//          want; everything above exists to make it correct.
//
// Only non-negative integers exist here. Signed MPI arithmetic has no caller
// in this kernel: DH and RSA operate in Z/nZ, and introducing a sign would put
// a second, untested representation of zero into every comparison.

#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(any(test, feature = "hosted"))] extern crate std;

mod addsub;
mod div;
mod mul;
mod num;
mod powm;
mod shift;

pub use num::Mpi;

#[cfg(test)] mod tests;
