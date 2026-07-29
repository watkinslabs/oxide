// Kernel CSPRNG — the single owner of kernel-generated randomness, per `27`.
//
// Module manifest:
//   `chacha` — ChaCha20 block function (RFC 8439), pinned by its test vectors.
//   `hw`     — hardware entropy: RDRAND / RNDR + the cycle counter.
//   `pool`   — the fast-key-erasure CSPRNG and its entropy absorb.
//
// Every consumer (`getrandom(2)`, `/dev/random`, `/dev/urandom`, AT_RANDOM,
// UUID generation, socket-filter cookies) calls `fill`/`next_u64` here. There
// is no second generator: a parallel "non-crypto" PRNG is how predictable
// bytes reach a security-critical consumer by accident.

#![no_std]
#![cfg_attr(test, allow(unused_imports))]

// dead_code is meaningful for this crate ONLY on the kernel target. A large
// part of it sits behind `cfg(target_os = "oxide-kernel")`, so a host build
// (`cargo test`, `cargo check --workspace`) compiles a strict subset and calls
// hundreds of live items dead. The kernel builds keep dead_code fully enabled
// and are warning-clean, and every one of these crates links into `kmain`, so
// nothing is hidden: real dead code still surfaces on `xtask kernel`.
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]
#[cfg(test)]
extern crate std;

mod chacha;
mod hw;
mod pool;

pub use hw::{cycles, hw_random_u64};
pub use pool::{add_entropy, add_hw_entropy, clear_bulk_source, fill, is_initialized,
               next_u64, reseed, set_bulk_source};
