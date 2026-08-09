// x86 port permission state (`ioperm(2)`, `iopl(2)`).
//
// Module manifest:
//   bitmap.rs — the per-task permission map: range edits, the max-byte
//               window, all-denied detection, revision stamps.
//   ladder.rs — the two syscalls' errno ordering, in the reference's order.
//   apply.rs  — work fns over a `Task`: grant, withdraw, fork inheritance.
//   arch.rs   — publication into the running CPU's TSS window (x86 only).
//   tests/    — hosted coverage of the ladders and the map arithmetic.
//
// Everything except `arch` is ungated, so the decisions are testable without
// a kernel build (`docs/53`).

pub mod apply;
pub mod arch;
pub mod bitmap;
pub mod ladder;

pub use apply::{inherit, ioperm, iopl, recompute_flag};
pub use bitmap::{IoBitmap, IO_BITMAP_BITS, IO_BITMAP_BYTES, IO_BITMAP_LONGS};
pub use ladder::{ioperm_check, iopl_check, IoplAction, IOPL_MAX};

#[cfg(test)]
mod tests;
