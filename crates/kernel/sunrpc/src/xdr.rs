// XDR (RFC 4506) — the external data representation every ONC RPC body is
// written in.
//
// Two properties matter and both are enforced here rather than at each call
// site, because getting either wrong shifts every later field by a few bytes
// and the result decodes as plausible garbage rather than as an error:
//
//   * every item occupies a whole multiple of four bytes, variable-length
//     items being followed by zero padding that the reader must skip;
//   * integers are big-endian, unlike the little-endian frame headers of the
//     other protocols this kernel speaks.
//
// Module manifest:
//   * `enc` — the encoder.
//   * `dec` — the decoder, bounds-checked on every read.

pub mod enc;
pub mod dec;

pub use enc::Enc;
pub use dec::Dec;

use crate::uapi::limits::XDR_UNIT;

/// Bytes an item of `len` occupies once padded to the XDR unit. # C: O(1)
pub const fn padded(len: usize) -> usize { (len + XDR_UNIT - 1) & !(XDR_UNIT - 1) }

/// Padding bytes that follow an item of `len`. # C: O(1)
pub const fn pad_of(len: usize) -> usize { padded(len) - len }
