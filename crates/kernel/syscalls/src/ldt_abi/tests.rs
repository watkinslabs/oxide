// Hosted unit tests for the `modify_ldt(2)` decision core. Manifest only —
// each child owns one contract.
//
//   decode.rs   — `user_desc` wire decode/encode round trip and bit positions.
//   classify.rs — `func` dispatch, including the ENOSYS-not-EINVAL rule.
//   packing.rs  — byte-exact `desc_struct` layout for known entries.
//   validate.rs — the write ladder's rules and its EINVAL/EFAULT ordering.
//   read.rs     — `read` / `read_default` sizing and clamping.

mod decode;
mod classify;
mod packing;
mod validate;
mod read;
