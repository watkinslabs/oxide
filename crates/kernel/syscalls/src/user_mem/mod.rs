// Caller-memory access for the syscall slot files and their shared helpers.
//
// Module manifest:
//   `copy` — scalar and run-length reads/writes of a caller address.
//   `pod`  — whole-record transfers for the ABI structs a slot exchanges.
//
// Ungated on purpose (`docs/53`): nearly every slot file carries a whole-file
// `#[cfg(target_os = "oxide-kernel")]`, so a test written beside one compiles
// to nothing and reports ok. The transfer decisions live here where a hosted
// `cargo test` can fail on them; the slot keeps the call and the errno.

mod copy;
mod pod;

// The consumers are kernel-gated, so a hosted build re-exports these without a user.
#[allow(unused_imports)]
pub(crate) use copy::{EFAULT, get_bytes, get_i8, get_i16, get_i32, get_i64, get_into, get_u8,
                      get_u16, get_u32, get_u64, put_bytes, put_i16, put_i32, put_i64, put_u8,
                      put_u32, put_u64};
#[allow(unused_imports)]
pub(crate) use pod::{UserPod, get_pod, put_pod};

#[cfg(test)]
mod tests;
