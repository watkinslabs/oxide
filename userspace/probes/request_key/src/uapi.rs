//! Keyring UAPI numbers. `libc` binds neither `request_key` nor `keyctl`, so the
//! slots come from the per-arch syscall tables and the command from
//! `linux/keyctl.h`. Named here rather than inline per `07§5`: the two slots
//! DIFFER between x86_64 and aarch64, which is exactly the off-by-arch a bare
//! literal hides.

/// `request_key(2)` slot.
#[cfg(target_arch = "x86_64")]
pub const SYS_REQUEST_KEY: libc::c_long = 249;
#[cfg(target_arch = "aarch64")]
pub const SYS_REQUEST_KEY: libc::c_long = 218;

/// `keyctl(2)` slot.
#[cfg(target_arch = "x86_64")]
pub const SYS_KEYCTL: libc::c_long = 250;
#[cfg(target_arch = "aarch64")]
pub const SYS_KEYCTL: libc::c_long = 219;

/// `KEYCTL_READ` — read a key's payload back.
pub const KEYCTL_READ: libc::c_long = 11;

// CONST, not `#[test]`: the whole point of this module is that the slots differ
// between x86_64 and aarch64, and a host-only test proves nothing about the
// cross-built binary. Verified against `arch/x86/entry/syscalls/syscall_64.tbl`
// and `include/uapi/asm-generic/unistd.h`.
#[cfg(target_arch = "x86_64")]
const _: () = { assert!(SYS_REQUEST_KEY == 249); assert!(SYS_KEYCTL == 250); };
#[cfg(target_arch = "aarch64")]
const _: () = { assert!(SYS_REQUEST_KEY == 218); assert!(SYS_KEYCTL == 219); };
/// `keyctl` follows `request_key` on both tables — a copy-paste that unified the
/// two arches would break this before it could run the wrong syscall in a guest.
const _: () = assert!(SYS_KEYCTL == SYS_REQUEST_KEY + 1);
