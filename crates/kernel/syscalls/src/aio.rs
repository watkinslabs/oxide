// Module manifest — libaio: io_setup(206), io_destroy(207), io_getevents(208),
// io_submit(209), io_cancel(210), io_pgetevents(333).
//
//   ctx     — the ring's frames, the per-address-space context registry, the
//             system-wide fs.aio-max-nr charge, completion publication
//   setup   — io_setup/io_destroy: build the ring, map it, tear it down
//   submit  — io_submit: the per-iocb validation ladder and opcode dispatch
//   reap    — io_getevents/io_pgetevents: the blocking drain of the ring
//   slots   — the six ABI shims (docs/53)
//
// The pure decisions — wire layout, nr_events rounding, the validation
// ladders, ring index arithmetic — live in `crate::aio_abi`, which is NOT
// target-gated and is unit-tested; everything in this directory needs a live
// address space and is therefore invisible to `cargo test`.
//
// `aio_context_t` is the user address the completion ring is mapped at, not an
// opaque handle: userspace libaio dereferences it, verifies `aio_ring.magic`,
// and reaps completions straight out of the shared page without a syscall.

#![cfg(target_os = "oxide-kernel")]

pub mod ctx;
pub mod reap;
pub mod setup;
pub mod slots;
pub mod submit;

pub use slots::{sys_io_cancel, sys_io_destroy, sys_io_getevents, sys_io_pgetevents,
                sys_io_setup, sys_io_submit};
