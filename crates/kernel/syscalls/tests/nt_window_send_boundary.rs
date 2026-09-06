// Cargo-discovered target; execute the same production boundary harness as rustc.
extern crate alloc;
extern crate self as sched;
extern crate self as ipc;
include!("../src/nt_window/send/tests/hosted_body.rs");
