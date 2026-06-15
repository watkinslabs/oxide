// Internal plumbing — no C ABI. errno TLS slot, raw syscall numbers,
// symbol-version macro. docs/59§3,§4.
pub mod errno;
pub mod nr;
#[macro_use]
pub mod version;
