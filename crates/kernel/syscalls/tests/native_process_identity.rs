extern crate alloc;
// identity resolves the process name through this module, so the standalone
// fixture has to carry it too: including one half of a pair by path and not
// the other is how a test crate silently stops compiling.
#[path = "../src/nt_process_naming.rs"]
mod nt_process_naming;
#[path = "../src/nt_process_create/identity.rs"]
mod identity;
#[path = "native_process_identity/tests.rs"]
mod tests;
