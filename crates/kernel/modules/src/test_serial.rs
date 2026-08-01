// One claim on the module subsystem's process-global state, held by every
// hosted test in this crate.
//
// Kernel-side this state IS global by design — one `EXPORT_SYMBOL` table, one
// firmware cache, one IRQ table — so a test cannot own a private copy, and the
// reset each test wants is exactly the operation that cannot run unserialized.
// Seventeen `export_symbols_registers_*_surface` tests, in seventeen files,
// each cleared the whole symbol table and then asserted their own names were
// present; any two running together wiped each other's registrations, and a
// third test merely RESOLVING a name lost it mid-test. `tests.rs` did hold a
// lock, but only for its own nine tests — two locks over one table exclude
// nothing.
//
// ONE claim rather than one per global: a test reaches several of these at
// once (registering a module publishes symbols AND takes IRQ state), and
// per-global claims would have to be taken in a fixed order by every caller to
// stay deadlock-free. A single claim makes the rule stateable in one line —
// every `#[test]` in this crate starts by taking it.
//
// Poison is recovered, not propagated: a genuine assertion failure must report
// as ONE failure instead of cascading into every sibling that shares the claim.

use std::sync::{Mutex, MutexGuard};

static MODULES: Mutex<()> = Mutex::new(());

/// Live claim on the module subsystem's globals. Held for the body of a test.
pub(crate) struct ModulesClaim(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Take the claim and return the shared globals to their boot state.
pub(crate) fn claim() -> ModulesClaim {
    let g = MODULES.lock().unwrap_or_else(|e| e.into_inner());
    crate::symtab::reset_for_test();
    crate::linux_firmware::reset_for_test();
    ModulesClaim(g)
}
