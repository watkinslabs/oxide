// Hosted coverage for the usermode-helper decision logic. Module manifest:
//   contract  submission ladder: refusals, wait-mode returns, ownership
//   gatelock  disable/enable depth + in-flight accounting
//   request   request construction, callbacks, argv/env fidelity

mod contract;
mod gatelock;
mod request;

use std::sync::{Mutex, MutexGuard, OnceLock};

/// Every test here drives process-global state (the gate depth, the installed
/// backend, the recording slots below), so they run one at a time.
pub(crate) fn serialize() -> MutexGuard<'static, ()> {
    static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
    match LOCK.get_or_init(|| Mutex::new(())).lock() {
        Ok(g) => g,
        Err(poisoned) => poisoned.into_inner(),
    }
}
