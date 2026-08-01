// Hosted tests share ONE driver model. `DEVICES`, `MODEL_DRIVERS`, their two
// counters and the six publication hooks are process-global by design — the
// kernel has exactly one device tree — so no test can own a private copy. This
// claim is that model's single owner for the duration of a test: taking it
// excludes every sibling and resets the model, so each test starts from an
// empty tree with no hooks installed.
//
// ONE claim for the whole crate, not one per test file. `model::tests::*` and
// `path::tests::*` publish into the same two registries, so a per-file lock
// would leave those files racing each other while each believed it was
// serialized — two locks over one resource exclude nothing.
//
// Poison is recovered rather than propagated: a genuine assertion failure must
// report as ONE failure instead of cascading into every sibling.

use core::sync::atomic::Ordering;
use std::sync::{Mutex, MutexGuard};

static MODEL: Mutex<()> = Mutex::new(());

/// Live claim on the driver model. Held for the body of a test.
pub(crate) struct ModelClaim(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Take the model claim and reset the model to its boot state.
pub(crate) fn claim_model() -> ModelClaim {
    let g = MODEL.lock().unwrap_or_else(|e| e.into_inner());
    reset();
    ModelClaim(g)
}

/// Return the process-global model to its boot state: no devices, no drivers,
/// no publication hooks. The running kernel never unwinds its device tree, so
/// this exists only behind the claim above.
fn reset() {
    super::DEVICES.lock().clear();
    super::MODEL_DRIVERS.lock().clear();
    super::DEV_COUNT.store(0, Ordering::Release);
    super::DRV_COUNT.store(0, Ordering::Release);
    *super::SYSFS_HOOK.lock() = None;
    *super::SYSFS_REMOVE_HOOK.lock() = None;
    *super::BIND_HOOK.lock() = None;
    *super::DRIVER_HOOK.lock() = None;
    *super::DEVTMPFS_HOOK.lock() = None;
    *super::DEVTMPFS_DEL_HOOK.lock() = None;
}
