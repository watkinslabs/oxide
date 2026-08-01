// Hosted tests share ONE framebuffer registry. `FBS`, the `FB_DEVICES` node
// table and the `graphics` bus entries those nodes publish into the driver
// model are process-global — a kernel has one set of framebuffers — so no test
// can own a private copy. This claim is that registry's single owner for the
// duration of a test: taking it excludes every sibling and returns the registry
// to its boot state (no framebuffers, no `/dev/fbN` nodes, no `graphics`
// devices), so each test starts from `fb0` being free.
//
// ONE claim for the whole crate. `tests.rs`, `devfs::tests` and
// `devfs::identity_tests` all register nodes into the same two tables, so a
// per-file lock would leave those three files racing each other.
//
// The reset must go through `unregister_node`, not a raw `FBS.clear()`: the
// model device published for each node is torn down by `device_del`, and a
// registry cleared without it leaves a `graphics`/`fbN` identity behind that
// makes the next `register` in ANY test fail as a duplicate.
//
// Poison is recovered rather than propagated: one failing test must report as
// one failure, not cascade into every sibling.

use std::sync::{Mutex, MutexGuard};

static FBDEV: Mutex<()> = Mutex::new(());

/// Live claim on the framebuffer registry. Held for the body of a test.
pub(crate) struct FbdevClaim(#[allow(dead_code)] MutexGuard<'static, ()>);

/// Take the registry claim and reset the registry to its boot state.
pub(crate) fn claim_fbdev() -> FbdevClaim {
    let g = FBDEV.lock().unwrap_or_else(|e| e.into_inner());
    crate::devfs::unregister_all_nodes();
    crate::registry::FBS.lock().clear();
    FbdevClaim(g)
}
