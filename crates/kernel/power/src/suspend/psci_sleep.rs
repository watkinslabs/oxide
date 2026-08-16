// The aarch64 platform sleep table: `mem` via PSCI `SYSTEM_SUSPEND` (`32a§9`).
//
// Module manifest:
// - `admit`: which states this platform offers and how a firmware return maps
//            to a sleep-sequence error — pure, ungated, host-tested.
// - `table`: the `PlatformSuspendOps` static, its hooks, and `init`.
//
// Declared unconditionally rather than behind an arch gate: `admit` is where
// the `standby`-is-never-offered and `mem`-needs-the-feature decisions live,
// and a module gated on `target_arch = "aarch64"` compiles out of a hosted x86
// test run, taking its tests with it (`docs/53`). The firmware calls inside
// `table` carry the arch gate instead.

pub mod admit;
mod table;

pub use table::{init, PSCI_SUSPEND_OPS};
