// Platform operation tables per `32a§4`.
//
// Function-pointer tables rather than a trait object: the tables are static,
// one per platform, and `07§5` forbids `dyn` on the arch-facing seams. Each
// member is optional with exactly the reference's meaning, so a platform
// supplies only the hooks it needs.

use sync::{Spinlock, TaskList as PowerListClass};

use crate::decide::KResult;
use super::state::SuspendState;

/// Deep/shallow platform sleep. Applies to `standby` and `mem` only —
/// suspend-to-idle never consults it.
pub struct PlatformSuspendOps {
    /// Whether this platform can enter `state`. Absent means no state is valid.
    pub valid: Option<fn(SuspendState) -> bool>,
    /// Opens the transition; paired with `end`.
    pub begin: Option<fn(SuspendState) -> KResult<()>>,
    /// Before the device late phase.
    pub prepare: Option<fn() -> KResult<()>>,
    /// Before the device noirq phase.
    pub prepare_late: Option<fn() -> KResult<()>>,
    /// The irreversible-looking part: hand the machine to firmware. Returns
    /// once a wakeup has brought it back.
    pub enter: Option<fn(SuspendState) -> KResult<()>>,
    /// Immediately after `enter` returns, before the device noirq resume.
    pub wake: Option<fn()>,
    /// Paired with `prepare`, after the device early resume.
    pub finish: Option<fn()>,
    /// Whether the platform wants the enter repeated without waking userspace.
    pub suspend_again: Option<fn() -> bool>,
    /// Closes the transition; paired with `begin`.
    pub end: Option<fn()>,
    /// Run when the device suspend phase failed, before resuming devices.
    pub recover: Option<fn()>,
}

/// Suspend-to-idle platform hooks. Every member optional; a platform with none
/// still supports `freeze`, which is the point of the state.
pub struct PlatformS2idleOps {
    pub begin: Option<fn() -> KResult<()>>,
    pub prepare: Option<fn() -> KResult<()>>,
    pub prepare_late: Option<fn() -> KResult<()>>,
    /// Returns true when the loop should break. Replaces the generic
    /// pending-wakeup check when present.
    pub wake: Option<fn() -> bool>,
    /// Runs each time round the loop before re-entering idle.
    pub check: Option<fn()>,
    pub restore_early: Option<fn()>,
    pub restore: Option<fn()>,
    pub end: Option<fn()>,
}

impl PlatformSuspendOps {
    /// A table with no members, the shape a platform with no sleep support has.
    /// # C: O(1)
    pub const fn none() -> Self {
        PlatformSuspendOps { valid: None, begin: None, prepare: None, prepare_late: None,
            enter: None, wake: None, finish: None, suspend_again: None, end: None, recover: None }
    }
}

impl PlatformS2idleOps {
    /// A table with no members. # C: O(1)
    pub const fn none() -> Self {
        PlatformS2idleOps { begin: None, prepare: None, prepare_late: None, wake: None,
            check: None, restore_early: None, restore: None, end: None }
    }
}

static SUSPEND_OPS: Spinlock<Option<&'static PlatformSuspendOps>, PowerListClass> = Spinlock::new(None);
static S2IDLE_OPS: Spinlock<Option<&'static PlatformS2idleOps>, PowerListClass> = Spinlock::new(None);

/// Install the platform sleep table. Called once, from arch init, before any
/// `/sys/power` attribute can be read.
/// # C: O(1)
pub fn suspend_set_ops(ops: &'static PlatformSuspendOps) { *SUSPEND_OPS.lock() = Some(ops); }

/// Install the suspend-to-idle table. # C: O(1)
pub fn s2idle_set_ops(ops: &'static PlatformS2idleOps) { *S2IDLE_OPS.lock() = Some(ops); }

/// The installed platform sleep table. # C: O(1)
pub fn suspend_ops() -> Option<&'static PlatformSuspendOps> { *SUSPEND_OPS.lock() }

/// The installed suspend-to-idle table. # C: O(1)
pub fn s2idle_ops() -> Option<&'static PlatformS2idleOps> { *S2IDLE_OPS.lock() }
