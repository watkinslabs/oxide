//! Who a filesystem's reserved-block pool is for.
//!
//! A volume may hold back a slice of its space so that a privileged writer can
//! still land a block once the volume is otherwise full — the emergency room
//! that lets a machine be repaired rather than only diagnosed. Deciding who
//! gets it needs the CALLER's identity, and a filesystem has none: the ids
//! travel as explicit parameters through the VFS entry points, and a block
//! allocation happens far below the last of them.
//!
//! The layer that owns credentials installs a probe here, in the shape the
//! quota limit ladder already uses. A filesystem asks the probe for the three
//! ambient facts the decision needs and takes the decision itself, so no
//! credential state is mirrored into any filesystem.
//!
//! With no probe installed the answer is "no task", which every caller must
//! read as kernel context — the reserve is FOR the kernel's own writes, so a
//! boot-time or kernel-internal allocation is admitted.

use sync::Spinlock;

struct ReservedCallerHookLock;
impl sync::LockClass for ReservedCallerHookLock {
    fn rank() -> u16 { 30 }
    fn name() -> &'static str { "ReservedCallerHookLock" }
}

/// The ambient facts a reserved-pool decision is taken from.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct ReservedCaller {
    /// The id a filesystem access is charged to, which is what a volume's
    /// reserved-uid names.
    pub fsuid: u32,
    /// Whether the caller's group set contains the group the volume reserved
    /// for. Asked of the probe rather than answered here, because the group
    /// set lives with the credentials.
    pub in_res_group: bool,
    /// `CAP_SYS_RESOURCE`, which a call site may or may not honour.
    pub cap_sys_resource: bool,
}

/// Answers the three facts for the group a volume reserved for.
pub type ReservedCallerHook = fn(u32) -> ReservedCaller;

static HOOK: Spinlock<Option<ReservedCallerHook>, ReservedCallerHookLock> = Spinlock::new(None);

/// Install the reserved-pool credential probe. # C: O(1)
pub fn set_reserved_caller_hook(hook: ReservedCallerHook) { *HOOK.lock() = Some(hook); }

/// Remove the reserved-pool credential probe. # C: O(1)
pub fn clear_reserved_caller_hook() { *HOOK.lock() = None; }

/// The running task's reserved-pool identity, tested against `res_gid`.
///
/// `None` means there is no task to ask — kernel context, or no probe
/// installed yet — which a caller admits to the reserve rather than refuses:
/// refusing would make the kernel's own writes the first thing a full volume
/// stops, which is the opposite of what the pool is held back for.
/// # C: O(groups)
pub fn reserved_caller(res_gid: u32) -> Option<ReservedCaller> {
    let hook = *HOOK.lock();
    hook.map(|hook| hook(res_gid))
}

#[cfg(test)]
#[path = "tests/fsreserve.rs"]
mod tests;
