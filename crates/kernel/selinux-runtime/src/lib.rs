// Kernel-side owner of the mandatory-access-control security server.
//
// The engine in `selinux` is pure and holds no state of its own. This crate
// owns the ONE live instance of it, the lock around it, and the boot-time
// decision about whether it runs at all. Everything in the kernel that asks a
// question of the policy asks it through here.
//
// There is exactly one instance. A second copy of the policy, the SID table
// or the enforcement flag could disagree with this one, and a disagreement is
// an access granted that the policy refuses.
//
// Module manifest:
//   boot  — command-line parsing and one-time initialisation
//   check — the permission-check entry points kernel subsystems call
//   label — SID storage helpers shared by the object owners
//   inode — how a mount and its inodes acquire labels
//   task  — the subject side of a check, read from the task owner

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(not(target_os = "oxide-kernel"), allow(dead_code))]

extern crate alloc;

pub mod boot;
pub mod check;
pub mod inode;
pub mod label;
pub mod task;

use sync::{Spinlock, SecurityPolicy};

use selinux::{BootConfig, SecurityServer};

/// The one security server.
///
/// Held under a lock ranked so a check may be taken with any subsystem lock
/// already held; see the lock-class declaration for why that rank is safe.
static SERVER: Spinlock<Option<SecurityServer>, SecurityPolicy> = Spinlock::new(None);

/// Install the security server for this boot. # C: O(1)
///
/// Called once, before any check can run. Calling it twice would discard a
/// loaded policy, so a second call is refused rather than honoured.
pub fn install(boot: BootConfig) -> bool {
    let mut slot = SERVER.lock();
    if slot.is_some() { return false; }
    *slot = Some(SecurityServer::new(boot));
    true
}

/// Whether the server has been installed. # C: O(1)
pub fn installed() -> bool { SERVER.lock().is_some() }

/// Run a closure against the server, if it is installed. # C: O(1) plus closure
///
/// Every caller goes through here so the lock is never held across a call the
/// engine cannot make; the engine takes no tracked lock of its own.
pub fn with<R>(f: impl FnOnce(&mut SecurityServer) -> R) -> Option<R> {
    let mut slot = SERVER.lock();
    slot.as_mut().map(f)
}

/// Whether the module runs and has a policy loaded. # C: O(1)
///
/// A caller that only needs to know whether to bother asking uses this; it is
/// not a permission answer and must never be used as one.
pub fn active() -> bool {
    with(|s| s.state().consults_policy()).unwrap_or(false)
}
