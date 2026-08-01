// `sb->s_user_ns` — the user namespace a filesystem instance's on-disk ids are
// expressed in. Every id crossing this superblock's boundary (quota ids today,
// idmapped-mount owners already, `ns_capable(sb->s_user_ns, ...)` admission
// checks) is translated against it.
//
// A mount stamps the MOUNTING task's user namespace onto the instance it
// creates; a superblock built with no task context (boot-time kernel mounts,
// hosted tests) gets the initial user namespace, which is the identity map.

use namespace_identity::{initial, NamespaceKind, NamespacePin};
use sync::{Spinlock, Superblock as SbClass};

type CurrentUserNsHook = fn() -> Option<NamespacePin>;

static CURRENT_USER_NS_HOOK: Spinlock<Option<CurrentUserNsHook>, SbClass> = Spinlock::new(None);

/// Install the "user namespace of the task performing this mount" probe. VFS
/// owns superblock construction; the layer that owns tasks owns the answer.
/// # C: O(1)
pub fn set_current_user_ns_hook(hook: CurrentUserNsHook) { *CURRENT_USER_NS_HOOK.lock() = Some(hook); }

/// Remove the mounting-namespace probe. # C: O(1)
pub fn clear_current_user_ns_hook() { *CURRENT_USER_NS_HOOK.lock() = None; }

/// User namespace to stamp on a superblock being constructed now. With no
/// installed probe, or a probe that finds no current task, this is the initial
/// user namespace — the identity map, so every id translates to itself.
/// # C: O(1)
pub(crate) fn mounting_user_ns() -> NamespacePin {
    let hook = *CURRENT_USER_NS_HOOK.lock();
    hook.and_then(|hook| hook()).unwrap_or_else(|| initial(NamespaceKind::User).pin())
}
