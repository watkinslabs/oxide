// Cgroup-namespace state keyed by canonical namespace identity — Linux
// `struct cgroup_namespace`'s `root_cset`, whose cgroup is the namespace's
// root for every path this namespace renders (`kernel/cgroup/cgroup.c`
// `copy_cgroup_ns` / `cgroup_path_ns_locked`).
//
// Linux stores a css_set reference; the unified v2 hierarchy makes the
// observable part exactly one thing — the absolute path of the cgroup the
// creating task was in — so that is what is stored.

use alloc::collections::BTreeMap;
use alloc::string::{String, ToString};

use namespace_identity::{Namespace, NamespaceId, NamespaceKind, NamespaceRef};

/// The initial cgroup namespace's root: the whole hierarchy.
pub const INIT_ROOT: &str = "/";

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum CgroupNsError { WrongKind, InitialOwner, StateExists }

static ROOTS: sync::Spinlock<BTreeMap<NamespaceId, String>, sync::TaskList> =
    sync::Spinlock::new(BTreeMap::new());

fn owner_id(owner: &Namespace) -> Result<NamespaceId, CgroupNsError> {
    if owner.kind() != NamespaceKind::Cgroup { return Err(CgroupNsError::WrongKind); }
    if owner.is_initial() { return Err(CgroupNsError::InitialOwner); }
    Ok(owner.id())
}

fn remove(kind: NamespaceKind, id: NamespaceId) {
    if kind == NamespaceKind::Cgroup { ROOTS.lock().remove(&id); }
}

/// Pin one exact non-init cgroup namespace's root (Linux `copy_cgroup_ns`
/// capturing the creating task's `css_set`). # C: O(log N)
pub fn allocate(owner: &NamespaceRef, root: String) -> Result<(), CgroupNsError> {
    let id = owner_id(owner)?;
    let mut roots = ROOTS.lock();
    if roots.contains_key(&id) { return Err(CgroupNsError::StateExists); }
    roots.insert(id, root);
    drop(roots);
    owner.register_finalizer(remove);
    Ok(())
}

/// Absolute cgroup path this namespace treats as `/`. The initial namespace —
/// and any owner whose state went away — is the whole hierarchy.
/// # C: O(log N)
pub fn root_of<H: core::ops::Deref<Target = Namespace>>(owner: &H) -> String {
    match owner_id(owner) {
        Err(_) => INIT_ROOT.to_string(),
        Ok(id) => ROOTS.lock().get(&id).cloned().unwrap_or_else(|| INIT_ROOT.to_string()),
    }
}

/// Linux `cgroup_path_ns_locked` → `kernfs_path_from_node(cgrp->kn, root->kn)`:
/// render `absolute` as seen from a namespace rooted at `root`.
///
/// * a cgroup AT the namespace root renders `/`;
/// * a descendant renders with the root prefix removed;
/// * a cgroup OUTSIDE the root renders `..`-relative, one `/..` per root
///   component that has to be walked back — kernfs does not clamp to `/`,
///   and a container manager reading `..` is how it learns the target is
///   outside its own namespace.
/// # C: O(components)
pub fn relativize(root: &str, absolute: &str) -> String {
    if root == INIT_ROOT { return absolute.to_string(); }
    let mut root_parts = root.split('/').filter(|c| !c.is_empty());
    let mut abs_parts = absolute.split('/').filter(|c| !c.is_empty()).peekable();
    let mut shared = 0usize;
    loop {
        let Some(r) = root_parts.next() else { break };
        match abs_parts.peek() {
            Some(a) if *a == r => { abs_parts.next(); shared += 1; }
            _ => {
                // Diverged: every remaining root component (this one included)
                // is one step back up.
                let mut out = String::from("/..");
                for _ in root_parts { out.push_str("/.."); }
                for a in abs_parts { out.push('/'); out.push_str(a); }
                let _ = shared;
                return out;
            }
        }
    }
    let mut out = String::new();
    for a in abs_parts { out.push('/'); out.push_str(a); }
    if out.is_empty() { out.push('/'); }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn owner() -> NamespaceRef {
        namespace_identity::allocate(NamespaceKind::Cgroup,
            namespace_identity::initial(NamespaceKind::User), None).unwrap()
    }

    #[test]
    fn initial_owner_roots_at_the_whole_hierarchy() {
        let init = namespace_identity::initial(NamespaceKind::Cgroup);
        assert_eq!(root_of(&init), INIT_ROOT);
        assert_eq!(allocate(&init, "/x".to_string()), Err(CgroupNsError::InitialOwner));
    }

    #[test]
    fn wrong_kind_is_rejected() {
        let uts = namespace_identity::allocate(NamespaceKind::Uts,
            namespace_identity::initial(NamespaceKind::User), None).unwrap();
        assert_eq!(allocate(&uts, "/x".to_string()), Err(CgroupNsError::WrongKind));
    }

    #[test]
    fn allocated_root_is_readable_and_single_shot() {
        let owner = owner();
        assert_eq!(root_of(&owner), INIT_ROOT, "unseeded owner sees the whole tree");
        allocate(&owner, "/user.slice/user-1000.slice".to_string()).unwrap();
        assert_eq!(root_of(&owner), "/user.slice/user-1000.slice");
        assert_eq!(allocate(&owner, "/other".to_string()), Err(CgroupNsError::StateExists));
    }

    #[test]
    fn final_owner_drop_removes_state() {
        let id = { let owner = owner();
            allocate(&owner, "/gone".to_string()).unwrap();
            owner.id() };
        assert!(!ROOTS.lock().contains_key(&id));
    }

    #[test]
    fn init_namespace_renders_absolute_paths_unchanged() {
        assert_eq!(relativize(INIT_ROOT, "/user.slice/a"), "/user.slice/a");
        assert_eq!(relativize(INIT_ROOT, "/"), "/");
    }

    #[test]
    fn the_namespace_root_itself_renders_as_slash() {
        assert_eq!(relativize("/user.slice", "/user.slice"), "/");
    }

    #[test]
    fn descendants_lose_the_root_prefix() {
        assert_eq!(relativize("/user.slice", "/user.slice/session-2.scope"),
            "/session-2.scope");
        assert_eq!(relativize("/a/b", "/a/b/c/d"), "/c/d");
    }

    #[test]
    fn outside_cgroups_render_dotdot_relative_like_kernfs() {
        assert_eq!(relativize("/a/b", "/"), "/../..");
        assert_eq!(relativize("/a/b", "/a"), "/..");
        assert_eq!(relativize("/a/b", "/a/c"), "/../c");
        assert_eq!(relativize("/user.slice", "/system.slice/x"), "/../system.slice/x");
    }

    #[test]
    fn a_sibling_prefix_is_not_treated_as_a_descendant() {
        // "/user.slice2" must not be read as a child of "/user.slice".
        assert_eq!(relativize("/user.slice", "/user.slice2"), "/../user.slice2");
    }
}
