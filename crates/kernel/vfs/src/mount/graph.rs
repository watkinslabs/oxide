/// A dentry's identity key (stable address of the `Arc<Dentry>` allocation).
/// # C: O(1)
fn dptr(d: &Arc<Dentry>) -> usize { Arc::as_ptr(d) as *const () as usize }

/// TEMP (D24, `debug-mnt`): emit ONE grep-able `[MNTCREATE]` line at a mount
/// create/attach/clone/graft site, via the same raw klog sink the `[MNTDIVERGE]`
/// probe uses. Lets the boot log reconstruct the exact sequence + via-tag that
/// builds the sandbox-root mounts (mnt_id 10/11) and whether the api-mounts
/// (/proc,/sys,/dev,/run) are re-created beneath them. Prod-inert (feature-off ⇒
/// no call sites). # C: O(name len)
#[cfg(feature = "debug-mnt")]
fn mntcreate_log(via: &str, new_id: u64, parent: u64, mp: Option<&Arc<Dentry>>,
                 root: Option<&Arc<Dentry>>, sb: Option<&Arc<SuperBlock>>) {
    klog::write_raw(b"[MNTCREATE] via=");
    klog::write_raw(via.as_bytes());
    klog::write_raw(b" new_id="); klog::write_dec_u64(new_id);
    klog::write_raw(b" parent="); klog::write_dec_u64(parent);
    klog::write_raw(b" mp_dentry=ptr:0x");
    klog::write_hex_u64(mp.map(|d| dptr(d) as u64).unwrap_or(0));
    klog::write_raw(b" name:");
    klog::write_raw(mp.map(|d| d.name()).unwrap_or("<none>").as_bytes());
    klog::write_raw(b" root_dentry=ptr:0x");
    klog::write_hex_u64(root.map(|d| dptr(d) as u64).unwrap_or(0));
    klog::write_raw(b" sb=ptr:0x");
    klog::write_hex_u64(sb.map(|s| Arc::as_ptr(s) as *const () as u64).unwrap_or(0));
    klog::write_raw(b"\n");
}

/// [D24] True iff `d` is THE namespace-root dentry by IDENTITY — the single
/// `s_root` of the current ns-root mount. A purely STRUCTURAL test (parentless +
/// empty name) matches EVERY superblock root dentry (procfs/sysfs singleton roots
/// included), so a fresh-fs `mount(proc,/proc)` over an existing proc mount —
/// whose target resolves to the procfs `s_root` (parentless, empty-name) — would
/// be wrongly treated as the ns root and HIJACK it. Compare against
/// [`global_root`] by pointer identity instead; fall back to the structural test
/// ONLY when no global root is set yet (the very first rootfs mount, where
/// `global_root() == None`). This is the single ns-root predicate — used both by
/// the self-root attach filter and the reader short-circuits. # C: O(1)
fn is_ns_root_dentry(d: &Arc<Dentry>) -> bool {
    match global_root() {
        Some(r) => dptr(&r) == dptr(d),
        None => d.parent().is_none() && d.name().is_empty(),
    }
}

/// The mount in `ns` whose superblock root DENTRY is `d`, by `s_root`
/// IDENTITY (cross-ns scanner over the global map). # C: O(N_mounts)
fn mount_with_root_dentry(ns: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    let dp = dptr(d);
    // Match the mount's OWN root dentry (`mnt_root`, per-mount for binds/clones),
    // not the shared `sb.s_root()` — see `visible_mnt_id_of_root_dentry`.
    MOUNTS.lock().values()
        .find(|m| m.ns == ns && m.mnt_root().map(|r| dptr(&r) == dp).unwrap_or(false))
        .cloned()
}

/// The VISIBLE mount in `ns` whose `s_root` dentry is `d`, disambiguating the
/// codebase's shared-`s_root` pseudo-filesystems (procfs/sysfs use a SINGLETON
/// root dentry, so several mounts in ONE ns can share it — see
/// `tests/sandbox_ns_crossing.rs`). The bare `s_root`-identity `.find()` returns
/// an ARBITRARY one of those duplicates; the `(parent_mnt_id, dentry)` mount
/// hash instead needs the one the path walk actually CROSSES INTO, so this picks
/// (a) the ns ROOT mount when `d` is the ns-root `s_root`, else (b) the duplicate
/// that is the current TOP at its own mountpoint (`top_mount_on(mp) == self`),
/// else (c) the first candidate. Keeps `parent_by_dentry` agreeing with the
/// walk's crossing chain so `__lookup_mnt(cur_mnt, child)` resolves the child
/// mount even under shadowed singleton-fs duplicates. # C: O(N_mounts)
fn visible_mnt_id_of_root_dentry(ns: u64, d: &Arc<Dentry>) -> Option<u64> {
    let dp = dptr(d);
    // Match on the mount's OWN root dentry (`mnt_root`), which for a bind/clone
    // is a per-mount override distinct from the shared `sb.s_root()`. Filtering
    // by `sb.s_root()` missed bind mounts entirely: a task chrooted/pivoted onto
    // a bind root (systemd sandbox, mnt 397) resolved its root dentry to the ns
    // root (381) instead, so `__lookup_mnt(381, /sys)` could not find the sysfs
    // mounted under 397 — logind's `/sys` fell to the empty ext4 underlay and no
    // greeter rendered. `mnt_root()` falls back to `sb.s_root()`, so the
    // singleton-pseudo-fs (procfs/sysfs) sharing case below is unchanged.
    let cands: Vec<Arc<Mount>> = MOUNTS.lock().values()
        .filter(|m| m.ns == ns && m.mnt_root().map(|r| dptr(&r) == dp).unwrap_or(false))
        .cloned().collect();
    if cands.is_empty() { return None; }
    // (a) THE ns root mount ⇒ the canonical ns-root id. Must be the ACTUAL ns
    // root (mnt_id == root_mount_id), NOT merely any self-parented mount: a
    // sandbox bind root is also self-parented (`is_root()`) but is a task's
    // private root, not the namespace root — collapsing it to the ns root is the
    // bind-root misidentification above.
    if cands.iter().any(|m| Some(m.mnt_id) == root_mount_id(ns)) { return root_mount_id(ns); }
    // (b) the duplicate currently visible (top of its own mountpoint crossing).
    for m in cands.iter() {
        if let Some(mp) = m.mountpoint() {
            if top_mount_on(ns, &mp) == Some(m.mnt_id) { return Some(m.mnt_id); }
        }
    }
    // (c) deterministic fallback.
    cands.first().map(|m| m.mnt_id)
}

/// One ancestor step in a CROSSING-AWARE parent walk (Linux `follow_dotdot`).
/// # C: O(N_mounts) at a mount root, else O(1)
fn cross_up(ns: u64, d: &Arc<Dentry>) -> Option<Arc<Dentry>> {
    if let Some(p) = d.parent() { return Some(p.clone()); }
    if d.is_root() { return mount_with_root_dentry(ns, d).and_then(|m| m.mountpoint()); }
    None
}

/// Absolute path rendered from a dentry's parent chain (Linux `d_path`) — the
/// WRITE-ONLY rendered path. # C: O(depth)
fn abs_string(d: &Arc<Dentry>) -> String {
    String::from_utf8(d.absolute_path()).unwrap_or_else(|_| String::from("/"))
}

/// MOUNT-AWARE rendered path for a mount attached at dentry `d` under `parent_id`
/// (true Linux `d_path`, which walks the MOUNT tree — mnt_parent chain — not the
/// global dentry chain). Bind mounts SHARE the source dentry, so `abs_string(d)`
/// (a pure d_parent walk) yields the SOURCE's path and drops the bind prefix — a
/// self-bind of `/run/systemd/mount-rootfs/proc/sys/kernel/domainname` rendered as
/// the real `/proc/sys/kernel/domainname`, so systemd never saw the prefix become
/// a mount and its `bind_remount_recursive` convergence loop spun to its 32-try
/// EBUSY cap (status 226). Reconstruct as `parent.rendered_path` + `d`'s suffix
/// past the parent mount's root dentry. Parents are created before children
/// (Linux `attach_recursive_mnt` top-down), so the recursion bottoms out at a
/// mount on a NON-shared dentry where `abs_string` is already correct. Falls back
/// to `abs_string(d)` at the ns root or when the suffix cannot be taken. For a
/// non-shared dentry the result equals `abs_string(d)` (the two chains agree), so
/// this is a strict refinement. # C: O(depth)
fn rendered_path_for(parent_id: u64, d: &Arc<Dentry>) -> String {
    let d_ap = d.absolute_path();
    if let Some(p) = mount_by_id(parent_id) {
        if let Some(proot) = root_dentry_for_mount_id(parent_id) {
            let root_ap = proot.absolute_path();
            if d_ap.starts_with(root_ap.as_slice()) {
                // `/` root dentry renders as "/" (len 1); stripping it would eat the
                // leading slash, so treat the fs root as a zero-length prefix.
                let strip = if root_ap.as_slice() == b"/" { 0 } else { root_ap.len() };
                let rel = core::str::from_utf8(&d_ap[strip..]).unwrap_or("");
                let prp = p.mount_point_str();
                return if prp == "/" {
                    if rel.is_empty() { String::from("/") } else { String::from(rel) }
                } else {
                    let mut s = prp;
                    s.push_str(rel);      // rel starts with '/' (or is empty ⇒ stacked at prp)
                    s
                };
            }
        }
    }
    String::from_utf8(d_ap).unwrap_or_else(|_| String::from("/"))
}

/// Materialise the dentry at `rel` beneath `base` by a dentry→dentry descent
/// that CROSSES MOUNTS at each component exactly as namei does — the
/// engine-internal resolver for SYNTHESIZED mount positions (propagation
/// mirrors, MS_MOVE / pivot_root relocations). NEVER a global path-string
/// resolve. `rel` empty ⇒ `base` itself. # C: O(components)
pub(super) fn descend(base: &Arc<Dentry>, rel: &str) -> Option<Arc<Dentry>> {
    let ns = current_ns();
    let mut cur = base.clone();
    // [D24] Track the mount the descent is currently "in" so crossings resolve via
    // the strict `(parent_mnt_id, dentry)` hash (Linux `__lookup_mnt`) instead of
    // the deleted parent-agnostic `dentry.mounted_mounts` map. Seeded from the
    // mount containing `base`.
    let mut cur_mnt = containing_mount_id(ns, base);
    let mut cur_inode: Option<crate::inode::InodeRef> = None;
    for comp in rel.split('/').filter(|c| !c.is_empty()) {
        let parent_inode = match cur_inode.take() { Some(i) => i, None => cur.inode()? };
        let child = match crate::dcache::d_lookup(&cur, comp) {
            Some(d) if !d.is_negative() => d,
            _ => {
                let ci = parent_inode.lookup(comp).ok()?;
                crate::dcache::d_add(&cur, comp, ci)
            }
        };
        let mut child = child;
        while let Some(m) = __lookup_mnt(cur_mnt, &child) {
            match m.mnt_root() { Some(sr) => { child = sr; cur_mnt = m.mnt_id; } None => break }
        }
        cur_inode = Some(child.inode()?);
        cur = child;
    }
    Some(cur)
}

/// The global namespace-root dentry. # C: O(1)
pub(super) fn global_root() -> Option<Arc<Dentry>> { crate::namei::root_dentry() }

// ---------------------------------------------------------------------------
// (parent_mnt_id, mountpoint_dentry_ptr) -> mnt_id stack — Linux
// `__lookup_mnt`. Top of stack = last attached (overmounts). The `ns` is NOT
// part of the key: `parent_mnt_id` is already ns-PRIVATE (every namespace mints
// fresh, never-recycled `mnt_id`s, and `copy_mnt_ns` re-stamps each clone), so
// a `(parent, dentry)` pair belongs to exactly one namespace — exactly Linux's
// `mount_hashtable` keyed on `(mnt_parent, mnt_mountpoint)`.
// ---------------------------------------------------------------------------
static MOUNT_HASH: Spinlock<BTreeMap<(u64, usize), Vec<u64>>, MountClass> =
    Spinlock::new(BTreeMap::new());

/// [D28a] Mount-tree WRITER serialization lock (Linux `mount_lock`/`namespace_sem`
/// write side — the coarse mutator gate). Every mount-tree MUTATOR takes this
/// OUTERMOST around its multi-structure mutation so two concurrent writers cannot
/// interleave the separate `MOUNTS` / `MOUNT_HASH` / `MOUNTPOINTS` / `NAMESPACES`
/// critical sections and leave them mutually inconsistent (the confirmed torn
/// window: graft inserts `MOUNTS` then `MOUNT_HASH` in SEPARATE sections; detach
/// removes them symmetrically). LOCK ORDERING (`MountWrite` rank 58, `06§3.6`):
/// STRICT OUTERMOST of the mount locks — acquired BEFORE any `MountClass`/`MountTable`
/// (70) structure lock and BEFORE `Superblock` (60, via `grab_active`), and NEVER
/// while one of those is held. It is NEVER held across a SLEEPING call — the
/// crossing-resolver `descend`/`descend_nocross`/`descend_mountpoint` (which call
/// `inode.lookup`) and `put_super_if_last` (`deactivate_super`) run OUTSIDE the
/// region — so each mutator scopes the lock to exactly its non-sleeping structural
/// mutation. READERS do NOT take it (the D28b reader-seqlock is out of scope; a
/// lock-free mount reader does not exist — readers still take `MOUNT_HASH.lock`).
/// Non-recursive (plain `Spinlock`): a mutator under `MOUNT_WRITE` must never call
/// another that takes it — `rebuild_ns_index` therefore does NOT self-lock; its
/// callers (`copy_mnt_ns`, `commit_retree`) hold `MOUNT_WRITE` around it instead.
static MOUNT_WRITE: Spinlock<(), MountWriteClass> = Spinlock::new(());

fn hash_insert(parent: u64, d: usize, mnt_id: u64) {
    MOUNT_HASH.lock().entry((parent, d)).or_default().push(mnt_id);
}
fn hash_remove(parent: u64, d: usize, mnt_id: u64) {
    let mut h = MOUNT_HASH.lock();
    if let Some(stack) = h.get_mut(&(parent, d)) {
        stack.retain(|&id| id != mnt_id);
        if stack.is_empty() { h.remove(&(parent, d)); }
    }
}
fn hash_top(parent: u64, d: usize) -> Option<u64> {
    MOUNT_HASH.lock().get(&(parent, d)).and_then(|s| s.last().copied())
}
/// Drop every hash entry naming one of `ids` (the ns-private `mnt_id`s of a
/// namespace being rebuilt / reaped). Replaces the old `ns`-keyed bulk drop now
/// that the key carries no `ns`. # C: O(N_hash × N_ids)
fn hash_drop_ids(ids: &[u64]) {
    let mut h = MOUNT_HASH.lock();
    h.retain(|_, stack| { stack.retain(|id| !ids.contains(id)); !stack.is_empty() });
}

/// `__lookup_mnt` (Linux `fs/namespace.c`): the (top) mount attached on
/// mountpoint dentry `d` whose PARENT mount is `parent_mnt_id`, by the
/// `(parent, dentry)` hash. [D24] THE crossing primitive the path walk
/// (`follow_mount_down`) and the engine-internal `descend` now read — the legacy
/// parent-agnostic `dentry.mounted_mounts` map it replaced is deleted. # C: O(log N)
pub fn __lookup_mnt(parent_mnt_id: u64, d: &Arc<Dentry>) -> Option<Arc<Mount>> {
    hash_top(parent_mnt_id, dptr(d)).and_then(mount_by_id)
}

/// [D24] The (top) mount in `ns` whose MOUNTPOINT dentry is `d`, PARENT-AGNOSTIC
/// — the strict-hash replacement for the deleted per-ns `dentry.mounted_mounts`
/// map. A mountpoint dentry's identity plus its containing filesystem fix its
/// parent mount, so every mount stacked here shares ONE `(parent, dptr)` hash
/// key; find that parent from any candidate, then return the hash TOP (last
/// attached = the overmount visible there). `None` ⇒ nothing mounted on `d` in
/// `ns`. Used where a caller has only the mountpoint dentry (not the containing
/// mount id) — e.g. `parent_by_dentry`'s ancestor walk, the busy/exact tests.
/// # C: O(N_mounts)
fn top_mount_on(ns: u64, d: &Arc<Dentry>) -> Option<u64> {
    let dp = dptr(d);
    // The visible top mount AT `d` is the LAST-attached one whose mountpoint
    // dentry is `d` (mnt_id is monotonic = attach/stack order), read DIRECTLY
    // from the arena. This is the exact value the legacy last-write-wins map
    // held. NOTE: do NOT indirect through `hash_top(parent_of_max, d)` — a
    // hash-only D24 clone can leave a mount in the `(parent,dptr)` bucket whose
    // mountpoint is no longer `d`, so the parent-indirection reports a mount as
    // covering `d` when none does (false Ebusy on move, missed shared/unbindable
    // parent checks). The direct arena scan cannot drift from the tree.
    MOUNTS.lock().values()
        .filter(|m| m.ns == ns && m.mountpoint().map(|mp| dptr(&mp) == dp).unwrap_or(false))
        .map(|m| m.mnt_id)
        .max()
}

/// Parent mount id for a mount whose mountpoint dentry is `mp_d`, by DENTRY
/// IDENTITY (Linux `mnt_parent`). # C: O(depth)
fn parent_by_dentry(ns: u64, mp_d: &Arc<Dentry>) -> u64 {
    // [D9] OVERMOUNT parent: when `mp_d` is ITSELF the root dentry of a mount X,
    // a mount attached here is stacked ON X (Linux resolves the mount target
    // THROUGH the existing mount, landing on its `mnt_root`), so its parent is X
    // — the underlay top mount — NOT X's own parent. The legacy loop started at
    // `mp_d.parent()` (None for a root dentry) and fell through to the ns-root
    // mount, mis-parenting every overmount; that broke a per-`(parent,dentry)`
    // hash lookup (`__lookup_mnt(X, X_root)` could not find the overmount). The
    // pre-loop root check makes the new hash resolve the overmount top
    // deterministically by tree position instead of Vec-stack order.
    if mp_d.is_root() {
        if let Some(id) = visible_mnt_id_of_root_dentry(ns, mp_d) { return id; }
    }
    let mut cur = mp_d.parent().cloned();
    while let Some(a) = cur {
        if let Some(id) = top_mount_on(ns, &a) { return id; }
        if a.is_root() {
            if let Some(id) = visible_mnt_id_of_root_dentry(ns, &a) { return id; }
            match cross_up(ns, &a) { Some(p) => { cur = Some(p); continue; } None => break }
        }
        cur = a.parent().cloned();
    }
    root_mount_id(ns).unwrap_or(0)
}

/// Relative path of `mp` beneath `stop` (exclusive), identity-bounded.
/// # C: O(depth)
pub(super) fn rel_under(mp: &Arc<Dentry>, stop: Option<&Arc<Dentry>>) -> Option<String> {
    let ns = current_ns();
    let mut names: Vec<String> = Vec::new();
    let mut cur = Some(mp.clone());
    while let Some(d) = cur {
        if let Some(s) = stop {
            if Arc::ptr_eq(&d, s) { return Some(join_names(&names)); }
        }
        match cross_up(ns, &d) {
            None => return if stop.is_none() { Some(join_names(&names)) } else { None },
            Some(p) => { if !d.name().is_empty() { names.push(d.name().to_string()); } cur = Some(p); }
        }
    }
    None
}

fn join_names(names: &[String]) -> String {
    let mut out = String::new();
    for n in names.iter().rev() { out.push('/'); out.push_str(n); }
    out
}

/// MOUNT-AWARE relative path of `mp` beneath `stop` (exclusive), starting in the
/// KNOWN mount `start_mnt`. Unlike [`rel_under`] (which re-derives the crossed
/// mount from the dentry alone via [`mount_with_root_dentry`] — AMBIGUOUS when an
/// SB-sharing clone shares one `s_root`, Stage 1), this carries the mount context
/// up the tree via the EXPLICIT `mnt_parent`/`mnt_mountpoint` links (Linux
/// `follow_up`): a plain dentry parent step stays in the same mount; at a mount
/// ROOT it crosses up to that mount's mountpoint dentry in its PARENT. `None` ⇒
/// `mp` is not under `stop` (when `stop` is `Some`). # C: O(depth)
fn rel_under_seeded(mp: &Arc<Dentry>, start_mnt: u64, stop: Option<&Arc<Dentry>>) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cur = mp.clone();
    let mut cur_mnt = start_mnt;
    loop {
        if let Some(s) = stop { if Arc::ptr_eq(&cur, s) { return Some(join_names(&names)); } }
        match cur.parent() {
            Some(p) => {
                // Plain parent within the current mount's filesystem.
                if !cur.name().is_empty() { names.push(cur.name().to_string()); }
                cur = p.clone();
            }
            None => {
                // At a filesystem ROOT: cross UP via the explicit mount links.
                let Some(m) = mount_by_id(cur_mnt) else {
                    return if stop.is_none() { Some(join_names(&names)) } else { None };
                };
                let parent = m.parent_id.load(Ordering::Acquire);
                match m.mountpoint() {
                    // ns-root mount (self-parent / no mountpoint): walk ends here.
                    _ if parent == cur_mnt => {
                        return if stop.is_none() { Some(join_names(&names)) } else { None };
                    }
                    Some(mp_d) => { cur = mp_d; cur_mnt = parent; }
                    None => {
                        return if stop.is_none() { Some(join_names(&names)) } else { None };
                    }
                }
            }
        }
    }
}

/// The mount in `subtree` whose `mnt_root` is the filesystem ROOT containing
/// dentry `d` (reached by PLAIN parent links) — the mount-aware seed for an
/// [`rel_under_seeded`] walk from a bare dentry whose containing mount a
/// dentry-ptr scan cannot pin down (a shared `s_root`). `pivot_root` uses it to
/// seed `put_old`, which must live inside the new-root subtree. # C: O(depth+N)
fn mount_owning_dentry_in(d: &Arc<Dentry>, subtree: &[u64]) -> Option<u64> {
    let mut r = d.clone();
    while let Some(p) = r.parent() { r = p.clone(); }
    let rp = dptr(&r);
    subtree.iter().copied()
        .filter_map(mount_by_id)
        .find(|m| m.mnt_root().map(|mr| dptr(&mr) == rp).unwrap_or(false))
        .map(|m| m.mnt_id)
}

/// Relative path of `mp` beneath `stop` via PLAIN parent links only (NO mount
/// crossing). Distinguishes an UNDERLAY child (mounted on a dentry beneath
/// `stop` in the SAME fs — an MS_MOVE of `stop` relocates it) from an IN-FS
/// child (mounted on a dentry INSIDE the moved fs, reached only by crossing
/// `stop`; Linux `copy_tree` keeps it in place). `None` ⇒ not a plain-parent
/// descendant of `stop`. # C: O(depth)
fn plain_rel_under(mp: &Arc<Dentry>, stop: &Arc<Dentry>) -> Option<String> {
    let mut names: Vec<String> = Vec::new();
    let mut cur = Some(mp.clone());
    while let Some(d) = cur {
        if Arc::ptr_eq(&d, stop) { return Some(join_names(&names)); }
        if !d.name().is_empty() { names.push(d.name().to_string()); }
        cur = d.parent().cloned();
    }
    None
}

/// All mounts in `ns`, sorted by `mnt_id` ascending (= attach order, the
/// overmount stack order). # C: O(N_mounts)
pub(super) fn mounts_in_ns(ns: u64) -> Vec<Arc<Mount>> {
    MOUNTS.lock().values().filter(|m| m.ns == ns).cloned().collect()
}

/// Rebuild the POSITIONAL links for namespace `ns` from each mount's recorded
/// mountpoint dentry (identity only): crossings + `parent_id` + `mnt_parent`
/// + `mnt_mounts` child lists + hash. Propagation links (master/slave) are
/// position-independent and untouched. The single funnel for bulk paths
/// (move / pivot / copy_mnt_ns). # C: O(N×depth)
fn rebuild_ns_index(ns: u64) {
    let mounts = mounts_in_ns(ns);
    let ids: Vec<u64> = mounts.iter().map(|m| m.mnt_id).collect();
    hash_drop_ids(&ids);
    // Clear crossings + parent/child links + RELEASE each mount's current
    // `struct mountpoint` hold first. Releasing then re-acquiring keeps the
    // `m_count` (and the `D_MOUNTED` flag it gates) exactly balanced regardless
    // of the caller's prior state: a `copy_mnt_ns` clone arrives with NO hold
    // (`mnt_mp == None`), a `commit_retree` mount arrives with one already set
    // by `set_mountpoint_dentry` — both end with exactly one hold per crossing.
    for m in mounts.iter() {
        if let Some(o) = m.mnt_mp.lock().take() { put_mountpoint(&o); }
        m.mnt_mounts.lock().clear();
        *m.mnt_parent.lock() = Weak::new();
    }
    // RE-ACQUIRE the `struct mountpoint` hold so the `D_MOUNTED` refcount tracks
    // this ns's crossings (Linux `get_mountpoint` per attached child after a tree
    // rebuild). The crossing IDENTITY itself lives in the `(parent,dentry)` hash
    // re-inserted below — there is no longer a per-ns `mounted_mounts` map to wire.
    for m in mounts.iter() {
        if let Some(d) = m.mountpoint() {
            *m.mnt_mp.lock() = Some(get_mountpoint(&d));
        }
    }
    // Parent + child links + hash from the wired crossings. The recorded
    // `parent_id` (the explicit Linux `mnt_parent`) is left intact by the clear
    // loop above, so the parent-aware derivation below can consult it.
    for m in mounts.iter() {
        match m.mountpoint() {
            None => { m.parent_id.store(m.mnt_id, Ordering::Release); }
            Some(d) => {
                let recorded = m.parent_id.load(Ordering::Acquire);
                let derived = parent_by_dentry(ns, &d);
                // [Stage 0] PARENT-AWARE: a dentry-ptr scan cannot tell two
                // mounts that SHARE one `s_root` (an SB-sharing clone, Stage 1)
                // apart, so when `parent_by_dentry` lands on a mount sharing the
                // recorded explicit parent's superblock root, trust the recorded
                // `mnt_parent` (Linux never re-derives it). When they do NOT share
                // an `s_root`, the parent genuinely moved (a pivot relocation) and
                // the freshly derived one wins.
                let parent = if recorded != 0 && recorded != m.mnt_id
                    && same_sb_root(recorded, derived) { recorded } else { derived };
                m.parent_id.store(parent, Ordering::Release);
                if let Some(p) = mount_by_id(parent) {
                    *m.mnt_parent.lock() = Arc::downgrade(&p);
                    p.mnt_mounts.lock().push(m.clone());
                }
                hash_insert(parent, dptr(&d), m.mnt_id);
            }
        }
    }
}

/// True iff mounts `a` and `b` resolve to the SAME superblock root dentry (or are
/// the same mount) — the signature of an SB-sharing clone pair that a bare
/// dentry-ptr scan cannot disambiguate. # C: O(log N)
fn same_sb_root(a: u64, b: u64) -> bool {
    if a == b { return true; }
    match (mount_by_id(a), mount_by_id(b)) {
        (Some(ma), Some(mb)) => match (ma.sb.s_root(), mb.sb.s_root()) {
            (Some(ra), Some(rb)) => dptr(&ra) == dptr(&rb),
            _ => false,
        },
        _ => false,
    }
}
