// Kernel-side binding of the `cgattach` algebra to live cgroup ids —
// Linux keeps this state in `struct cgroup`'s embedded `cgroup_bpf`
// (include/linux/bpf-cgroup-defs.h). The cgroup crate is a leaf that may
// not depend on `security`, so the lists live here, keyed by the cgroup
// id, and the hierarchy walk goes through `cgroup::parent_of()`.
//
// Effective arrays are computed on demand rather than cached per
// descendant (`update_effective_progs()`): the per-cgroup lists stay the
// single source of truth, and a device check is a `open`/`mknod`-rate
// event, not a packet-rate one.

extern crate alloc;
use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use sync::{Spinlock, TaskList as TaskListClass};
use syscall::errno::Errno;
use vfs::InodeRef;

use super::BpfProgInode;
use super::cgattach::{Anchor, AttachList, AttachReq, attach as list_attach, detach as list_detach, effective as list_effective};

/// A loaded program's identity: the fd-backed inode it was published on.
/// Linux compares `struct bpf_prog *` pointers; the `Arc` is the same
/// identity and keeps the program alive for as long as a cgroup holds it,
/// even after userspace closes the loading fd.
#[derive(Clone)]
pub struct ProgRef(pub InodeRef);

impl core::fmt::Debug for ProgRef {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ProgRef(id={})", self.prog().map(|p| p.id).unwrap_or(0))
    }
}

impl PartialEq for ProgRef {
    fn eq(&self, o: &Self) -> bool { Arc::ptr_eq(&self.0, &o.0) }
}
impl Eq for ProgRef {}

impl ProgRef {
    /// # C: O(1)
    pub fn prog(&self) -> Option<&BpfProgInode> { self.0.private::<BpfProgInode>() }
}

/// `BPF_CGROUP_DEVICE` attach lists, keyed by cgroup id. Only this attach
/// type has a loadable program type, so it is the only list a cgroup can
/// hold; a new cgroup attach type arrives with its own map plus the run
/// site that consumes it.
static DEVICE: Spinlock<BTreeMap<u64, AttachList<ProgRef>>, TaskListClass> =
    Spinlock::new(BTreeMap::new());

/// `cgroup_bpf_enabled_key[CGROUP_DEVICE]` — lets the device check skip
/// the map lock (and the cgroup lookup) on a system with nothing attached.
static DEVICE_ENABLED: AtomicBool = AtomicBool::new(false);

/// `bpf_prog_alloc_id()` — ids are 1-based and never reused.
static NEXT_PROG_ID: AtomicU32 = AtomicU32::new(1);

/// # C: O(1)
pub fn alloc_prog_id() -> u32 { NEXT_PROG_ID.fetch_add(1, Ordering::Relaxed) }

/// # C: O(1)
pub fn device_enabled() -> bool { DEVICE_ENABLED.load(Ordering::Acquire) }

/// `cgroup` ids from `cgid`'s parent up to the root. # C: O(depth)
fn ancestor_ids(cgid: u64) -> Vec<u64> {
    let mut v = Vec::new();
    let mut cur = cgroup::parent_of(cgid);
    while let Some(id) = cur {
        v.push(id);
        cur = cgroup::parent_of(id);
    }
    v
}

/// `cgroup_bpf_attach()` for `BPF_CGROUP_DEVICE`. # C: O(depth · progs)
pub fn device_attach(cgid: u64, req: AttachReq<ProgRef>, anchor: Anchor<ProgRef>) -> Result<(), Errno> {
    let ids = ancestor_ids(cgid);
    let mut map = DEVICE.lock();
    let mut leaf = map.remove(&cgid).unwrap_or_default();
    let empty = AttachList::<ProgRef>::new();
    let ancestors: Vec<&AttachList<ProgRef>> =
        ids.iter().map(|id| map.get(id).unwrap_or(&empty)).collect();
    let r = list_attach(&mut leaf, &ancestors, req, anchor);
    drop(ancestors);
    if !leaf.is_empty() || r.is_ok() { map.insert(cgid, leaf); }
    DEVICE_ENABLED.store(!map.is_empty(), Ordering::Release);
    r
}

/// `cgroup_bpf_detach()` for `BPF_CGROUP_DEVICE`. # C: O(progs)
pub fn device_detach(cgid: u64, prog: Option<&ProgRef>, revision: u64) -> Result<(), Errno> {
    let mut map = DEVICE.lock();
    let Some(leaf) = map.get_mut(&cgid) else { return Err(Errno::Enoent); };
    let r = list_detach(leaf, prog, revision);
    if leaf.is_empty() { map.remove(&cgid); }
    DEVICE_ENABLED.store(!map.is_empty(), Ordering::Release);
    r
}

/// The `BPF_CGROUP_DEVICE` program array a task in `cgid` runs.
/// # C: O(depth · progs)
pub fn device_effective(cgid: u64) -> Vec<ProgRef> {
    let ids = ancestor_ids(cgid);
    let map = DEVICE.lock();
    if map.is_empty() { return Vec::new(); }
    let empty = AttachList::<ProgRef>::new();
    let mut levels: Vec<&AttachList<ProgRef>> = Vec::with_capacity(ids.len() + 1);
    levels.push(map.get(&cgid).unwrap_or(&empty));
    for id in &ids { levels.push(map.get(id).unwrap_or(&empty)); }
    list_effective(&levels)
}

/// `cgroup_bpf_release()` — the node is gone, so its attach lists are too.
/// Registered on the cgroup crate's release hook at boot. # C: O(log n)
pub fn release(cgid: u64) {
    let mut map = DEVICE.lock();
    map.remove(&cgid);
    DEVICE_ENABLED.store(!map.is_empty(), Ordering::Release);
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::uapi::attach_flags as af;
    use super::super::{make_bpf_prog_inode, uapi};

    fn prog() -> ProgRef {
        ProgRef(make_bpf_prog_inode(uapi::prog_type::CGROUP_DEVICE, alloc_prog_id(),
                                    alloc::vec![0x95, 0, 0, 0, 0, 0, 0, 0]))
    }

    fn req(p: &ProgRef, flags: u32) -> AttachReq<ProgRef> {
        AttachReq {
            prog: p.clone(), id: p.prog().map(|b| b.id).unwrap_or(0), replace: None,
            flags, id_or_fd: 0, revision: 0,
        }
    }

    /// One test: `DEVICE`/`DEVICE_ENABLED` are process-global, so parallel
    /// test threads would clobber each other's attach state.
    #[test]
    fn attach_detach_and_release_drive_the_enabled_gate() {
        // No cgroup tree is mounted in a hosted test, so `parent_of` reports
        // no ancestors and every id behaves as a root.
        assert!(!device_enabled());
        assert!(device_effective(7).is_empty());

        let a = prog();
        let b = prog();
        assert_eq!(device_attach(7, req(&a, af::ALLOW_MULTI), Anchor::None), Ok(()));
        assert!(device_enabled());
        assert_eq!(device_attach(7, req(&b, af::ALLOW_MULTI), Anchor::None), Ok(()));
        assert_eq!(device_effective(7), alloc::vec![a.clone(), b.clone()]);
        // A sibling cgroup shares nothing.
        assert!(device_effective(8).is_empty());
        // Duplicate attach of a live program.
        assert_eq!(device_attach(7, req(&a, af::ALLOW_MULTI), Anchor::None), Err(Errno::Einval));

        assert_eq!(device_detach(7, Some(&a), 0), Ok(()));
        assert_eq!(device_effective(7), alloc::vec![b.clone()]);
        assert!(device_enabled());
        assert_eq!(device_detach(7, Some(&b), 0), Ok(()));
        assert!(!device_enabled());
        assert_eq!(device_detach(7, Some(&b), 0), Err(Errno::Enoent));

        // Releasing the cgroup drops whatever it still held.
        assert_eq!(device_attach(7, req(&a, af::ALLOW_MULTI), Anchor::None), Ok(()));
        assert!(device_enabled());
        release(7);
        assert!(!device_enabled());
        assert!(device_effective(7).is_empty());
    }
}
