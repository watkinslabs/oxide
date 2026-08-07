// Scheduler-owned membership indices for owner-shaped task queries. `by_mm`
// replaces process_mrelease's global task scan; `by_tgid` handles the rare
// case where the pidfd-named thread already dropped its own mm. VMM does not
// own this relation: it cannot depend on scheduler Task ownership.

use alloc::collections::BTreeMap;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use sync::{MmTaskIndex, Spinlock};
use vmm::AddressSpace;

use crate::Task;

struct Members {
    by_mm: BTreeMap<usize, Vec<Member>>,
    by_tgid: BTreeMap<usize, Vec<Member>>,
}

impl Members {
    const fn new() -> Self { Self { by_mm: BTreeMap::new(), by_tgid: BTreeMap::new() } }
}

static MEMBERS: Spinlock<Members, MmTaskIndex> = Spinlock::new(Members::new());

#[derive(Copy, Clone)]
struct Member { tid: u32, ptr: usize }

fn mm_key(mm: &Arc<AddressSpace>) -> usize { Arc::as_ptr(mm) as usize }

fn member(task: &Task) -> Member { Member { tid: task.tid, ptr: task as *const Task as usize } }

fn add(bucket: &mut Vec<Member>, task: &Task) {
    let member = member(task);
    if !bucket.iter().any(|old| old.tid == member.tid && old.ptr == member.ptr) { bucket.push(member); }
}

fn live_bucket(map: &mut BTreeMap<usize, Vec<Member>>, key: usize) -> Vec<Member> {
    let Some(bucket) = map.get_mut(&key) else { return Vec::new(); };
    bucket.clone()
}

/// Seed both indices before the task is published in the tid registry.
/// # C: O(log N_groups + log N_mms)
pub(crate) fn track_task_before_publish(task: &Arc<Task>) {
    let mm = task.clone_mm();
    let tgid = task.tgid.load(Ordering::Acquire);
    let mut members = MEMBERS.lock();
    add(members.by_tgid.entry(tgid as usize).or_default(), task);
    if let Some(mm) = mm { add(members.by_mm.entry(mm_key(&mm)).or_default(), task); }
}

/// Add a task to `new_mm`'s bucket while its old mm remains installed.
/// # C: O(log N_mms + N_sharers)
/// # Lk: TaskList -> MmTaskIndex
pub(crate) fn track_mm_before_replace(task: &Task, new_mm: &Arc<AddressSpace>) {
    let mut members = MEMBERS.lock();
    add(members.by_mm.entry(mm_key(new_mm)).or_default(), task);
}

/// Remove the departed-mm membership only after the authoritative task slot
/// has changed. This pairs with `track_mm_before_replace`: readers therefore
/// never miss a current sharer, and buckets contain only current live sharers
/// once a replacement finishes.
/// # C: O(log N_mms + N_sharers)
/// # Lk: TaskList -> MmTaskIndex
pub(crate) fn untrack_mm_after_replace(task: &Task, old_mm: &Arc<AddressSpace>) {
    let mut members = MEMBERS.lock();
    let key = mm_key(old_mm);
    let Some(bucket) = members.by_mm.get_mut(&key) else { return; };
    let member = member(task);
    bucket.retain(|candidate| candidate.tid != member.tid || candidate.ptr != member.ptr);
    if bucket.is_empty() { members.by_mm.remove(&key); }
}

/// Live tasks currently sharing `mm`. Candidates are revalidated against the
/// authoritative Task mm after dropping the index lock.
/// # C: O(N_sharers)
pub fn mm_sharers(mm: &Arc<AddressSpace>) -> Vec<Arc<Task>> {
    let candidates = live_bucket(&mut MEMBERS.lock().by_mm, mm_key(mm));
    candidates.into_iter()
        .filter_map(|member| super::tid::lookup(member.tid)
            .filter(|task| Arc::as_ptr(task) as usize == member.ptr))
        .filter(|task| task.clone_mm().is_some_and(|current| Arc::ptr_eq(&current, mm)))
        .collect()
}

/// Live tasks in a real thread group, without a registry-wide walk.
/// # C: O(N_threads_in_group)
pub fn thread_group_members(tgid: u32) -> Vec<Arc<Task>> {
    live_bucket(&mut MEMBERS.lock().by_tgid, tgid as usize).into_iter()
        .filter_map(|member| super::tid::lookup(member.tid)
            .filter(|task| Arc::as_ptr(task) as usize == member.ptr))
        .filter(|task| task.tgid.load(Ordering::Acquire) == tgid)
        .collect()
}

#[cfg(any(test, feature = "hosted"))]
pub(super) fn clear_for_tests() {
    let mut members = MEMBERS.lock();
    members.by_mm.clear();
    members.by_tgid.clear();
}
