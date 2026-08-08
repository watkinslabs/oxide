// The ring's half of the asynchronous engine: the in-flight table, the
// borrowed execution context, the per-class concurrency limits, and the
// completion counter a count-gated timeout is measured against.

use alloc::sync::Arc;

use core::sync::atomic::Ordering;

use crate::io_uring::iowq::{acct, Owner};
use crate::io_uring::req::IoReq;

use super::IoUringInode;

impl IoUringInode {
    /// The execution context this ring's deferred work runs under, captured
    /// from the running task the first time it is asked for. Captured once
    /// rather than per request: it is the ring's submitter's context, and a
    /// ring that admits more than one submitter has already said (by not
    /// asking for a single issuer) that it does not distinguish them.
    /// # C: O(1)
    pub fn owner_ctx(&self) -> Arc<Owner> {
        if let Some(o) = self.owner.lock().as_ref() { return Arc::clone(o); }
        let o = Owner::of_current();
        let mut slot = self.owner.lock();
        match slot.as_ref() {
            Some(existing) => Arc::clone(existing),
            None => { *slot = Some(Arc::clone(&o)); o }
        }
    }

    /// Record a request as outstanding. # C: O(1) amortised
    pub fn track(&self, req: &Arc<IoReq>) { self.inflight.lock().insert(req); }

    /// Every request this ring still owes a completion for. # C: O(N)
    pub fn inflight_reqs(&self) -> alloc::vec::Vec<Arc<IoReq>> {
        let mut t = self.inflight.lock();
        t.sweep();
        t.live()
    }

    /// Whether this ring may start another request of `class` right now. A
    /// registered worker limit is a limit on how much of this ring's work runs
    /// at once, so it is checked here and released when the request ends.
    /// # C: O(1)
    pub fn iowq_admits(&self, class: usize) -> bool {
        let max = self.iowq_max[class].load(Ordering::Acquire);
        loop {
            let cur = self.iowq_running[class].load(Ordering::Acquire);
            if cur >= max { return false; }
            if self.iowq_running[class]
                .compare_exchange(cur, cur + 1, Ordering::AcqRel, Ordering::Acquire).is_ok()
            {
                return true;
            }
        }
    }

    /// Give back the slot `iowq_admits` took. # C: O(1)
    pub fn iowq_release(&self, class: usize) {
        let _ = self.iowq_running[class].fetch_update(
            Ordering::AcqRel, Ordering::Acquire,
            |n| if n == 0 { None } else { Some(n - 1) },
        );
    }

    /// Install new per-class limits, reporting what they were. A zero asks for
    /// no change, which is what makes the registration usable as a query.
    /// # C: O(1)
    pub fn set_iowq_max(&self, new: [u32; acct::NR]) -> [u32; acct::NR] {
        let mut prev = [0u32; acct::NR];
        for c in 0..acct::NR {
            prev[c] = self.iowq_max[c].load(Ordering::Acquire);
            if new[c] != 0 { self.iowq_max[c].store(new[c], Ordering::Release); }
        }
        prev
    }

    /// Note an armed timeout that fires on this ring's completion count, or
    /// release one. A completion posted while any are armed has to rouse the
    /// pool, since nothing else will notice that one became due. # C: O(1)
    pub fn note_count_timer(&self, delta: i32) {
        if delta > 0 { self.count_timers.fetch_add(1, Ordering::AcqRel); }
        else {
            let _ = self.count_timers.fetch_update(Ordering::AcqRel, Ordering::Acquire,
                |n| if n == 0 { None } else { Some(n - 1) });
        }
    }

    /// Whether a completion on this ring can make an armed timeout due.
    /// # C: O(1)
    pub fn has_count_timers(&self) -> bool { self.count_timers.load(Ordering::Acquire) > 0 }

    /// Completions posted since the ring was created. # C: O(1)
    pub fn posted_count(&self) -> u64 { self.posted.load(Ordering::Acquire) }

    /// Cancel every outstanding request. Run when the ring's last descriptor
    /// goes away: a request left armed would hold the ring alive for as long
    /// as its deadline or its description felt like, and its submitter is
    /// already gone. # C: O(N_inflight)
    pub fn cancel_all(&self) {
        for req in self.inflight_reqs() {
            let _ = crate::io_uring::cancel::cancel_one(&req);
        }
        *self.owner.lock() = None;
    }
}
