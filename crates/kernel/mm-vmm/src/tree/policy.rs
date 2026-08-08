// mbind(2)'s VMA-policy rewrite and set_mempolicy_home_node(2)'s VMA
// walk over the VMA tree.

use alloc::vec::Vec;
use hal::UserVirtAddr;

use crate::mempolicy::uapi::{MPOL_BIND, MPOL_PREFERRED_MANY};
use crate::mempolicy::MemPolicy;
use crate::tree::VmaTree;

/// `set_mempolicy_home_node`'s two failure modes.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum HomeNodeErr {
    /// `-ENOENT` — the error the loop starts with. No VMA in the range
    /// carried a policy, so there was nothing whose home node to set.
    NoEnt,
    /// `-EOPNOTSUPP` — a VMA in the range has a policy that is neither
    /// `MPOL_BIND` nor `MPOL_PREFERRED_MANY`.
    OpNotSupp,
}

impl VmaTree {
    /// `mbind_range`: install `pol` on every VMA fragment overlapping
    /// `[start, end)`, splitting at the boundaries. Holes are legal — the
    /// caller (`do_mbind`) has already decided whether they are an EFAULT.
    /// # C: O(N_vma in range)
    pub fn set_policy_range(&mut self, start: UserVirtAddr, end: UserVirtAddr,
                            pol: Option<MemPolicy>) {
        self.rewrite_range(start, end, |v| v.mempolicy = pol);
    }

    /// `set_mempolicy_home_node`'s walk. Only VMAs that already carry a
    /// `MPOL_BIND` / `MPOL_PREFERRED_MANY` policy are updated; a VMA with no
    /// policy is skipped (it does not clear the pending ENOENT only because a
    /// LATER VMA succeeded), and any other mode aborts with EOPNOTSUPP after
    /// leaving earlier VMAs updated — Linux does not roll back either.
    /// # C: O(N_vma in range)
    pub fn set_home_node_range(&mut self, start: UserVirtAddr, end: UserVirtAddr,
                               home_node: i32) -> Result<(), HomeNodeErr> {
        let mut err = Err(HomeNodeErr::NoEnt);
        let mut ranges: Vec<(UserVirtAddr, UserVirtAddr)> = Vec::new();
        for (_, v) in self.map.range(..end) {
            if v.end.as_u64() <= start.as_u64() { continue; }
            match v.mempolicy {
                None => continue,
                Some(p) if p.mode == MPOL_BIND || p.mode == MPOL_PREFERRED_MANY => {}
                Some(_) => return Err(HomeNodeErr::OpNotSupp),
            }
            let s = UserVirtAddr::new(v.start.as_u64().max(start.as_u64())).expect("UVA in range");
            let e = UserVirtAddr::new(v.end.as_u64().min(end.as_u64())).expect("UVA in range");
            ranges.push((s, e));
        }
        for (s, e) in ranges {
            self.rewrite_range(s, e, |v| {
                if let Some(p) = v.mempolicy.as_mut() { p.home_node = home_node; }
            });
            err = Ok(());
        }
        err
    }

    /// Split at `[start, end)` and apply `f` to every fragment inside it.
    /// Shared by the policy writers; the same split shape `seal_range` uses.
    /// # C: O(N_vma in range)
    fn rewrite_range<F: FnMut(&mut crate::vma::Vma)>(&mut self, start: UserVirtAddr,
                                                     end: UserVirtAddr, mut f: F) {
        if start.as_u64() >= end.as_u64() { return; }
        let mut keys: Vec<UserVirtAddr> = Vec::new();
        for (k, v) in self.map.range(..end) {
            if v.end.as_u64() > start.as_u64() { keys.push(*k); }
        }
        for k in keys {
            let v = self.map.remove(&k).expect("collected key");
            let (v_start, v_end) = (v.start.as_u64(), v.end.as_u64());
            let s = start.as_u64().max(v_start);
            let e = end.as_u64().min(v_end);
            if v_start < s {
                let lend = UserVirtAddr::new(s).expect("UVA in range");
                let left = v.clone_subrange(v.start, lend);
                self.map.insert(left.start, left);
            }
            let ms = UserVirtAddr::new(s).expect("UVA in range");
            let me = UserVirtAddr::new(e).expect("UVA in range");
            let mut mid = v.clone_subrange(ms, me);
            f(&mut mid);
            self.map.insert(mid.start, mid);
            if e < v_end {
                let rstart = UserVirtAddr::new(e).expect("UVA in range");
                let right = v.clone_subrange(rstart, v.end);
                self.map.insert(right.start, right);
            }
        }
    }
}
