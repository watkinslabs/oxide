use alloc::sync::Arc;
use alloc::vec::Vec;
use hal::UserVirtAddr;

use crate::{Error, VmaBacking};
use super::VmaTree;

impl VmaTree {
    /// Set one Linux anonymous-VMA name across a fully mapped range. The
    /// operation validates every VMA before changing any, then splits and
    /// re-merges exactly at the requested boundaries.
    /// # C: O(K log N)
    pub fn set_anon_name_range(&mut self, start: UserVirtAddr, end: UserVirtAddr,
                               name: Option<Arc<str>>) -> Result<(), Error> {
        if start.as_u64() >= end.as_u64() { return Err(Error::Inval); }
        let mut cursor = start.as_u64();
        for (_, v) in self.map.range(..end) {
            if v.end.as_u64() <= cursor { continue; }
            if v.start.as_u64() > cursor { return Err(Error::NoMem); }
            if !matches!(v.backing, VmaBacking::Anonymous) { return Err(Error::Access); }
            cursor = v.end.as_u64();
            if cursor >= end.as_u64() { break; }
        }
        if cursor < end.as_u64() { return Err(Error::NoMem); }
        let keys: Vec<UserVirtAddr> = self.map.range(..end)
            .filter_map(|(k, v)| (v.end.as_u64() > start.as_u64()).then_some(*k)).collect();
        for k in keys {
            let v = self.map.remove(&k).expect("collected VMA key");
            let (vs, ve) = (v.start.as_u64(), v.end.as_u64());
            let (s, e) = (start.as_u64().max(vs), end.as_u64().min(ve));
            if vs < s {
                let left = v.clone_subrange(v.start, UserVirtAddr::new(s).expect("validated VMA boundary"));
                self.map.insert(left.start, left);
            }
            let mut mid = v.clone_subrange(UserVirtAddr::new(s).expect("validated VMA boundary"),
                                             UserVirtAddr::new(e).expect("validated VMA boundary"));
            mid.anon_name = name.as_ref().map(Arc::clone);
            let mid_key = mid.start;
            self.map.insert(mid_key, mid);
            if e < ve {
                let right = v.clone_subrange(UserVirtAddr::new(e).expect("validated VMA boundary"), v.end);
                self.map.insert(right.start, right);
            }
            self.try_merge_left(mid_key);
            let key = if self.map.contains_key(&mid_key) { mid_key }
                else { self.map.range(..mid_key).next_back().map(|(k, _)| *k).expect("left VMA") };
            self.try_merge_right(key);
        }
        Ok(())
    }
}
