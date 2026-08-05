// Mutable VMA lookup used by the fault path to install per-mapping state.

use hal::UserVirtAddr;

use crate::vma::Vma;

use super::VmaTree;

impl VmaTree {
    /// Find the mutable VMA containing `va`.
    /// # C: O(log N)
    pub fn find_containing_mut(&mut self, va: UserVirtAddr) -> Option<&mut Vma> {
        let key = *self.map.range(..=va).next_back()?.0;
        let vma = self.map.get_mut(&key)?;
        if vma.contains(va) { Some(vma) } else { None }
    }
}
