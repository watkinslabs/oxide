//! Heap-owned hibernation workspaces kept off bounded kernel stacks.

extern crate alloc;
use alloc::boxed::Box;
use alloc::vec::Vec;

/// Exact heap workspace without caller-stack materialization.
/// # C: O(N)
pub(super) fn zeroed<T: Copy + Default, const N: usize>() -> Option<Box<[T; N]>> {
    let mut values = Vec::new();
    values.try_reserve_exact(N).ok()?;
    values.resize(N, T::default());
    values.into_boxed_slice().try_into().ok()
}

#[cfg(test)]
mod tests {
    #[test]
    fn workspace_has_exact_zeroed_heap_extent() {
        let mut page = super::zeroed::<u8, 4096>().unwrap();
        assert_eq!(page.len(), 4096);
        assert!(page.iter().all(|byte| *byte == 0));
        page[4095] = 1;
        assert_eq!(page[4095], 1);
    }
}
