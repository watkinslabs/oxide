//! Allocation-free AVL index for permanent heap backing-region descriptors.

use core::ptr::NonNull;

use super::{HoleList, RegionHdr};

impl HoleList {
    pub(super) fn region_height(node: Option<NonNull<RegionHdr>>) -> u8 {
        node.map_or(0, |node| {
            // SAFETY: region descriptors are permanent allocator-owned
            // prefixes and their tree links are only read under the lock.
            unsafe { node.as_ref().height }
        })
    }

    /// Recompute one AVL node after a child change.
    ///
    /// # SAFETY: `node` is a permanent descriptor exclusively owned through
    /// this allocator's region tree while the outer lock is held.
    unsafe fn update_region_height(mut node: NonNull<RegionHdr>) {
        // SAFETY: the caller exclusively owns this permanent tree node.
        let current = unsafe { node.as_mut() };
        current.height = 1 + Self::region_height(current.left).max(Self::region_height(current.right));
    }

    /// Rotate one AVL subtree right and return its new root.
    ///
    /// # SAFETY: `root` and its left child are valid, exclusively-owned region
    /// descriptors linked in this tree.
    unsafe fn rotate_region_right(mut root: NonNull<RegionHdr>) -> NonNull<RegionHdr> {
        // SAFETY: caller guarantees a left child and exclusive tree mutation.
        let mut new_root = unsafe { root.as_ref().left }.expect("region AVL missing left child");
        // SAFETY: both nodes are permanent descriptors under the allocator lock.
        let middle = unsafe { new_root.as_ref().right };
        // SAFETY: both permanent nodes are exclusively owned while their AVL
        // links and derived heights are updated under the allocator lock.
        unsafe {
            root.as_mut().left = middle;
            new_root.as_mut().right = Some(root);
            Self::update_region_height(root);
            Self::update_region_height(new_root);
        }
        new_root
    }

    /// Rotate one AVL subtree left and return its new root.
    ///
    /// # SAFETY: `root` and its right child are valid, exclusively-owned region
    /// descriptors linked in this tree.
    unsafe fn rotate_region_left(mut root: NonNull<RegionHdr>) -> NonNull<RegionHdr> {
        // SAFETY: caller guarantees a right child and exclusive tree mutation.
        let mut new_root = unsafe { root.as_ref().right }.expect("region AVL missing right child");
        // SAFETY: both nodes are permanent descriptors under the allocator lock.
        let middle = unsafe { new_root.as_ref().left };
        // SAFETY: both permanent nodes are exclusively owned while their AVL
        // links and derived heights are updated under the allocator lock.
        unsafe {
            root.as_mut().right = middle;
            new_root.as_mut().left = Some(root);
            Self::update_region_height(root);
            Self::update_region_height(new_root);
        }
        new_root
    }

    /// Restore the AVL height invariant after inserting below `root`.
    ///
    /// # SAFETY: `root` owns a valid region subtree under the allocator lock.
    unsafe fn balance_region(mut root: NonNull<RegionHdr>) -> NonNull<RegionHdr> {
        // SAFETY: caller owns this subtree exclusively.
        unsafe { Self::update_region_height(root) };
        // SAFETY: permanent descriptor read under the allocator lock.
        let (left, right) = unsafe { (root.as_ref().left, root.as_ref().right) };
        let balance = i16::from(Self::region_height(left)) - i16::from(Self::region_height(right));
        if balance > 1 {
            let left = left.expect("region AVL left-heavy without child");
            // SAFETY: `left` is linked beneath `root` and exclusively owned.
            let left_balance = unsafe {
                i16::from(Self::region_height(left.as_ref().left))
                    - i16::from(Self::region_height(left.as_ref().right))
            };
            if left_balance < 0 {
                // SAFETY: a right-heavy left child has the required right link.
                let rotated = unsafe { Self::rotate_region_left(left) };
                // SAFETY: exclusive root mutation under the allocator lock.
                unsafe { root.as_mut().left = Some(rotated) };
            }
            // SAFETY: root has a left child after the optional double rotation.
            return unsafe { Self::rotate_region_right(root) };
        }
        if balance < -1 {
            let right = right.expect("region AVL right-heavy without child");
            // SAFETY: `right` is linked beneath `root` and exclusively owned.
            let right_balance = unsafe {
                i16::from(Self::region_height(right.as_ref().left))
                    - i16::from(Self::region_height(right.as_ref().right))
            };
            if right_balance > 0 {
                // SAFETY: a left-heavy right child has the required left link.
                let rotated = unsafe { Self::rotate_region_right(right) };
                // SAFETY: exclusive root mutation under the allocator lock.
                unsafe { root.as_mut().right = Some(rotated) };
            }
            // SAFETY: root has a right child after the optional double rotation.
            return unsafe { Self::rotate_region_left(root) };
        }
        root
    }

    /// Insert a unique region descriptor and return the balanced subtree root.
    ///
    /// # SAFETY: every node is permanent, `node` is not already linked, its
    /// interval does not overlap the tree, and the allocator lock is held.
    pub(super) unsafe fn insert_region(
        root: Option<NonNull<RegionHdr>>,
        node: NonNull<RegionHdr>,
    ) -> NonNull<RegionHdr> {
        let Some(mut root) = root else { return node };
        if node.as_ptr() < root.as_ptr() {
            // SAFETY: caller's unique/non-overlap contract is preserved in the
            // selected child subtree.
            let inserted = unsafe { Self::insert_region(root.as_ref().left, node) };
            // SAFETY: exclusive tree mutation under the allocator lock.
            unsafe { root.as_mut().left = Some(inserted) };
        } else {
            // SAFETY: same contract, for the right subtree.
            let inserted = unsafe { Self::insert_region(root.as_ref().right, node) };
            // SAFETY: exclusive tree mutation under the allocator lock.
            unsafe { root.as_mut().right = Some(inserted) };
        }
        // SAFETY: insertion leaves a valid BST that only needs AVL rebalancing.
        unsafe { Self::balance_region(root) }
    }
}
