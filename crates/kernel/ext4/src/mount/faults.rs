use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use super::Mount;

pub(crate) struct HostedFaults {
    pub(crate) next_alloc_block: AtomicBool,
    pub(crate) alloc_block_after: AtomicU32,
    pub(crate) next_free_block:  AtomicBool,
    pub(crate) free_block_after: AtomicU32,
    pub(crate) next_inode_write: AtomicBool,
    pub(crate) inode_write_after: AtomicU32,
    pub(crate) next_metadata_write: AtomicBool,
    pub(crate) metadata_write_after: AtomicU32,
    pub(crate) next_inode_read: AtomicBool,
    pub(crate) inode_read_after: AtomicU32,
    pub(crate) inode_reads: AtomicU32,
    pub(crate) next_extent_write: AtomicBool,
    pub(crate) extent_write_after: AtomicU32,
    pub(crate) next_data_write:  AtomicBool,
    pub(crate) next_quota_info_write: AtomicBool,
    pub(crate) quota_info_write_after: AtomicU32,
    pub(crate) next_quota_record_write: AtomicBool,
    pub(crate) next_quota_qblk_write: AtomicBool,
    pub(crate) quota_qblk_write_after: AtomicU32,
    pub(crate) next_quota_mark_dirty: AtomicBool,
    pub(crate) quota_mark_dirty_after: AtomicU32,
}

impl HostedFaults {
    pub(crate) fn new() -> Self {
        Self {
            next_alloc_block: AtomicBool::new(false),
            alloc_block_after: AtomicU32::new(0),
            next_free_block: AtomicBool::new(false),
            free_block_after: AtomicU32::new(0),
            next_inode_write: AtomicBool::new(false),
            inode_write_after: AtomicU32::new(0),
            next_metadata_write: AtomicBool::new(false),
            metadata_write_after: AtomicU32::new(0),
            next_inode_read: AtomicBool::new(false),
            inode_read_after: AtomicU32::new(0),
            inode_reads: AtomicU32::new(0),
            next_extent_write: AtomicBool::new(false),
            extent_write_after: AtomicU32::new(0),
            next_data_write: AtomicBool::new(false),
            next_quota_info_write: AtomicBool::new(false),
            quota_info_write_after: AtomicU32::new(0),
            next_quota_record_write: AtomicBool::new(false),
            next_quota_qblk_write: AtomicBool::new(false),
            quota_qblk_write_after: AtomicU32::new(0),
            next_quota_mark_dirty: AtomicBool::new(false),
            quota_mark_dirty_after: AtomicU32::new(0),
        }
    }
}

impl Mount {
    /// Hosted-test hook: fail the next block-allocation attempt. # C: O(1)
    pub fn fail_next_alloc_block_for_tests(&self) {
        self.faults.next_alloc_block.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` successful allocation attempts. # C: O(1)
    pub fn fail_alloc_block_after_for_tests(&self, ok_count: u32) {
        self.faults.alloc_block_after.store(ok_count + 1, Ordering::Release);
    }

    /// Hosted-test hook: fail the next block-free attempt. # C: O(1)
    pub fn fail_next_free_block_for_tests(&self) {
        self.faults.next_free_block.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` successful free attempts. # C: O(1)
    pub fn fail_free_block_after_for_tests(&self, ok_count: u32) {
        self.faults.free_block_after.store(ok_count + 1, Ordering::Release);
    }

    /// Hosted-test hook: fail the next inode metadata write. # C: O(1)
    pub fn fail_next_inode_write_for_tests(&self) {
        self.faults.next_inode_write.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` inode metadata writes. # C: O(1)
    pub fn fail_inode_write_after_for_tests(&self, ok_count: u32) {
        self.faults.inode_write_after.store(ok_count + 1, Ordering::Release);
    }

    /// Hosted-test hook: fail the next generic metadata write. # C: O(1)
    pub fn fail_next_metadata_write_for_tests(&self) {
        self.faults.next_metadata_write.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` generic metadata writes. # C: O(1)
    pub fn fail_metadata_write_after_for_tests(&self, ok_count: u32) {
        self.faults.metadata_write_after.store(ok_count + 1, Ordering::Release);
    }

    pub(crate) fn should_fail_metadata_write_for_tests(&self) -> bool {
        if self.faults.next_metadata_write.swap(false, Ordering::AcqRel) { return true; }
        let n = self.faults.metadata_write_after.load(Ordering::Acquire);
        if n == 0 { return false; }
        if n == 1 {
            self.faults.metadata_write_after.store(0, Ordering::Release);
            return true;
        }
        let _ = self.faults.metadata_write_after.compare_exchange(n, n - 1, Ordering::AcqRel, Ordering::Acquire);
        false
    }

    /// Hosted-test hook: fail the next `read_inode` (an inode-table read that
    /// returns `BadChecksum`/`BlockIo` on real hardware). Load-bearing for
    /// "create must not depend on reading back what it just wrote". # C: O(1)
    pub fn fail_next_inode_read_for_tests(&self) {
        self.faults.next_inode_read.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` successful `read_inode`s. # C: O(1)
    pub fn fail_inode_read_after_for_tests(&self, ok_count: u32) {
        self.faults.inode_read_after.store(ok_count + 1, Ordering::Release);
    }

    /// Hosted-test hook: `read_inode` calls since the last reset. Lets a test
    /// assert an op performs ZERO inode-table reads rather than infer it from
    /// which injected fault happened to fire first. # C: O(1)
    pub fn inode_read_count_for_tests(&self) -> u32 {
        self.faults.inode_reads.load(Ordering::Acquire)
    }

    /// Hosted-test hook: zero the `read_inode` counter. # C: O(1)
    pub fn reset_inode_read_count_for_tests(&self) {
        self.faults.inode_reads.store(0, Ordering::Release);
    }

    pub(crate) fn should_fail_inode_read_for_tests(&self) -> bool {
        self.faults.inode_reads.fetch_add(1, Ordering::AcqRel);
        if self.faults.next_inode_read.swap(false, Ordering::AcqRel) { return true; }
        let n = self.faults.inode_read_after.load(Ordering::Acquire);
        if n == 0 { return false; }
        if n == 1 {
            self.faults.inode_read_after.store(0, Ordering::Release);
            return true;
        }
        let _ = self.faults.inode_read_after.compare_exchange(n, n - 1, Ordering::AcqRel, Ordering::Acquire);
        false
    }

    /// Hosted-test hook: fail the next external extent-block write. # C: O(1)
    pub fn fail_next_extent_block_write_for_tests(&self) {
        self.faults.next_extent_write.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` external extent-block writes. # C: O(1)
    pub fn fail_extent_block_write_after_for_tests(&self, ok_count: u32) {
        self.faults.extent_write_after.store(ok_count + 1, Ordering::Release);
    }

    /// Hosted-test hook: fail the next direct byte-range data write. # C: O(1)
    pub fn fail_next_data_write_for_tests(&self) {
        self.faults.next_data_write.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail the next quota-file info write. # C: O(1)
    pub fn fail_next_quota_info_write_for_tests(&self) {
        self.faults.next_quota_info_write.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` quota-info writes. # C: O(1)
    pub fn fail_quota_info_write_after_for_tests(&self, ok_count: u32) {
        self.faults.quota_info_write_after.store(ok_count + 1, Ordering::Release);
    }

    /// Hosted-test hook: fail the next quota-file record write. # C: O(1)
    pub fn fail_next_quota_record_write_for_tests(&self) {
        self.faults.next_quota_record_write.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail the next quota qtree block write. # C: O(1)
    pub fn fail_next_quota_qblk_write_for_tests(&self) {
        self.faults.next_quota_qblk_write.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` quota qtree block writes. # C: O(1)
    pub fn fail_quota_qblk_write_after_for_tests(&self, ok_count: u32) {
        self.faults.quota_qblk_write_after.store(ok_count + 1, Ordering::Release);
    }

    /// Hosted-test hook: fail the next quota mark-dirty operation. # C: O(1)
    pub fn fail_next_quota_mark_dirty_for_tests(&self) {
        self.faults.next_quota_mark_dirty.store(true, Ordering::Release);
    }

    /// Hosted-test hook: fail after `ok_count` quota mark-dirty operations. # C: O(1)
    pub fn fail_quota_mark_dirty_after_for_tests(&self, ok_count: u32) {
        self.faults.quota_mark_dirty_after.store(ok_count + 1, Ordering::Release);
    }
}

impl Mount {
    /// Hosted-test hook: charge every later allocation on this mount to the
    /// named credentials instead of the kernel's own. # C: O(len(gids))
    pub fn set_alloc_cred_for_tests(&self, uid: u32, gids: &[u32], cap_sys_resource: bool) {
        *self.test_cred.lock() = Some(crate::balloc::reserve::AllocCred {
            uid, gids: gids.to_vec(), cap_sys_resource,
        });
    }
}
