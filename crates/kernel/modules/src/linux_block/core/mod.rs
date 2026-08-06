// Module manifest: queue owns request_queue/tag-set lifetime; disk owns gendisk lifetime and the
// block-registry publication; bio owns the BIO facade and vector/page owner; adapter owns the
// BlockDevice bridge that carries registry traffic into a module's make_request_fn.

mod adapter;
mod bio;
mod disk;
mod queue;
#[cfg(test)]
mod tests;

pub(super) use bio::{bio_add_page, bio_alloc, submit_bio, zero_bio};
pub(super) use disk::{add_disk, alloc_disk_node, mark_disk_dead, put_disk};
pub(super) use queue::{blk_alloc_queue, blk_cleanup_queue, default_limits};

/// Register Linux block KPI symbols.
/// # C: O(1)
pub(super) fn export_symbols() {
    queue::export_symbols();
    disk::export_symbols();
    bio::export_symbols();
}
