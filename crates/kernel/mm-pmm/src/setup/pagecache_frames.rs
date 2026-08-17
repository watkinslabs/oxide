// Naming this allocator to the page cache, so a cached page can BE a machine
// frame a user page table points at.
//
// The direction is forced by the dependency graph: the block layer, which owns
// the page cache, is BELOW this crate — a swap area is a block device — so the
// page cache cannot call the frame allocator directly and the allocator has to
// introduce itself on the way up. That is the same inversion the machine's
// managed-page count already goes through, and for the same reason.
//
// What a cached page's frame is, in lifetime terms: an OBJECT frame. The cache
// holds one reference for as long as the page is resident; every user PTE the
// fault path installs over it adds its own through `inc_ref`, which bumps the
// mapcount too. So a page dropped from the cache while userspace still maps it
// is not freed — the mapper's reference outlives the cache's — and the frame
// returns to the buddy only once the last of them is gone. That is what makes a
// cached page safe to hand out and is exactly the contract an unrefcounted
// device-memory mapping does NOT have.

use block::pagecache::FrameProvider;

use super::frame_alloc::{alloc_object_frame, frame_ptr};
use super::metadata::frame_mapcount;
use super::refs::dec_object_ref_and_maybe_free_frame;

/// # Safety: `pa` is a frame the page cache took from `alloc_object_frame` and
/// holds the object reference for.
unsafe fn release(pa: u64) { dec_object_ref_and_maybe_free_frame(pa); }

/// # C: O(1)
fn mapped(pa: u64) -> bool { frame_mapcount(pa) > 0 }

static PROVIDER: FrameProvider = FrameProvider {
    alloc: alloc_object_frame,
    ptr: frame_ptr,
    release,
    mapped,
};

/// Let the page cache turn a cached page into a mappable frame.
///
/// Until this runs, a cached page is a heap buffer and a shared writable mapping
/// of a file cached there cannot be satisfied — which is the correct answer
/// before there is an allocator, and the wrong one afterwards.
/// # C: O(1)
pub fn install_page_cache_frames() { block::pagecache::install_frame_provider(&PROVIDER); }
