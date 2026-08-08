// The completion a released tagged resource posts.
//
// A slot registered with a non-zero tag posts a completion carrying that tag
// the moment the kernel is finished with what was in it — an update that
// replaced it, or an unregister that dropped it. Without that notification a
// caller cannot know when it is safe to reuse the buffer it lent the kernel,
// which is the whole point of tagging.

use crate::io_uring::cqe::Cqe;
use crate::io_uring::ctx::IoUringInode;

/// Post the release notification for one tag. A zero tag is "untagged" and
/// notifies nothing. # C: O(1)
pub fn release(inode: &IoUringInode, tag: u64) {
    if tag == 0 { return; }
    inode.post_cqe(Cqe::new(tag, 0));
}
