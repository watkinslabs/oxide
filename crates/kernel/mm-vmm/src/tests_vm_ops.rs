//! Linux `shm_vm_ops.open`/`.close` accounting over the VMA tree.
//!
//! `shm_nattch` counts VMAs. Before F765 it counted `shmat` calls: a fork made
//! a second attachment invisible to `ipcs -m`, and an exit without `shmdt`
//! left the count raised forever, so an `IPC_RMID`ed segment was never
//! reclaimed. The guest differential caught it as
//! `wdiff|sysv_shm|nattch_tracks_fork|forked=1` against Linux's `forked=2`.
//!
//! One test function, deliberately: the callbacks are a process-wide pair
//! (Linux's `vm_ops` table is per-VMA; this kernel installs it once), so two
//! test threads sharing them would race on the counter.

use alloc::sync::Arc;
use core::sync::atomic::{AtomicI64, Ordering};
use hal::UserVirtAddr;

use crate::vma::{FileBacking, FileBackingError, Vma, VmaBacking, VmaFlags, VmaProt};
use crate::tree::VmaTree;

static NATTCH: AtomicI64 = AtomicI64::new(0);

struct Seg;
impl FileBacking for Seg {
    fn read_at(&self, _off: u64, _dst: &mut [u8]) -> Result<usize, FileBackingError> { Ok(0) }
    fn size_hint(&self) -> u64 { PAGE * 3 }
}

fn opened(_b: &Arc<dyn FileBacking>) { NATTCH.fetch_add(1, Ordering::AcqRel); }
fn closed(_b: &Arc<dyn FileBacking>) { NATTCH.fetch_sub(1, Ordering::AcqRel); }

const PAGE: u64 = 4096;
const BASE: u64 = 0x4000_0000;

fn uva(a: u64) -> UserVirtAddr { UserVirtAddr::new(a).expect("test VA") }

fn attach(backing: &Arc<dyn FileBacking>, start: u64, end: u64, shm: bool) -> Vma {
    let mut flags = VmaFlags::SHARED | VmaFlags::ANONYMOUS;
    if shm { flags |= VmaFlags::SYSVSHM; }
    Vma::new(uva(start), uva(end), VmaProt::READ | VmaProt::WRITE, flags,
             VmaBacking::File { backing: Arc::clone(backing), off: start - BASE })
}

fn nattch() -> i64 { NATTCH.load(Ordering::Acquire) }

#[test]
fn shm_nattch_follows_vma_lifetime_not_shmat_calls() {
    crate::vm_ops::set_shm_vm_ops(opened, closed);
    let backing: Arc<dyn FileBacking> = Arc::new(Seg);

    // A mapping that is not a SysV attachment never reaches the callbacks,
    // which is what keeps every ordinary mmap off this path.
    {
        let mut t = VmaTree::new();
        t.insert(attach(&backing, BASE, BASE + 3 * PAGE, false)).expect("insert");
        assert_eq!(nattch(), 0, "only SYSVSHM VMAs run shm_vm_ops");
    }
    assert_eq!(nattch(), 0);

    let mut t = VmaTree::new();
    t.insert(attach(&backing, BASE, BASE + 3 * PAGE, true)).expect("insert");
    assert_eq!(nattch(), 1, "shmat's own mapping is one attachment");

    // Linux `__split_vma`: an mprotect cutting the attachment in two leaves
    // TWO VMAs, and `shm_nattch` reports two. The fragments must be opened
    // before the original closes, or a single-attachment SHM_DEST segment
    // would be destroyed mid-split.
    t.mprotect_range(uva(BASE), uva(BASE + PAGE), VmaProt::READ).expect("mprotect");
    assert_eq!(t.len(), 2);
    assert_eq!(nattch(), 2, "each fragment of a split attachment counts");

    // Re-merging them back (same prot) drops one, exactly as `vma_merge`'s
    // `remove_vma` does.
    t.mprotect_range(uva(BASE), uva(BASE + PAGE), VmaProt::READ | VmaProt::WRITE)
        .expect("mprotect back");
    assert_eq!(t.len(), 1);
    assert_eq!(nattch(), 1, "a merge frees one VMA");

    // A partial munmap keeps one fragment; a full one keeps none.
    t.remove_range(uva(BASE + 2 * PAGE), uva(BASE + 3 * PAGE));
    assert_eq!(nattch(), 1, "the surviving fragment is still an attachment");
    t.remove_range(uva(BASE), uva(BASE + 2 * PAGE));
    assert_eq!(nattch(), 0, "shmdt of the whole attachment");

    // exit_mmap: whatever is still mapped when the address space dies closes.
    // This is the case a process that exits without shmdt hits, and the one
    // that used to leak `shm_nattch` forever.
    t.insert(attach(&backing, BASE, BASE + 3 * PAGE, true)).expect("re-insert");
    assert_eq!(nattch(), 1);
    drop(t);
    assert_eq!(nattch(), 0, "dropping the tree closes every surviving VMA");

    crate::vm_ops::set_shm_vm_ops(noop, noop);
}

fn noop(_b: &Arc<dyn FileBacking>) {}
