// `shmget(SHM_HUGETLB)`: which granule the flag word names, how large the
// backing file has to be, and who is allowed to ask for one.
//
// A huge segment is not ordinary shared memory with a bigger page: it is a
// file on the kernel-private hugetlbfs mount, and every property below follows
// from that. Nothing here is target-gated — the decisions are the part worth
// testing, and the ABI shim only turns the answer into a file.

use core::sync::atomic::{AtomicI32, Ordering};

use pmm::hugetlb::{self, HugePageSize};
use syscall::errno::Errno;

use super::{in_group, IpcCred};

/// `shmget` flag bit selecting huge-page backing.
pub const SHM_HUGETLB: u64 = 0o4000;

/// The group whose members may create huge-page segments without
/// `CAP_IPC_LOCK`. Group 0 by default, which is what a kernel that has never
/// been told otherwise offers.
static SHM_GROUP: AtomicI32 = AtomicI32::new(0);

/// `vm.hugetlb_shm_group` read side. # C: O(1)
pub fn hugetlb_shm_group() -> i64 { SHM_GROUP.load(Ordering::Acquire) as i64 }

/// `vm.hugetlb_shm_group` write side. The leaf is a plain integer with no
/// window of its own, so a value naming no group simply matches nobody.
/// # C: O(1)
pub fn set_hugetlb_shm_group(v: i64) { SHM_GROUP.store(v as i32, Ordering::Release); }

/// Whether this caller may build a huge-page segment.
///
/// Two independent grants, either of which suffices: the capability that
/// governs pinning memory, or membership of the configured group. The group
/// exists precisely so an administrator can hand out huge-page shared memory
/// without handing out the capability.
///
/// A negative group value names no group at all and therefore grants nothing —
/// a gid is unsigned, so there is no group whose id could match it.
/// # C: O(log N_groups)
pub fn can_do_hugetlb_shm(cred: &IpcCred) -> bool {
    if cred.cap_ipc_lock { return true; }
    let g = hugetlb_shm_group();
    g >= 0 && in_group(cred, g as u32)
}

/// A resolved huge-page segment request.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct HugeSeg {
    /// Size-log the backing file is built at; 0 selects the default granule.
    pub log: u32,
    /// Granule the selector resolved to.
    pub size: HugePageSize,
    /// Bytes the backing file must hold — the requested size rounded up to
    /// whole huge pages.
    pub bytes: u64,
}

/// Resolve a `shmget` flag word and size into a huge-page request.
///
/// `Ok(None)` is an ordinary shared-memory segment. A selector naming a
/// granule this kernel has no pool for is refused rather than quietly served
/// at another size, because a program that asked for 1 GiB pages and was given
/// 2 MiB ones has been handed something it did not ask for.
///
/// The size rounds UP to whole huge pages: the file is made of whole pages, so
/// a size stopping inside one would leave the tail of a page belonging to a
/// segment that does not cover it. A size so large that rounding it cannot be
/// represented is refused as an allocation failure rather than wrapped to a
/// smaller segment than the caller asked for.
/// # C: O(1)
pub fn huge_plan(flg: u64, size: usize) -> Result<Option<HugeSeg>, Errno> {
    if flg & SHM_HUGETLB == 0 { return Ok(None); }
    let log = hugetlb::size_log_from_flags(flg);
    let hs = hugetlb::size_from_log(log).ok_or(Errno::Einval)?;
    let hb = hs.bytes();
    let bytes = (size as u64).checked_add(hb - 1).ok_or(Errno::Enomem)? & !(hb - 1);
    Ok(Some(HugeSeg { log, size: hs, bytes }))
}

/// Byte size of the page a segment's backing is made of. A hugetlbfs file
/// answers with its granule; ordinary shared memory with the base page.
///
/// The backing is the only place this is recorded — the segment keeps no
/// second copy that could disagree with the file it is built on.
/// # C: O(1)
pub fn seg_page_size(backing: &alloc::sync::Arc<dyn vmm::FileBacking>) -> u64 {
    let huge = backing.huge_page_size();
    if huge != 0 { huge } else { super::PAGE_SIZE }
}

/// Round `size` up to whole `page`-sized pages. `None` on overflow.
/// # C: O(1)
pub fn span_of(size: usize, page: u64) -> Option<usize> {
    (size as u64).checked_add(page - 1).map(|v| (v & !(page - 1)) as usize)
}

#[cfg(test)]
mod tests {
    use super::*;
    use pmm::hugetlb::HUGE_FLAG_ENCODE_SHIFT as SHM_HUGE_SHIFT;

    const M2: u64 = 2 * 1024 * 1024;
    const G1: u64 = 1024 * 1024 * 1024;
    const HUGE_2MB: u64 = 21 << SHM_HUGE_SHIFT;
    const HUGE_1GB: u64 = 30 << SHM_HUGE_SHIFT;

    fn cred(egid: u32, groups: &[u32], cap_ipc_lock: bool) -> IpcCred {
        IpcCred {
            euid: 1000, egid,
            groups: vfs::GroupList::from_slice(groups),
            cap_ipc_owner: false, cap_ipc_lock,
            cap_sys_admin: false, cap_sys_resource: false,
        }
    }

    #[test]
    fn a_request_without_the_huge_flag_is_ordinary_shared_memory() {
        assert_eq!(huge_plan(0o1000 | 0o600, 4096), Ok(None));
        assert_eq!(huge_plan(HUGE_1GB, 4096), Ok(None));
    }

    #[test]
    fn no_selector_names_the_default_granule() {
        let p = huge_plan(SHM_HUGETLB, 1).unwrap().unwrap();
        assert_eq!(p.log, 0);
        assert_eq!(p.size, HugePageSize::Huge2M);
        assert_eq!(p.bytes, M2);
    }

    #[test]
    fn each_selector_names_its_own_granule() {
        assert_eq!(huge_plan(SHM_HUGETLB | HUGE_2MB, 1).unwrap().unwrap().size, HugePageSize::Huge2M);
        assert_eq!(huge_plan(SHM_HUGETLB | HUGE_1GB, 1).unwrap().unwrap().size, HugePageSize::Huge1G);
    }

    #[test]
    fn an_invalid_selector_is_einval_not_a_downgrade() {
        assert_eq!(huge_plan(SHM_HUGETLB | (16u64 << SHM_HUGE_SHIFT), 4096), Err(Errno::Einval));
        assert_eq!(huge_plan(SHM_HUGETLB | (63u64 << SHM_HUGE_SHIFT), 4096), Err(Errno::Einval));
    }

    #[test]
    fn the_size_rounds_up_to_whole_huge_pages() {
        assert_eq!(huge_plan(SHM_HUGETLB, M2 as usize).unwrap().unwrap().bytes, M2);
        assert_eq!(huge_plan(SHM_HUGETLB, M2 as usize + 1).unwrap().unwrap().bytes, 2 * M2);
        assert_eq!(huge_plan(SHM_HUGETLB | HUGE_1GB, 1).unwrap().unwrap().bytes, G1);
    }

    #[test]
    fn a_size_that_cannot_be_rounded_is_refused_rather_than_wrapped() {
        assert_eq!(huge_plan(SHM_HUGETLB, usize::MAX), Err(Errno::Enomem));
        assert_eq!(huge_plan(SHM_HUGETLB | HUGE_1GB, usize::MAX - 3), Err(Errno::Enomem));
    }

    #[test]
    fn the_capability_alone_grants_a_huge_segment() {
        let _shm = crate::sysv_shm::test_claim::claim_shm();
        assert!(can_do_hugetlb_shm(&cred(4242, &[], true)));
    }

    #[test]
    fn group_membership_alone_grants_a_huge_segment() {
        let _shm = crate::sysv_shm::test_claim::claim_shm();
        set_hugetlb_shm_group(77);
        assert!(can_do_hugetlb_shm(&cred(77, &[], false)), "effective gid counts");
        assert!(can_do_hugetlb_shm(&cred(4242, &[5, 77], false)), "a supplementary group counts");
        assert!(!can_do_hugetlb_shm(&cred(4242, &[5, 78], false)));
    }

    #[test]
    fn a_group_naming_nobody_grants_nothing() {
        let _shm = crate::sysv_shm::test_claim::claim_shm();
        set_hugetlb_shm_group(-1);
        assert!(!can_do_hugetlb_shm(&cred(0, &[0], false)));
        assert!(can_do_hugetlb_shm(&cred(0, &[0], true)), "the capability still grants it");
    }

    #[test]
    fn the_group_leaf_reads_back_what_was_written() {
        let _shm = crate::sysv_shm::test_claim::claim_shm();
        set_hugetlb_shm_group(1234);
        assert_eq!(hugetlb_shm_group(), 1234);
        set_hugetlb_shm_group(0);
        assert_eq!(hugetlb_shm_group(), 0);
    }

    #[test]
    fn a_span_covers_whole_pages_of_the_backing_granule() {
        assert_eq!(span_of(1, super::super::PAGE_SIZE), Some(4096));
        assert_eq!(span_of(1, M2), Some(M2 as usize));
        assert_eq!(span_of(M2 as usize + 1, M2), Some(2 * M2 as usize));
        assert_eq!(span_of(usize::MAX, M2), None);
    }
}
