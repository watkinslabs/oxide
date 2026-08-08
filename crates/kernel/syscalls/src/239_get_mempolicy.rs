// 239 get_mempolicy — `SYSCALL_DEFINE5(get_mempolicy)` / `kernel_get_mempolicy`
// + `do_get_mempolicy` (`:1147`). ABI shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use vmm::mempolicy::uapi::{NODE_ID_LOCAL, NR_NODE_IDS};
use vmm::mempolicy::{get_mempolicy_kind, report_policy, GetPolicyKind};

use crate::misc::mempolicy_common::{current_mm, err, errno_of, page_present, write_nodemask};

/// `get_mempolicy(policy, nmask, maxnode, addr, flags)`.
///
/// `nmask != NULL && maxnode < nr_node_ids` is EINVAL BEFORE any policy
/// lookup — libnuma relies on that to size its
/// buffers.
/// # C: O(maxnode / 8)
pub fn sys_get_mempolicy(args: &SyscallArgs) -> i64 {
    let (policy_p, nmask, maxnode, addr, flags) = (args.a0, args.a1, args.a2, args.a3, args.a4);
    if nmask != 0 && maxnode < NR_NODE_IDS { return err(Errno::Einval); }
    let kind = match get_mempolicy_kind(flags, addr) { Ok(k) => k, Err(e) => return errno_of(e) };
    let (pol, node_at_addr) = match kind {
        GetPolicyKind::MemsAllowed => (None, None),
        GetPolicyKind::TaskPolicy { .. } => {
            let Some(cur) = sched::live::current() else { return err(Errno::Einval) };
            (cur.mempolicy(), None)
        }
        GetPolicyKind::VmaPolicy { node } => {
            let Some(mm) = current_mm() else { return err(Errno::Einval) };
            // `vma_lookup(mm, addr)` failing is EFAULT, not ENOMEM.
            let p = match mm.vma_policy_at(addr) { Ok(p) => p, Err(()) => return err(Errno::Efault) };
            // `lookup_node()` = `get_user_pages_fast(addr, 1, 0, &p)`, which
            // needs VM_READ and faults the page in; then `page_to_nid`.
            let n = if node {
                // `check_vma_flags` refuses a range without VM_READ.
                if !mm.gup_read_permitted(addr, crate::pkey::rights_allow) { return err(Errno::Efault); }
                let page = addr & !(hal::PAGE_SIZE_BYTES - 1);
                if !page_present(page) {
                    // gup POPULATES the page; a range that cannot be
                    // populated is EFAULT. Doing the same keeps the side
                    // effect Linux has, so a subsequent mincore(2) agrees.
                    let Some(uva) = hal::UserVirtAddr::new(page) else { return err(Errno::Efault) };
                    if pmm::user_as::populate_current_range(uva, hal::PAGE_SIZE_BYTES as usize,
                                                   vmm::VmaProt::READ).is_err() {
                        return err(Errno::Efault);
                    }
                }
                Some(NODE_ID_LOCAL)
            } else { None };
            (p, n)
        }
    };
    let rep = match report_policy(kind, pol, node_at_addr) { Ok(r) => r, Err(e) => return errno_of(e) };
    // `put_user(pval, policy)` happens before the nodemask copy, so a bad
    // `policy` pointer wins over a bad `nmask` pointer.
    if policy_p != 0 {
        if uaccess::copy_to_user(policy_p, &rep.policy.to_ne_bytes()).is_err() {
            return err(Errno::Efault);
        }
    }
    if nmask != 0 {
        if let Err(rv) = write_nodemask(nmask, maxnode, rep.nodes) { return rv; }
    }
    0
}
