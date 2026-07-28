// 279 move_pages — `SYSCALL_DEFINE6(move_pages)` / `kernel_move_pages`
// (`mm/migrate.c:2592`), `do_pages_move` (`:2347`), `do_pages_stat` (`:2508`).
// ABI shim (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::errno::Errno;
use syscall::SyscallArgs;
use vmm::mempolicy::args::{move_pages_flags, move_pages_target_node, MovePagesNodeErr};
use vmm::mempolicy::scan::vma_migratable;
use vmm::mempolicy::uapi::NODE_ID_LOCAL;
use vmm::AddressSpace;

use crate::misc::mempolicy_common::{cap_sys_nice, err, errno_of, find_mm_struct, page_present_in};

/// `store_status(status, i, value, 1)`. # C: O(1)
fn store_status(status: u64, i: u64, value: i32) -> Result<(), i64> {
    if status == 0 { return Ok(()); }
    let at = status.checked_add(i.checked_mul(4).ok_or(err(Errno::Efault))?)
        .ok_or(err(Errno::Efault))?;
    uaccess::copy_to_user(at, &value.to_ne_bytes()).map_err(|_| err(Errno::Efault))
}

/// `add_folio_for_migration` (`mm/migrate.c:2281`) reduced to the single-node
/// case: a page already on the destination node returns 0 ("nothing to do"),
/// which `do_pages_move` then stores as the node id.
/// # C: O(log N_vmas + walk depth)
fn page_status(mm: &AddressSpace, vmas: &[vmm::Vma], addr: u64) -> i32 {
    let vma = vmas.iter().find(|v| addr >= v.start.as_u64() && addr < v.end.as_u64());
    match vma {
        // `vma_lookup` miss, or a VM_IO/VM_PFNMAP mapping: -EFAULT.
        None => -(Errno::Efault.as_i32()),
        Some(v) if !vma_migratable(v) => -(Errno::Efault.as_i32()),
        Some(_) => {
            let page = addr & !(hal::PAGE_SIZE_BYTES - 1);
            // `folio_walk_start` finding nothing is -ENOENT: the address is
            // mapped but has no page yet.
            if !page_present_in(mm, page) { -(Errno::Enoent.as_i32()) }
            else { NODE_ID_LOCAL as i32 }
        }
    }
}

/// `move_pages(pid, nr_pages, pages, nodes, status, flags)`.
///
/// `nodes == NULL` is the query form (`do_pages_stat`) — it reports which node
/// each page is on, or a negative errno per page. `nodes != NULL` is the move
/// form (`do_pages_move`), where a bad target node aborts the WHOLE syscall
/// with ENODEV/EACCES while a per-page lookup failure lands in `status`.
///
/// Every legal destination is the node the page already occupies, so the move
/// form stores node 0 for each resident page and migrates nothing.
/// # C: O(nr_pages * (log N_vmas + walk depth))
pub fn sys_move_pages(args: &SyscallArgs) -> i64 {
    let (pid, nr_pages, pages) = (args.a0 as u32, args.a1, args.a2);
    let (nodes, status, flags) = (args.a3, args.a4, args.a5 & 0xffff_ffff);
    if let Err(e) = move_pages_flags(flags, cap_sys_nice()) { return errno_of(e); }
    let mm = match find_mm_struct(pid) { Ok(m) => m, Err(rv) => return rv };
    // One snapshot for the whole array: `do_pages_stat` holds mmap_read_lock
    // across each 16-entry chunk rather than re-taking it per page.
    let vmas = mm.snapshot_vmas();
    for i in 0..nr_pages {
        let Some(off) = i.checked_mul(8) else { return err(Errno::Efault) };
        let Some(at) = pages.checked_add(off) else { return err(Errno::Efault) };
        let mut buf = [0u8; 8];
        if uaccess::copy_from_user(&mut buf, at).is_err() { return err(Errno::Efault); }
        let addr = u64::from_ne_bytes(buf);
        if nodes != 0 {
            let Some(noff) = i.checked_mul(4) else { return err(Errno::Efault) };
            let Some(nat) = nodes.checked_add(noff) else { return err(Errno::Efault) };
            let mut nbuf = [0u8; 4];
            if uaccess::copy_from_user(&mut nbuf, nat).is_err() { return err(Errno::Efault); }
            match move_pages_target_node(i32::from_ne_bytes(nbuf)) {
                Ok(_) => {}
                Err(MovePagesNodeErr::NoDev) => return err(Errno::Enodev),
                Err(MovePagesNodeErr::Access) => return err(Errno::Eacces),
            }
        }
        if let Err(rv) = store_status(status, i, page_status(&mm, &vmas, addr)) { return rv; }
    }
    0
}
