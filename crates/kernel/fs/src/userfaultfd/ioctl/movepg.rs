// UFFDIO_MOVE: relocate pages from one anonymous mapping to another inside the
// address space the fd owns.

use alloc::sync::Arc;
use hal::UserVirtAddr;
use syscall::errno::Errno;

use crate::userbuf::validate_user_buf_writable;
use crate::userfaultfd::policy::{self, MoveVma};
use crate::userfaultfd::{uapi::*, work, UfData};
use vmm::address_space::uffd::UffdVma;

use super::structs::{ctx_is, err, read_req, write_reply, UffdioMove};

/// A cross-address-space move is refused outright: the source pages would have
/// to be re-parented into another address space's reverse mappings, and the
/// caller's right to the source is a different question from the fd's right to
/// the destination. Same-address-space only keeps both answers to one.
/// # C: O(N_vmas) + O(len/PAGE)
pub fn ioc_move(ufd: &Arc<UfData>, arg: u64) -> i64 {
    if let Err(rv) = validate_user_buf_writable(arg, UFFDIO_MOVE_SIZE, 1) { return rv; }
    // SAFETY: arg validated writable for the full uffdio_move object.
    let m: UffdioMove = unsafe { read_req(arg) };
    let Some(mm) = ufd.mm() else { return err(Errno::Esrch) };
    if !caller_owns(&mm) { return err(Errno::Einval); }
    if let Err(e) = policy::validate_range(m.dst, m.len) { return err(e); }
    if let Err(e) = policy::validate_range(m.src, m.len) { return err(e); }
    let mode = match policy::check_move_mode(m.mode) { Ok(x) => x, Err(e) => return err(e) };
    let Some(dst_vma) = UserVirtAddr::new(m.dst).and_then(|v| mm.uffd_vma_at(v))
        else { return err(Errno::Enoent) };
    let Some(src_vma) = UserVirtAddr::new(m.src).and_then(|v| mm.uffd_vma_at(v))
        else { return err(Errno::Enoent) };
    let (src, dst) = (facts(&src_vma, ufd), facts(&dst_vma, ufd));
    if let Err(e) = policy::check_move_ranges(m.dst, m.src, m.len, &src, &dst) { return err(e); }
    if let Err(e) = policy::check_move_areas(&src, &dst) { return err(e); }
    let (moved, fail) = work::move_pages(&mm, m.dst, m.src, m.len, mode.allow_src_holes,
                                         &dst_vma, &src_vma);
    let (rv, count) = policy::fill_retval(moved, m.len, fail);
    write_reply(arg + UFFDIO_MOVE_MOVE_OFF, count);
    if moved != 0 && !mode.dontwake { ufd.wake_faulters(); }
    rv
}

/// Whether the caller is running in the address space the fd owns. With no
/// running task there is no other address space the request could have come
/// from, so the question does not arise.
/// # C: O(1)
fn caller_owns(mm: &Arc<vmm::AddressSpace>) -> bool {
    let Some(cur) = sched::current() else { return true };
    // SAFETY: running task on this CPU; preempt-off; single-mutator mm slot per 13§5; the comparison only reads the pointer.
    let Some(cur_mm) = (unsafe { cur.mm_ref() }) else { return false };
    Arc::ptr_eq(cur_mm, mm)
}

/// # C: O(1)
fn facts(v: &UffdVma, ufd: &Arc<UfData>) -> MoveVma {
    MoveVma {
        start: v.start,
        end: v.end,
        prot: v.prot.bits(),
        write: v.write,
        shared: v.shared,
        locked: v.locked,
        anonymous: v.anonymous,
        registered_by_this_ctx: v.ctx.as_ref().is_some_and(|c| ctx_is(c, ufd)),
    }
}
