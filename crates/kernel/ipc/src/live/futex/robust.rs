use super::core::{FUTEX_BITSET_MATCH_ANY, current_key, load_user_u32, store_user_u32, user_addr_accessible, wake_key};

/// Robust-futex bits (linux/futex.h). glibc stores the owner's TID in the low
/// 30 bits of a robust mutex word; the kernel ORs OWNER_DIED on owner death.
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const ROBUST_LIST_LIMIT: usize = 2048;

/// Linux `exit_robust_list` (kernel/futex): on thread death, walk the user
/// `robust_list_head` this thread registered via set_robust_list and, for every
/// robust mutex it still owns, mark FUTEX_OWNER_DIED and wake one waiter so a
/// peer blocked on that mutex can recover (glibc's mutex lock returns
/// EOWNERDEAD). Without this, a thread that dies — crash or normal exit —
/// holding a robust mutex strands every waiter forever (the boot wedge: init
/// parks in waitid while a service hangs on a dead owner's lock).
///
/// `owner_tid` is the dying thread's userspace TID (== gettid, the value glibc
/// wrote into the word). Runs in the dying task's address space (CR3 live).
/// # SAFETY: caller is the exit/fault path with the dying task's mm active.
/// # C: O(min(list_len, ROBUST_LIST_LIMIT))
pub fn exit_robust_list(head_uaddr: u64, owner_tid: u32) {
    if head_uaddr == 0 || head_uaddr >= hal::USER_VA_END || (head_uaddr & 0x7) != 0 { return; }
    let rd = |va: u64| -> Option<u64> {
        if va == 0 || va >= hal::USER_VA_END || (va & 0x7) != 0 { return None; }
        // Fault-safe: a crashing task's list memory may be unmapped; a raw read
        // of an unmapped user VA here would #PF the kernel. Verify the page is
        // present under the active AS first (Linux `get_user` returns -EFAULT,
        // aborting the walk, rather than faulting the kernel).
        if !user_addr_accessible(va, false) { return None; }
        // SAFETY: page verified present under the active CR3/TTBR0 by user_addr_accessible; bounded, 8-aligned user VA in the dying task's live address space.
        Some(unsafe { core::ptr::read_volatile(va as *const u64) })
    };
    let futex_offset = match rd(head_uaddr + 8) { Some(v) => v as i64, None => return };
    let pending = rd(head_uaddr + 16).unwrap_or(0);
    let mut entry = match rd(head_uaddr) { Some(v) => v, None => return };
    let mut n = 0usize;
    while entry != head_uaddr && n < ROBUST_LIST_LIMIT {
        if entry != pending {
            handle_futex_death((entry as i64).wrapping_add(futex_offset) as u64, owner_tid);
        }
        entry = match rd(entry) { Some(v) => v, None => break };
        n += 1;
    }
    if pending != 0 {
        handle_futex_death((pending as i64).wrapping_add(futex_offset) as u64, owner_tid);
    }
}

/// Recover one robust mutex owned by a dying thread (Linux `handle_futex_death`).
/// # C: O(W) waiters on wake
fn handle_futex_death(futex_uaddr: u64, owner_tid: u32) {
    if futex_uaddr == 0 || futex_uaddr >= hal::USER_VA_END || (futex_uaddr & 0x3) != 0 { return; }
    // Fault-safe read guard (see `exit_robust_list`): abort if the mutex word's
    // page is not present under the active AS rather than #PF the kernel.
    if !user_addr_accessible(futex_uaddr, false) { return; }
    // SAFETY: page verified present by user_addr_accessible; bounded, 4-aligned user word in the dying task's live address space.
    let val = unsafe { load_user_u32(futex_uaddr) };
    if (val & FUTEX_TID_MASK) != owner_tid || (val & FUTEX_OWNER_DIED) != 0 { return; }
    // Store guard: require the page present AND user-writable, else a read-only
    // or corrupt mapping would #PF the kernel on the CPL=0 write below.
    if !user_addr_accessible(futex_uaddr, true) { return; }
    let newval = (val & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
    // SAFETY: page verified present+writable by user_addr_accessible; same 4-aligned user word, CPL=0 store through the active CR3/TTBR0.
    unsafe { store_user_u32(futex_uaddr, newval); }
    if val & FUTEX_WAITERS != 0 {
        if let Some(k) = current_key(futex_uaddr, true) { wake_key(k, 1, FUTEX_BITSET_MATCH_ANY); }
        if let Some(k) = current_key(futex_uaddr, false) { wake_key(k, 1, FUTEX_BITSET_MATCH_ANY); }
    }
}
