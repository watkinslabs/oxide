use super::core::{FUTEX_BITSET_MATCH_ANY, cmpxchg_user_u32, current_key, load_user_u32,
                  user_addr_accessible, wake_key};
use crate::robust_decode::{DeathAction, DeathSite, RobustPtr, death_verdict};

/// Robust-futex bits (`include/uapi/linux/futex.h:200-205`). glibc stores the
/// owner's TID in the low 30 bits of a robust mutex word; the kernel ORs
/// OWNER_DIED on owner death.
const FUTEX_WAITERS: u32 = 0x8000_0000;
const FUTEX_OWNER_DIED: u32 = 0x4000_0000;
const FUTEX_TID_MASK: u32 = 0x3fff_ffff;
const ROBUST_LIST_LIMIT: usize = 2048;
/// Linux retries the OWNER_DIED cmpxchg via `goto retry` with NO bound
/// (`kernel/futex/core.c:1069-1070`). It converges in practice because each
/// pass re-reads the word and either the owner check stops matching or
/// OWNER_DIED lands, and the racing writer is userspace code for a thread that
/// is already dying.
///
/// This bound is a DELIBERATE divergence: an unbounded loop here runs on the
/// task-exit path, where spinning forever on a hostile or wedged userspace
/// word would leave the exiting task un-reaped and its remaining robust
/// mutexes unprocessed. On exhaustion this entry is SKIPPED and the walk
/// CONTINUES — never aborted — so at worst one mutex keeps a dead owner while
/// every other entry on the list is still recovered. Aborting instead (the
/// first version of this) would have stranded every remaining waiter, which is
/// strictly worse than what Linux risks.
const CMPXCHG_RETRY_LIMIT: usize = 16;

/// Offsets in `struct robust_list_head` (`include/uapi/linux/futex.h:212-231`).
const HEAD_LIST_NEXT: u64 = 0;
const HEAD_FUTEX_OFFSET: u64 = 8;
const HEAD_LIST_OP_PENDING: u64 = 16;

/// Linux `exit_robust_list` (`kernel/futex/core.c:1108-1167`): on thread death,
/// walk the user `robust_list_head` this thread registered via
/// `set_robust_list` and, for every robust mutex it still owns, mark
/// FUTEX_OWNER_DIED and wake one waiter so a peer blocked on that mutex can
/// recover (glibc's mutex lock returns EOWNERDEAD). Without this, a thread that
/// dies holding a robust mutex strands every waiter forever.
///
/// `owner_tid` is the dying thread's userspace TID (== gettid, the value glibc
/// wrote into the word). Runs in the dying task's address space (CR3 live).
/// # SAFETY: caller is the exit/fault path with the dying task's mm active.
/// # C: O(min(list_len, ROBUST_LIST_LIMIT))
pub fn exit_robust_list(head_uaddr: u64, owner_tid: u32) {
    if head_uaddr == 0 || head_uaddr >= hal::USER_VA_END || (head_uaddr & 0x7) != 0 { return; }
    let Some(entry) = fetch_robust_entry(head_uaddr + HEAD_LIST_NEXT) else { return };
    let Some(futex_offset) = read_user_u64(head_uaddr + HEAD_FUTEX_OFFSET) else { return };
    let futex_offset = futex_offset as i64;
    let Some(pending) = fetch_robust_entry(head_uaddr + HEAD_LIST_OP_PENDING) else { return };

    let mut cur = entry;
    let mut limit = ROBUST_LIST_LIMIT;
    while cur.addr != head_uaddr && limit > 0 {
        // Linux fetches the NEXT entry BEFORE calling `handle_futex_death`
        // (`core.c:1136-1140`) — the handler can fault or userspace can recycle
        // the entry, so the link must be captured first.
        let next = fetch_robust_entry(cur.addr);
        if cur.addr != pending.addr {
            let uaddr = (cur.addr as i64).wrapping_add(futex_offset) as u64;
            // A failed handler aborts the walk (`core.c:1146-1148`).
            if handle_futex_death(uaddr, owner_tid, cur.pi(), DeathSite::List).is_err() { return; }
        }
        // `core.c:1150-1151`: the deferred fetch error is only acted on after
        // the current entry has been handled.
        let Some(next) = next else { return };
        cur = next;
        limit -= 1;
    }
    if pending.addr != 0 {
        let uaddr = (pending.addr as i64).wrapping_add(futex_offset) as u64;
        let _ = handle_futex_death(uaddr, owner_tid, pending.pi(), DeathSite::Pending);
    }
}

/// Linux `fetch_robust_entry` (`kernel/futex/core.c:1085-1099`): read a
/// `robust_list` pointer and split bit 0 off it. Bit 0 is
/// `FUTEX_ROBUST_MOD_PI`, the tag glibc sets on a PI robust mutex. The previous
/// code demanded every fetched pointer be 8-aligned and bailed otherwise, so a
/// single PI-tagged entry ABORTED THE WHOLE WALK and every robust mutex after
/// it stayed owned by a dead thread.
/// # C: O(1)
fn fetch_robust_entry(at: u64) -> Option<RobustPtr> {
    read_user_u64(at).map(RobustPtr::decode)
}

/// Fault-safe user u64 read. Linux's `get_user` returns -EFAULT and aborts the
/// walk rather than faulting the kernel; a crashing task's list memory may be
/// unmapped, so verify presence under the active AS first.
/// # C: O(1)
fn read_user_u64(va: u64) -> Option<u64> {
    if va == 0 || va >= hal::USER_VA_END || (va & 0x7) != 0 { return None; }
    if !user_addr_accessible(va, false) { return None; }
    // SAFETY: page verified present under the active CR3/TTBR0 by
    // user_addr_accessible; bounded, 8-aligned user VA in the dying task's live
    // address space.
    Some(unsafe { core::ptr::read_volatile(va as *const u64) })
}

/// Recover one robust mutex owned by a dying thread — Linux
/// `handle_futex_death` (`kernel/futex/core.c:968-1082`). `Err` aborts the
/// caller's walk, matching Linux's `return -1`.
/// # C: O(W) waiters on wake
fn handle_futex_death(futex_uaddr: u64, owner_tid: u32, pi: bool, site: DeathSite)
    -> Result<(), ()>
{
    // "Futex address must be 32bit aligned" (`core.c:976-978`).
    if futex_uaddr == 0 || futex_uaddr >= hal::USER_VA_END || (futex_uaddr & 0x3) != 0 {
        return Err(());
    }
    let mut tries = 0usize;
    loop {
        if !user_addr_accessible(futex_uaddr, false) { return Err(()); }
        // SAFETY: page verified present by user_addr_accessible; bounded,
        // 4-aligned user word in the dying task's live address space.
        let uval = unsafe { load_user_u32(futex_uaddr) };
        match death_verdict(uval & FUTEX_TID_MASK, owner_tid, pi, site) {
            // `core.c:1022-1026`: a REGULAR futex reached via list_op_pending
            // whose owner field is already zero. Wake a potential waiter
            // WITHOUT touching the word — setting OWNER_DIED here would create
            // inconsistent state for userspace's owner-died handling.
            DeathAction::WakeOnly => { wake_one(futex_uaddr); return Ok(()); }
            // `core.c:1029-1030`: not ours — skip, but keep walking.
            DeathAction::Skip => return Ok(()),
            DeathAction::SetOwnerDied => {}
        }
        if uval & FUTEX_OWNER_DIED != 0 {
            // Already flagged. Linux still re-wakes for the "rare but possible
            // case of recursive thread-death" (`core.c:1035-1039`), but the
            // word already holds the value the cmpxchg would write.
            if !pi && uval & FUTEX_WAITERS != 0 { wake_one(futex_uaddr); }
            return Ok(());
        }
        // `core.c:1042`: mval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED.
        let mval = (uval & FUTEX_WAITERS) | FUTEX_OWNER_DIED;
        if !user_addr_accessible(futex_uaddr, true) { return Err(()); }
        // `futex_cmpxchg_value_locked` (`core.c:1052`). The previous code did a
        // plain load-then-store, which silently dropped a concurrent userspace
        // unlock; Linux loops on `if (nval != uval) goto retry` precisely
        // because that word is live.
        // SAFETY: page verified present+writable by user_addr_accessible; a
        // single naturally-aligned RMW on the same 4-aligned user word under
        // the active CR3/TTBR0.
        let nval = unsafe { cmpxchg_user_u32(futex_uaddr, uval, mval) };
        if nval == uval {
            // `core.c:1074-1077`: "Wake robust non-PI futexes here. The wakeup
            // of PI futexes happens in exit_pi_state()." Waking a PI waiter
            // here would bypass the ownership handoff.
            if !pi && uval & FUTEX_WAITERS != 0 { wake_one(futex_uaddr); }
            return Ok(());
        }
        // `core.c:1069-1070`: userspace moved the word under us — re-read.
        tries += 1;
        // Exhaustion skips THIS entry and lets the caller keep walking; see
        // CMPXCHG_RETRY_LIMIT. `Err` here would abort the whole list.
        if tries >= CMPXCHG_RETRY_LIMIT { return Ok(()); }
    }
}

/// Linux's `futex_wake(uaddr, ..., 1, FUTEX_BITSET_MATCH_ANY)`. Both key
/// flavours are tried because the robust word may be private or shared and the
/// dying task no longer tells us which.
/// # C: O(W)
fn wake_one(futex_uaddr: u64) {
    if let Some(k) = current_key(futex_uaddr, true) { wake_key(k, 1, FUTEX_BITSET_MATCH_ANY); }
    if let Some(k) = current_key(futex_uaddr, false) { wake_key(k, 1, FUTEX_BITSET_MATCH_ANY); }
}
