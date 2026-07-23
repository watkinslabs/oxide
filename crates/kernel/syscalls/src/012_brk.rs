// 012 brk — one syscall, one file (docs/53 §0). Moved verbatim from lib.rs.
#![cfg(target_os = "oxide-kernel")]

use syscall::SyscallArgs;

const PAGE_MASK: u64 = 0xfff;

fn page_align(v: u64) -> Option<u64> {
    v.checked_add(PAGE_MASK).map(|x| x & !PAGE_MASK)
}

fn data_rlimit_ok(mm: &vmm::AddressSpace, req: u64, rlim_data: u64) -> bool {
    if rlim_data == sched::rlimit::INFINITY { return true; }
    let start_brk = mm.start_brk();
    if req < start_brk { return false; }
    let data = mm.end_data().saturating_sub(mm.start_data());
    match (req - start_brk).checked_add(data) {
        Some(total) => total <= rlim_data,
        None        => false,
    }
}

/// sys_brk — adjust brk within ELF heap VMA. F158: enforces
/// RLIMIT_DATA per Linux semantic.
/// # C: O(log N_vmas)
pub fn sys_brk(args: &SyscallArgs) -> i64 {
    let req = args.a0;
    let cur = match sched::live::current() { Some(c) => c, None => return 0 };
    // SAFETY: running task, no concurrent mm writer per `13§5`.
    let mm = match unsafe { cur.mm_ref() } { Some(m) => m.clone(), None => return 0 };
    if req == 0 { return mm.brk() as i64; }
    let rlim_data = cur.rlimit(sched::rlimit::rlim::DATA).0;
    let cur_brk = mm.brk();
    if !data_rlimit_ok(&mm, req, rlim_data) {
        return cur_brk as i64;
    }
    let old_page = match page_align(cur_brk) { Some(v) => v, None => return cur_brk as i64 };
    let new_page = match page_align(req)     { Some(v) => v, None => return cur_brk as i64 };
    if new_page > old_page {
        mm.try_set_brk(req) as i64
    } else if new_page < old_page {
        let out = mm.try_set_brk(req);
        if out == req {
            // Linux releases the shrunk region's pages (do_brk munmaps): a
            // re-grown brk must read fresh ZEROS, not stale heap data.
            let _ = pmm::user_as::evict_pages_in_range(new_page, old_page - new_page);
        }
        out as i64
    } else {
        mm.try_set_brk(req) as i64
    }
}
