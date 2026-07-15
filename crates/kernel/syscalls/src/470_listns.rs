// 470 listns - one syscall, one file (docs/53).

#![cfg(target_os = "oxide-kernel")]

use syscall::{errno::Errno, SyscallArgs};

use crate::userbuf::{validate_user_buf, validate_user_buf_writable};

const NS_ID_REQ_SIZE_VER0: u64 = 32;
const PAGE_SIZE:           u64 = 4096;
const MAX_COUNT:           u64 = 1_000_000;
const U64:                 u64 = 8;

const REQ_OFF_SIZE:       u64 = 0;
const REQ_OFF_SPARE:      u64 = 4;
const REQ_OFF_NS_ID:      u64 = 8;
const REQ_OFF_NS_TYPE:    u64 = 16;
const REQ_OFF_USER_NS_ID: u64 = 24;

const TIME_NS:   u32 = 1 << 7;
const MNT_NS:    u32 = nscg::CLONE_NEWNS as u32;
const CGROUP_NS: u32 = nscg::CLONE_NEWCGROUP as u32;
const UTS_NS:    u32 = nscg::CLONE_NEWUTS as u32;
const IPC_NS:    u32 = nscg::CLONE_NEWIPC as u32;
const USER_NS:   u32 = nscg::CLONE_NEWUSER as u32;
const PID_NS:    u32 = nscg::CLONE_NEWPID as u32;
const NET_NS:    u32 = nscg::CLONE_NEWNET as u32;
const NS_ALL:    u32 = PID_NS | USER_NS | MNT_NS | UTS_NS | IPC_NS | NET_NS | CGROUP_NS | TIME_NS;

const LISTNS_CURRENT_USER: u64 = u64::MAX;

fn err(e: Errno) -> i64 { -(e.as_i32() as i64) }

fn read_u32(ptr: u64, off: u64) -> u32 {
    // SAFETY: caller validated the readable user range covering this field.
    unsafe { core::ptr::read_unaligned((ptr + off) as *const u32) }
}

fn read_u64(ptr: u64, off: u64) -> u64 {
    // SAFETY: caller validated the readable user range covering this field.
    unsafe { core::ptr::read_unaligned((ptr + off) as *const u64) }
}

/// `sys_listns(req, ns_ids, nr_ns_ids, flags)` - slot 470. # C: O(N_tasks log N)
pub fn sys_listns(args: &SyscallArgs) -> i64 {
    let req       = args.a0;
    let out       = args.a1;
    let nr_ns_ids = args.a2;
    let flags     = args.a3 as u32;

    if flags != 0 { return err(Errno::Einval); }
    if nr_ns_ids > MAX_COUNT { return err(Errno::Eoverflow); }
    if nr_ns_ids != 0 {
        let Some(out_len) = nr_ns_ids.checked_mul(U64) else { return err(Errno::Efault); };
        if let Err(rv) = validate_user_buf_writable(out, out_len, 1) { return rv; }
    }

    if let Err(rv) = validate_user_buf(req, 4, 1) { return rv; }
    let size = read_u32(req, REQ_OFF_SIZE) as u64;
    if size > PAGE_SIZE { return err(Errno::E2big); }
    if size < NS_ID_REQ_SIZE_VER0 { return err(Errno::Einval); }
    if let Err(rv) = validate_user_buf(req, size, 1) { return rv; }

    let spare = read_u32(req, REQ_OFF_SPARE);
    if spare != 0 { return err(Errno::Einval); }
    let last_ns_id   = read_u64(req, REQ_OFF_NS_ID);
    let ns_type      = read_u32(req, REQ_OFF_NS_TYPE);
    let user_ns_id   = read_u64(req, REQ_OFF_USER_NS_ID);
    if (ns_type & !NS_ALL) != 0 { return err(Errno::Eopnotsupp); }

    let owner_filter = match user_ns_id {
        0 => nscg::ListNsOwnerFilter::All,
        LISTNS_CURRENT_USER => nscg::ListNsOwnerFilter::Current,
        nsfs_ino => nscg::ListNsOwnerFilter::NsfsIno(nsfs_ino),
    };
    let snapshot = match nscg::listns_snapshot(ns_type, owner_filter) {
        Ok(snapshot) => snapshot,
        Err(nscg::ListNsError::InvalidUserNamespace) => return err(Errno::Einval),
    };
    let start = match snapshot.first_after(last_ns_id) {
        Some(index) => index,
        None if last_ns_id != 0 => return err(Errno::Enoent),
        None => return 0,
    };
    if nr_ns_ids == 0 { return 0; }
    let n = (snapshot.len() - start).min(nr_ns_ids as usize);
    for i in 0..n {
        let Some(id) = snapshot.id(start + i) else { return err(Errno::Eio); };
        // SAFETY: out validated writable for nr_ns_ids u64 entries.
        unsafe { core::ptr::write_unaligned((out + i as u64 * U64) as *mut u64, id); }
    }
    n as i64
}
