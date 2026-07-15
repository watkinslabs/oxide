// 470 listns - one syscall, one file (docs/53).

#![cfg(any(target_os = "oxide-kernel", test))]

use syscall::{errno::Errno, SyscallArgs};

const NS_ID_REQ_SIZE_VER0: usize = 32;
const PAGE_SIZE:           usize = 4096;
const MAX_COUNT:           u64 = 1_000_000;
const U64_SIZE:            usize = core::mem::size_of::<u64>();

const REQ_OFF_SIZE:       usize = 0;
const REQ_OFF_SPARE:      usize = 4;
const REQ_OFF_NS_ID:      usize = 8;
const REQ_OFF_NS_TYPE:    usize = 16;
const REQ_OFF_USER_NS_ID: usize = 24;

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

trait ListNsIo {
    fn access_ok(&mut self, addr: u64, len: usize) -> bool;
    fn copy_from(&mut self, dst: &mut [u8], src: u64) -> Result<(), Errno>;
    fn copy_to(&mut self, dst: u64, src: &[u8]) -> Result<(), Errno>;
}

#[cfg(target_os = "oxide-kernel")]
struct KernelIo;

#[cfg(target_os = "oxide-kernel")]
impl ListNsIo for KernelIo {
    fn access_ok(&mut self, addr: u64, len: usize) -> bool { uaccess::access_ok(addr, len) }
    fn copy_from(&mut self, dst: &mut [u8], src: u64) -> Result<(), Errno> {
        uaccess::copy_from_user(dst, src)
    }
    fn copy_to(&mut self, dst: u64, src: &[u8]) -> Result<(), Errno> {
        uaccess::copy_to_user(dst, src)
    }
}

fn u32_at(bytes: &[u8; NS_ID_REQ_SIZE_VER0], off: usize) -> u32 {
    u32::from_ne_bytes(bytes[off..off + 4].try_into().unwrap())
}

fn u64_at(bytes: &[u8; NS_ID_REQ_SIZE_VER0], off: usize) -> u64 {
    u64::from_ne_bytes(bytes[off..off + U64_SIZE].try_into().unwrap())
}

fn request<I: ListNsIo>(io: &mut I, ptr: u64) -> Result<[u8; NS_ID_REQ_SIZE_VER0], Errno> {
    let mut size_bytes = [0u8; 4];
    io.copy_from(&mut size_bytes, ptr + REQ_OFF_SIZE as u64)?;
    let size = u32::from_ne_bytes(size_bytes) as usize;
    if size > PAGE_SIZE { return Err(Errno::E2big); }
    if size < NS_ID_REQ_SIZE_VER0 { return Err(Errno::Einval); }
    if size > NS_ID_REQ_SIZE_VER0 {
        let mut extension = [0u8; PAGE_SIZE - NS_ID_REQ_SIZE_VER0];
        let extension = &mut extension[..size - NS_ID_REQ_SIZE_VER0];
        io.copy_from(extension, ptr + NS_ID_REQ_SIZE_VER0 as u64)?;
        if extension.iter().any(|byte| *byte != 0) { return Err(Errno::E2big); }
    }
    let mut bytes = [0u8; NS_ID_REQ_SIZE_VER0];
    io.copy_from(&mut bytes, ptr)?;
    Ok(bytes)
}

fn sys_listns_with<I: ListNsIo>(args: &SyscallArgs, caller: &sched::Task, io: &mut I) -> i64 {
    let req       = args.a0;
    let out       = args.a1;
    let nr_ns_ids = args.a2;
    let flags     = args.a3 as u32;

    if flags != 0 { return err(Errno::Einval); }
    if nr_ns_ids > MAX_COUNT { return err(Errno::Eoverflow); }
    let out_len = match (nr_ns_ids as usize).checked_mul(U64_SIZE) {
        Some(len) => len,
        None => return err(Errno::Eoverflow),
    };
    if !io.access_ok(out, out_len) { return err(Errno::Efault); }

    let bytes = match request(io, req) { Ok(bytes) => bytes, Err(error) => return err(error) };
    if u32_at(&bytes, REQ_OFF_SPARE) != 0 { return err(Errno::Einval); }
    let cursor     = u64_at(&bytes, REQ_OFF_NS_ID);
    let ns_type    = u32_at(&bytes, REQ_OFF_NS_TYPE);
    let user_ns_id = u64_at(&bytes, REQ_OFF_USER_NS_ID);
    if (ns_type & !NS_ALL) != 0 { return err(Errno::Eopnotsupp); }

    let owner_filter = match user_ns_id {
        0 => nscg::ListNsOwnerFilter::All,
        LISTNS_CURRENT_USER => nscg::ListNsOwnerFilter::Current,
        ns_id => nscg::ListNsOwnerFilter::NsId(ns_id),
    };
    let page = match nscg::listns_page(caller, cursor, ns_type, owner_filter,
        nr_ns_ids as usize)
    {
        Ok(page) => page,
        Err(nscg::ListNsError::InvalidOwner) => return err(Errno::Einval),
        Err(nscg::ListNsError::NoSuccessor) => return err(Errno::Enoent),
    };
    for index in 0..page.len() {
        let Some(id) = page.id(index) else { return err(Errno::Eio) };
        let dst = out + index as u64 * U64_SIZE as u64;
        if io.copy_to(dst, &id.to_ne_bytes()).is_err() { return err(Errno::Efault); }
    }
    page.len() as i64
}

/// `sys_listns(req, ns_ids, nr_ns_ids, flags)` - slot 470. # C: O(N log N)
#[cfg(target_os = "oxide-kernel")]
pub fn sys_listns(args: &SyscallArgs) -> i64 {
    let caller = match sched::live::current() { Some(caller) => caller, None => return 0 };
    sys_listns_with(args, caller, &mut KernelIo)
}

#[cfg(test)]
#[path = "470_listns/tests.rs"]
mod tests;
