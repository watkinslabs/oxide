use alloc::sync::Arc;
use alloc::vec;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use namespace_identity::NamespaceKind;

use super::*;

const REQ: u64 = 0x1000;
const OUT: u64 = 0x2000;
const LAST_NONWRAPPING_NS_ID: u64 = LISTNS_CURRENT_USER - 1;
static NEXT_TID: AtomicU32 = AtomicU32::new(0x7200_0000);

struct FakeIo {
    req: [u8; PAGE_SIZE],
    out: Vec<u8>,
    access: bool,
    fail_read_at: Option<u64>,
    fail_write_at: Option<u64>,
}

impl FakeIo {
    fn new(size: u32) -> Self {
        let mut this = Self {
            req: [0; PAGE_SIZE], out: vec![0; 64], access: true,
            fail_read_at: None, fail_write_at: None,
        };
        this.req[REQ_OFF_SIZE..REQ_OFF_SIZE + 4].copy_from_slice(&size.to_ne_bytes());
        this
    }

    fn put_u32(&mut self, off: usize, value: u32) {
        self.req[off..off + 4].copy_from_slice(&value.to_ne_bytes());
    }

    fn put_u64(&mut self, off: usize, value: u64) {
        self.req[off..off + U64_SIZE].copy_from_slice(&value.to_ne_bytes());
    }
}

impl ListNsIo for FakeIo {
    fn access_ok(&mut self, _addr: u64, _len: usize) -> bool { self.access }

    fn copy_from(&mut self, dst: &mut [u8], src: u64) -> Result<(), Errno> {
        if self.fail_read_at == Some(src) { return Err(Errno::Efault); }
        let off = src.checked_sub(REQ).ok_or(Errno::Efault)? as usize;
        let end = off.checked_add(dst.len()).ok_or(Errno::Efault)?;
        let source = self.req.get(off..end).ok_or(Errno::Efault)?;
        dst.copy_from_slice(source);
        Ok(())
    }

    fn copy_to(&mut self, dst: u64, src: &[u8]) -> Result<(), Errno> {
        if self.fail_write_at == Some(dst) { return Err(Errno::Efault); }
        let off = dst.checked_sub(OUT).ok_or(Errno::Efault)? as usize;
        let end = off.checked_add(src.len()).ok_or(Errno::Efault)?;
        let target = self.out.get_mut(off..end).ok_or(Errno::Efault)?;
        target.copy_from_slice(src);
        Ok(())
    }
}

fn task(name: &'static str) -> Arc<sched::Task> {
    Arc::new(sched::Task::new(NEXT_TID.fetch_add(1, Ordering::Relaxed), name,
        sched::SchedClass::Normal { weight: 1024 }))
}

fn args(count: u64, flags: u64) -> SyscallArgs {
    SyscallArgs { a0: REQ, a1: OUT, a2: count, a3: flags, ..SyscallArgs::default() }
}

#[test]
fn validation_order_matches_linux_contract() {
    let caller = task("listns-order");
    let mut io = FakeIo::new(NS_ID_REQ_SIZE_VER0 as u32);
    io.access = false;
    io.fail_read_at = Some(REQ);
    assert_eq!(sys_listns_with(&args(1, 1), &caller, &mut io), err(Errno::Einval));
    assert_eq!(sys_listns_with(&args(MAX_COUNT + 1, 0), &caller, &mut io),
        err(Errno::Eoverflow));
    assert_eq!(sys_listns_with(&args(1, 0), &caller, &mut io), err(Errno::Efault));
    io.access = true;
    assert_eq!(sys_listns_with(&args(1, 0), &caller, &mut io), err(Errno::Efault));
}

#[test]
fn request_size_extension_and_reserved_order_matches_linux() {
    let caller = task("listns-request");
    let mut io = FakeIo::new((NS_ID_REQ_SIZE_VER0 + 1) as u32);
    io.fail_read_at = Some(REQ + NS_ID_REQ_SIZE_VER0 as u64);
    io.put_u32(REQ_OFF_SPARE, 1);
    assert_eq!(sys_listns_with(&args(1, 0), &caller, &mut io), err(Errno::Efault));

    io.fail_read_at = None;
    io.req[NS_ID_REQ_SIZE_VER0] = 1;
    assert_eq!(sys_listns_with(&args(1, 0), &caller, &mut io), err(Errno::E2big));
    io.req[NS_ID_REQ_SIZE_VER0] = 0;
    assert_eq!(sys_listns_with(&args(1, 0), &caller, &mut io), err(Errno::Einval));

    io.put_u32(REQ_OFF_SPARE, 0);
    io.put_u32(20, u32::MAX);
    assert!(sys_listns_with(&args(1, 0), &caller, &mut io) >= 0,
        "spare2 is ignored by Linux");
}

#[test]
fn unknown_type_precedes_owner_lookup_and_zero_capacity_still_checks_cursor() {
    let caller = task("listns-type");
    let mut io = FakeIo::new(NS_ID_REQ_SIZE_VER0 as u32);
    io.put_u32(REQ_OFF_NS_TYPE, 1);
    io.put_u64(REQ_OFF_USER_NS_ID, u64::MAX - 1);
    assert_eq!(sys_listns_with(&args(1, 0), &caller, &mut io), err(Errno::Eopnotsupp));

    io.put_u32(REQ_OFF_NS_TYPE, UTS_NS);
    io.put_u64(REQ_OFF_USER_NS_ID, 0);
    // Linux kernel/nstree.c do_listns() looks up last_ns_id + 1 before
    // considering output capacity. This cursor has no possible successor and
    // avoids racing the process-global namespace registry.
    io.put_u64(REQ_OFF_NS_ID, LAST_NONWRAPPING_NS_ID);
    assert_eq!(sys_listns_with(&args(0, 0), &caller, &mut io), err(Errno::Enoent));

    io.put_u64(REQ_OFF_NS_ID, u64::MAX);
    assert_eq!(sys_listns_with(&args(0, 0), &caller, &mut io), 0,
        "maximum cursor wraps to the first structural entry");
}

#[test]
fn element_fault_keeps_written_prefix() {
    let caller = task("listns-prefix");
    caller.creds.cap_effective.store(u64::MAX, Ordering::Release);
    let init_user = namespace_identity::initial(NamespaceKind::User);
    let first = namespace_identity::allocate(NamespaceKind::Uts,
        init_user.clone(), None).unwrap();
    let second = namespace_identity::allocate(NamespaceKind::Uts, init_user, None).unwrap();
    let mut io = FakeIo::new(NS_ID_REQ_SIZE_VER0 as u32);
    io.put_u32(REQ_OFF_NS_TYPE, UTS_NS);
    io.put_u64(REQ_OFF_NS_ID, first.ns_id().as_u64() - 1);
    io.fail_write_at = Some(OUT + U64_SIZE as u64);

    assert_eq!(sys_listns_with(&args(2, 0), &caller, &mut io), err(Errno::Efault));
    assert_eq!(u64::from_ne_bytes(io.out[..U64_SIZE].try_into().unwrap()),
        first.ns_id().as_u64());
    assert!(second.ns_id().as_u64() > first.ns_id().as_u64());
}
