// Linux uaccess KPI exports for loadable drivers.

use core::ptr;

use hal::{UserVirtAddr, PAGE_SIZE_BYTES, USER_VA_END};
use vmm::VmaProt;

const LINUX_OK: i64 = 0;
const LINUX_EFAULT: i64 = 14;
const PAGE_MASK: u64 = !(PAGE_SIZE_BYTES - 1);

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum UserAccess {
    Read,
    Write,
}

/// Register Linux usercopy KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    use crate::symtab::export;
    for (name, addr) in [
        ("access_ok",      access_ok      as *const () as usize),
        ("copy_from_user", copy_from_user as *const () as usize),
        ("copy_to_user",   copy_to_user   as *const () as usize),
        ("clear_user",     clear_user     as *const () as usize),
        ("__get_user_1",   __get_user_1   as *const () as usize),
        ("__get_user_2",   __get_user_2   as *const () as usize),
        ("__get_user_4",   __get_user_4   as *const () as usize),
        ("__get_user_8",   __get_user_8   as *const () as usize),
        ("__put_user_1",   __put_user_1   as *const () as usize),
        ("__put_user_2",   __put_user_2   as *const () as usize),
        ("__put_user_4",   __put_user_4   as *const () as usize),
        ("__put_user_8",   __put_user_8   as *const () as usize),
    ] { export(name, addr, false); }
}

extern "C" fn access_ok(addr: *const u8, size: usize) -> bool {
    validate_user_range(addr as u64, size as u64).is_some()
}

extern "C" fn copy_from_user(dst: *mut u8, src: *const u8, n: usize) -> usize {
    if n == 0 { return 0; }
    if dst.is_null() || !user_range_permits(src as u64, n, UserAccess::Read) { return n; }
    // SAFETY: dst is a non-null kernel buffer; src range is validated as readable user memory.
    unsafe { ptr::copy_nonoverlapping(src, dst, n); }
    0
}

extern "C" fn copy_to_user(dst: *mut u8, src: *const u8, n: usize) -> usize {
    if n == 0 { return 0; }
    if src.is_null() || !user_range_permits(dst as u64, n, UserAccess::Write) { return n; }
    // SAFETY: src is a non-null kernel buffer; dst range is validated as writable user memory.
    unsafe { ptr::copy_nonoverlapping(src, dst, n); }
    0
}

extern "C" fn clear_user(dst: *mut u8, n: usize) -> usize {
    if n == 0 { return 0; }
    if !user_range_permits(dst as u64, n, UserAccess::Write) { return n; }
    // SAFETY: dst range is validated as writable user memory.
    unsafe { ptr::write_bytes(dst, 0, n); }
    0
}

extern "C" fn __get_user_1(src: *const u8, out: *mut u8) -> i64 {
    get_user_bytes(src, out, core::mem::size_of::<u8>())
}

extern "C" fn __get_user_2(src: *const u8, out: *mut u16) -> i64 {
    get_user_bytes(src, out as *mut u8, core::mem::size_of::<u16>())
}

extern "C" fn __get_user_4(src: *const u8, out: *mut u32) -> i64 {
    get_user_bytes(src, out as *mut u8, core::mem::size_of::<u32>())
}

extern "C" fn __get_user_8(src: *const u8, out: *mut u64) -> i64 {
    get_user_bytes(src, out as *mut u8, core::mem::size_of::<u64>())
}

extern "C" fn __put_user_1(v: u8, dst: *mut u8) -> i64 {
    put_user_bytes(dst, &v as *const u8, core::mem::size_of::<u8>())
}

extern "C" fn __put_user_2(v: u16, dst: *mut u8) -> i64 {
    put_user_bytes(dst, &v as *const u16 as *const u8, core::mem::size_of::<u16>())
}

extern "C" fn __put_user_4(v: u32, dst: *mut u8) -> i64 {
    put_user_bytes(dst, &v as *const u32 as *const u8, core::mem::size_of::<u32>())
}

extern "C" fn __put_user_8(v: u64, dst: *mut u8) -> i64 {
    put_user_bytes(dst, &v as *const u64 as *const u8, core::mem::size_of::<u64>())
}

fn get_user_bytes(src: *const u8, out: *mut u8, n: usize) -> i64 {
    if out.is_null() { return -LINUX_EFAULT; }
    if copy_from_user(out, src, n) == 0 { LINUX_OK } else { -LINUX_EFAULT }
}

fn put_user_bytes(dst: *mut u8, src: *const u8, n: usize) -> i64 {
    if copy_to_user(dst, src, n) == 0 { LINUX_OK } else { -LINUX_EFAULT }
}

fn user_range_permits(ptr: u64, len: usize, access: UserAccess) -> bool {
    let Some((start, end_inclusive)) = validate_user_range(ptr, len as u64) else { return false; };
    let Some(cur) = sched::current() else { return false; };
    // SAFETY: running task owns its mm slot during syscall/module callback context.
    let Some(mm) = unsafe { cur.mm_ref() }.cloned() else { return false; };
    let mut page = start & PAGE_MASK;
    let last_page = end_inclusive & PAGE_MASK;
    loop {
        let Some(uva) = UserVirtAddr::new(page) else { return false; };
        let Some(vma) = mm.find_vma(uva) else { return false; };
        if !permits(vma.prot, access) { return false; }
        if page == last_page { return true; }
        let Some(next) = page.checked_add(PAGE_SIZE_BYTES) else { return false; };
        page = next;
    }
}

fn validate_user_range(ptr: u64, len: u64) -> Option<(u64, u64)> {
    if len == 0 { return Some((ptr, ptr)); }
    if ptr == 0 { return None; }
    let end = ptr.checked_add(len)?;
    if end > USER_VA_END { return None; }
    Some((ptr, end - 1))
}

fn permits(prot: VmaProt, access: UserAccess) -> bool {
    match access {
        UserAccess::Read  => prot.contains(VmaProt::READ),
        UserAccess::Write => prot.contains(VmaProt::WRITE),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const USER_PTR: u64 = 0x1000;
    const USER_LEN: u64 = 16;
    const OVERFLOW_BASE: u64 = u64::MAX - 3;

    #[test]
    fn access_ok_accepts_user_range() {
        assert!(access_ok(USER_PTR as *const u8, USER_LEN as usize));
    }

    #[test]
    fn access_ok_rejects_null_nonempty_and_kernel_range() {
        assert!(!access_ok(core::ptr::null(), USER_LEN as usize));
        assert!(!access_ok(USER_VA_END as *const u8, USER_LEN as usize));
    }

    #[test]
    fn access_ok_rejects_overflow() {
        assert!(!access_ok(OVERFLOW_BASE as *const u8, USER_LEN as usize));
    }

    #[test]
    fn copy_helpers_report_uncopied_without_current_mm() {
        let mut dst = [0u8; USER_LEN as usize];
        let src = [1u8; USER_LEN as usize];
        assert_eq!(copy_from_user(dst.as_mut_ptr(), USER_PTR as *const u8, dst.len()), dst.len());
        assert_eq!(copy_to_user(USER_PTR as *mut u8, src.as_ptr(), src.len()), src.len());
    }

    #[test]
    fn typed_helpers_return_efault_for_invalid_user_ptrs() {
        let mut out = 0u32;
        assert_eq!(__get_user_4(core::ptr::null(), &mut out), -LINUX_EFAULT);
        assert_eq!(__put_user_4(0xfeed_beefu32, core::ptr::null_mut()), -LINUX_EFAULT);
    }
}
