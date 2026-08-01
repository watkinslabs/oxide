// Linux uaccess KPI exports for loadable drivers.

#[cfg(test)]
use hal::USER_VA_END;

const LINUX_OK: i64 = 0;
const LINUX_EFAULT: i64 = 14;

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
    uaccess::access_ok(addr as u64, size)
}

extern "C" fn copy_from_user(dst: *mut u8, src: *const u8, n: usize) -> usize {
    if dst.is_null() { return n; }
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: Linux KPI caller supplies a kernel destination valid for n bytes.
    unsafe { uaccess::raw_copy_from_user(dst, src as u64, n) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = src; n }
}

extern "C" fn copy_to_user(dst: *mut u8, src: *const u8, n: usize) -> usize {
    if src.is_null() { return n; }
    #[cfg(target_os = "oxide-kernel")]
    // SAFETY: Linux KPI caller supplies a kernel source valid for n bytes.
    unsafe { uaccess::raw_copy_to_user(dst as u64, src, n) }
    #[cfg(not(target_os = "oxide-kernel"))]
    { let _ = dst; n }
}

extern "C" fn clear_user(dst: *mut u8, n: usize) -> usize {
    const ZERO: [u8; 64] = [0; 64];
    let mut off = 0usize;
    while off < n {
        let take = core::cmp::min(ZERO.len(), n - off);
        let left = copy_to_user(dst.wrapping_add(off), ZERO.as_ptr(), take);
        if left != 0 { return n - off - take + left; }
        off += take;
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    const USER_PTR: u64 = 0x1000;
    const USER_LEN: u64 = 16;
    const OVERFLOW_BASE: u64 = u64::MAX - 3;

    #[test]
    fn access_ok_accepts_user_range() {
        let _modules = crate::test_serial::claim();
        assert!(access_ok(USER_PTR as *const u8, USER_LEN as usize));
    }

    #[test]
    fn access_ok_rejects_null_nonempty_and_kernel_range() {
        let _modules = crate::test_serial::claim();
        assert!(!access_ok(core::ptr::null(), USER_LEN as usize));
        assert!(!access_ok(USER_VA_END as *const u8, USER_LEN as usize));
    }

    #[test]
    fn access_ok_rejects_overflow() {
        let _modules = crate::test_serial::claim();
        assert!(!access_ok(OVERFLOW_BASE as *const u8, USER_LEN as usize));
    }

    #[test]
    fn copy_helpers_report_uncopied_without_current_mm() {
        let _modules = crate::test_serial::claim();
        let mut dst = [0u8; USER_LEN as usize];
        let src = [1u8; USER_LEN as usize];
        assert_eq!(copy_from_user(dst.as_mut_ptr(), USER_PTR as *const u8, dst.len()), dst.len());
        assert_eq!(copy_to_user(USER_PTR as *mut u8, src.as_ptr(), src.len()), src.len());
    }

    #[test]
    fn typed_helpers_return_efault_for_invalid_user_ptrs() {
        let _modules = crate::test_serial::claim();
        let mut out = 0u32;
        assert_eq!(__get_user_4(core::ptr::null(), &mut out), -LINUX_EFAULT);
        assert_eq!(__put_user_4(0xfeed_beefu32, core::ptr::null_mut()), -LINUX_EFAULT);
    }
}
