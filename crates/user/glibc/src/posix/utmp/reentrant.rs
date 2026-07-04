use super::*;
// into the caller buffer + set *result; return 0 on hit, -1 on EOF/no match.

// # C: int getutent_r(struct utmp *buffer, struct utmp **result)
#[no_mangle]
pub unsafe extern "C" fn getutent_r(buffer: *mut utmp, result: *mut *mut utmp) -> i32 {
    // SAFETY: buffer is caller storage; result an out-pointer. getutent yields a
    // pointer into the global buffer; copy that record into buffer.
    unsafe {
        if !result.is_null() { *result = core::ptr::null_mut(); }
        if buffer.is_null() { return -1; }
        let e = getutent();
        if e.is_null() { return -1; }
        core::ptr::copy_nonoverlapping(e as *const u8, buffer as *mut u8, REC);
        if !result.is_null() { *result = buffer; }
        0
    }
}
// # C: int getutid_r(const struct utmp *id, struct utmp *buffer, struct utmp **result)
#[no_mangle]
pub unsafe extern "C" fn getutid_r(id: *const utmp, buffer: *mut utmp, result: *mut *mut utmp) -> i32 {
    // SAFETY: id/buffer are caller storage; result an out-pointer. Reuse getutid
    // for the scan, then copy the hit into buffer.
    unsafe {
        if !result.is_null() { *result = core::ptr::null_mut(); }
        if buffer.is_null() { return -1; }
        let e = getutid(id);
        if e.is_null() { return -1; }
        core::ptr::copy_nonoverlapping(e as *const u8, buffer as *mut u8, REC);
        if !result.is_null() { *result = buffer; }
        0
    }
}
// # C: int getutline_r(const struct utmp *line, struct utmp *buffer, struct utmp **result)
#[no_mangle]
pub unsafe extern "C" fn getutline_r(line: *const utmp, buffer: *mut utmp, result: *mut *mut utmp) -> i32 {
    // SAFETY: line/buffer are caller storage; result an out-pointer. Reuse
    // getutline for the scan, then copy the hit into buffer.
    unsafe {
        if !result.is_null() { *result = core::ptr::null_mut(); }
        if buffer.is_null() { return -1; }
        let e = getutline(line);
        if e.is_null() { return -1; }
        core::ptr::copy_nonoverlapping(e as *const u8, buffer as *mut u8, REC);
        if !result.is_null() { *result = buffer; }
        0
    }
}
// # C: int getutxent_r(struct utmpx *buffer, struct utmpx **result)
#[no_mangle]
pub unsafe extern "C" fn getutxent_r(buffer: *mut utmpx, result: *mut *mut utmpx) -> i32 {
    // SAFETY: utmpx alias of getutent_r; identical layout and contract.
    unsafe { getutent_r(buffer, result) }
}
// # C: int getutxid_r(const struct utmpx *id, struct utmpx *buffer, struct utmpx **result)
#[no_mangle]
pub unsafe extern "C" fn getutxid_r(id: *const utmpx, buffer: *mut utmpx, result: *mut *mut utmpx) -> i32 {
    // SAFETY: utmpx alias of getutid_r; identical layout and contract.
    unsafe { getutid_r(id, buffer, result) }
}
// # C: int getutxline_r(const struct utmpx *line, struct utmpx *buffer, struct utmpx **result)
#[no_mangle]
pub unsafe extern "C" fn getutxline_r(line: *const utmpx, buffer: *mut utmpx, result: *mut *mut utmpx) -> i32 {
    // SAFETY: utmpx alias of getutline_r; identical layout and contract.
    unsafe { getutline_r(line, buffer, result) }
}

