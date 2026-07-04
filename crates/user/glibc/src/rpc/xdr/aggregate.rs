use super::*;
pub unsafe extern "C" fn xdr_opaque(x: *mut XDR, cp: *mut u8, cnt: u32) -> i32 {
    // SAFETY: cnt bytes + (4 - cnt%4)%4 zero padding bytes.
    unsafe {
        if cnt == 0 { return TRUE; }
        let rnd = (4 - (cnt & 3)) & 3;
        let zeros = [0u8; 4];
        match (*x).x_op {
            ENCODE => { if putbytes(x, cp, cnt) == 0 { return FALSE; } if rnd > 0 { return putbytes(x, zeros.as_ptr(), rnd); } TRUE }
            DECODE => { if getbytes(x, cp, cnt) == 0 { return FALSE; } if rnd > 0 { let mut crud = [0u8; 4]; return getbytes(x, crud.as_mut_ptr(), rnd); } TRUE }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_bytes(XDR*, char**, unsigned*, unsigned maxsize)
#[no_mangle]
pub unsafe extern "C" fn xdr_bytes(x: *mut XDR, cpp: *mut *mut u8, sizep: *mut u32, maxsize: u32) -> i32 {
    // SAFETY: length-prefixed counted bytes; DECODE mallocs *cpp if null, FREE frees it.
    unsafe {
        if xdr_u_int(x, sizep) == 0 { return FALSE; }
        let n = *sizep;
        if n > maxsize { return FALSE; }
        match (*x).x_op {
            DECODE => {
                if n == 0 { return TRUE; }
                if (*cpp).is_null() { *cpp = crate::malloc::heap::malloc(n as usize); if (*cpp).is_null() { return FALSE; } }
                xdr_opaque(x, *cpp, n)
            }
            ENCODE => { if n == 0 { return TRUE; } xdr_opaque(x, *cpp, n) }
            _ => { if !(*cpp).is_null() { crate::malloc::heap::free(*cpp); *cpp = core::ptr::null_mut(); } TRUE }
        }
    }
}
// # C: bool_t xdr_string(XDR*, char**, unsigned maxsize)
#[no_mangle]
pub unsafe extern "C" fn xdr_string(x: *mut XDR, cpp: *mut *mut u8, maxsize: u32) -> i32 {
    // SAFETY: length-prefixed NUL-terminated string; DECODE allocs size+1.
    unsafe {
        let op = (*x).x_op;
        if op == FREE { if !(*cpp).is_null() { crate::malloc::heap::free(*cpp); *cpp = core::ptr::null_mut(); } return TRUE; }
        let mut size: u32 = if op == ENCODE { crate::string::len::strlen_impl(*cpp) as u32 } else { 0 };
        if xdr_u_int(x, &mut size) == 0 { return FALSE; }
        if size > maxsize { return FALSE; }
        match op {
            ENCODE => xdr_opaque(x, *cpp, size),
            DECODE => {
                if (*cpp).is_null() { *cpp = crate::malloc::heap::malloc(size as usize + 1); if (*cpp).is_null() { return FALSE; } }
                if xdr_opaque(x, *cpp, size) == 0 { return FALSE; }
                *(*cpp).add(size as usize) = 0; TRUE
            }
            _ => TRUE,
        }
    }
}
// # C: bool_t xdr_wrapstring(XDR*, char**)
#[no_mangle]
pub unsafe extern "C" fn xdr_wrapstring(x: *mut XDR, cpp: *mut *mut u8) -> i32 {
    // SAFETY: xdr_string with the maximum length bound.
    unsafe { xdr_string(x, cpp, u32::MAX) }
}
// # C: bool_t xdr_netobj(XDR*, struct netobj*)  {u_int n_len; char* n_bytes;}
#[repr(C)]
pub struct netobj { pub n_len: u32, _pad: u32, pub n_bytes: *mut u8 }
#[no_mangle]
pub unsafe extern "C" fn xdr_netobj(x: *mut XDR, np: *mut netobj) -> i32 {
    // SAFETY: a counted byte string (max 1024) via xdr_bytes.
    unsafe { xdr_bytes(x, &mut (*np).n_bytes, &mut (*np).n_len, 1024) }
}

// # C: void xdr_free(xdrproc_t proc, char *objp)
#[no_mangle]
pub unsafe extern "C" fn xdr_free(proc: unsafe extern "C" fn(*mut XDR, *mut c_void) -> i32, objp: *mut c_void) {
    // SAFETY: run `proc` with a FREE-op XDR so it releases any owned allocations.
    unsafe {
        let mut x: XDR = core::mem::zeroed();
        x.x_op = FREE;
        proc(&mut x, objp);
    }
}

pub type XdrProc = unsafe extern "C" fn(*mut XDR, *mut c_void) -> i32;

pub(super) unsafe extern "C" fn xdr_int_void(x: *mut XDR, p: *mut c_void) -> i32 {
    // SAFETY: adapter for xdr_array/xdr_vector over int-sized elements.
    unsafe { xdr_int(x, p as *mut i32) }
}

// # C: bool_t xdr_vector(XDR*, char *basep, unsigned nelem, unsigned elemsize, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_vector(x: *mut XDR, basep: *mut u8, nelem: u32, elemsize: u32, elproc: XdrProc) -> i32 {
    // SAFETY: basep is an nelem*elemsize array; run elproc on each element.
    unsafe {
        for i in 0..nelem as usize {
            if elproc(x, basep.add(i * elemsize as usize) as *mut c_void) == 0 { return FALSE; }
        }
        TRUE
    }
}
// # C: bool_t xdr_array(XDR*, char**, unsigned*, unsigned maxsize, unsigned elemsize, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_array(x: *mut XDR, addrp: *mut *mut u8, sizep: *mut u32, maxsize: u32, elemsize: u32, elproc: XdrProc) -> i32 {
    // SAFETY: length-prefixed counted array; DECODE allocs the element block,
    // FREE runs elproc(FREE) on each element then frees the block.
    unsafe {
        if xdr_u_int(x, sizep) == 0 { return FALSE; }
        let n = *sizep;
        if n > maxsize { return FALSE; }
        let op = (*x).x_op;
        if op == DECODE && n != 0 && (*addrp).is_null() {
            *addrp = crate::malloc::heap::malloc(n as usize * elemsize as usize);
            if (*addrp).is_null() { return FALSE; }
            core::ptr::write_bytes(*addrp, 0, n as usize * elemsize as usize);
        }
        let r = if n != 0 { xdr_vector(x, *addrp, n, elemsize, elproc) } else { TRUE };
        if op == FREE && !(*addrp).is_null() { crate::malloc::heap::free(*addrp); *addrp = core::ptr::null_mut(); }
        r
    }
}
// # C: bool_t xdr_reference(XDR*, char**, unsigned size, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_reference(x: *mut XDR, pp: *mut *mut u8, size: u32, proc: XdrProc) -> i32 {
    // SAFETY: a non-optional pointer to one object; DECODE allocs it, FREE frees it.
    unsafe {
        let op = (*x).x_op;
        if op == DECODE && (*pp).is_null() {
            *pp = crate::malloc::heap::malloc(size as usize);
            if (*pp).is_null() { return FALSE; }
            core::ptr::write_bytes(*pp, 0, size as usize);
        }
        if (*pp).is_null() { return TRUE; }
        let r = proc(x, *pp as *mut c_void);
        if op == FREE { crate::malloc::heap::free(*pp); *pp = core::ptr::null_mut(); }
        r
    }
}
// # C: bool_t xdr_pointer(XDR*, char**, unsigned objsize, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_pointer(x: *mut XDR, objpp: *mut *mut u8, objsize: u32, proc: XdrProc) -> i32 {
    // SAFETY: an optional pointer — a leading bool says whether the object is
    // present, then xdr_reference handles it.
    unsafe {
        let mut more = (!(*objpp).is_null()) as i32;
        if xdr_bool(x, &mut more) == 0 { return FALSE; }
        if more == 0 { *objpp = core::ptr::null_mut(); return TRUE; }
        xdr_reference(x, objpp, objsize, proc)
    }
}
