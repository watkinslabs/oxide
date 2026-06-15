// insque(3)/remque(3) (docs/59§6 G8): operate on caller structs whose first two
// fields are `struct qelem *q_forw, *q_back` (doubly-linked list). C ABI only.
#![cfg(feature = "freestanding")]

#[repr(C)]
struct Qelem { forw: *mut Qelem, back: *mut Qelem }

// # C: void insque(void *elem, void *prev) — insert elem after prev
#[no_mangle]
pub unsafe extern "C" fn insque(elem: *mut core::ffi::c_void, prev: *mut core::ffi::c_void) {
    // SAFETY: elem/prev are null or point to structs beginning with the
    // {forw,back} pointer pair. prev==null builds a one-element list (forw and
    // back set null), else elem is spliced between prev and prev->forw.
    unsafe {
        let e = elem as *mut Qelem;
        if prev.is_null() { (*e).forw = core::ptr::null_mut(); (*e).back = core::ptr::null_mut(); return; }
        let p = prev as *mut Qelem;
        let nxt = (*p).forw;
        (*e).forw = nxt;
        (*e).back = p;
        (*p).forw = e;
        if !nxt.is_null() { (*nxt).back = e; }
    }
}

// # C: void remque(void *elem) — unlink elem
#[no_mangle]
pub unsafe extern "C" fn remque(elem: *mut core::ffi::c_void) {
    // SAFETY: elem points to a struct beginning with {forw,back}; relink its
    // neighbours around it.
    unsafe {
        let e = elem as *mut Qelem;
        let (nxt, prv) = ((*e).forw, (*e).back);
        if !prv.is_null() { (*prv).forw = nxt; }
        if !nxt.is_null() { (*nxt).back = prv; }
    }
}
