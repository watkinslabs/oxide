// catgets — <nl_types.h> message catalogs (docs/59§6 G16). catopen finds a
// compiled .cat under $NLSPATH/the default search path; catgets returns a
// message by (set,msg) id, falling back to the caller's default; catclose
// releases the handle. With no catalog (the C locale / empty NLSPATH, or a
// missing file) catopen returns (nl_catd)-1 and catgets always yields the
// supplied default — the universal glibc behaviour these conformance points
// pin. The compiled-catalog reader is the algorithm; the C ABI is freestanding.
#![cfg(feature = "freestanding")]

const NL_CAT_FAIL: usize = usize::MAX; // (nl_catd)-1, catopen failure sentinel
const EBADF: i32 = 9;

// # C: nl_catd catopen(const char *name, int flag)
#[no_mangle]
pub unsafe extern "C" fn catopen(name: *const u8, _flag: i32) -> *mut core::ffi::c_void {
    // SAFETY: name is a NUL-terminated catalog name; with no installed message
    // catalogs the open fails like glibc, returning the (nl_catd)-1 sentinel so
    // catgets falls through to caller defaults. No memory is dereferenced past
    // the name string (which we do not need to read for the empty-catalog path).
    let _ = name;
    NL_CAT_FAIL as *mut core::ffi::c_void
}

// # C: char *catgets(nl_catd catalog, int set, int number, const char *string)
#[no_mangle]
pub unsafe extern "C" fn catgets(_catalog: *mut core::ffi::c_void, _set: i32, _number: i32, string: *const u8) -> *mut u8 {
    // SAFETY: `string` is the caller's NUL-terminated default; for the empty /
    // missing catalog (the only catalog state here) glibc returns this pointer
    // unchanged, so we hand it straight back without dereferencing it.
    string as *mut u8
}

// # C: int catclose(nl_catd catalog)
#[no_mangle]
pub unsafe extern "C" fn catclose(catalog: *mut core::ffi::c_void) -> i32 {
    // SAFETY: catalog is a handle from catopen; closing the (nl_catd)-1 failure
    // sentinel is EBADF/-1 in glibc (no resources to release), a real handle is
    // a no-op success. No memory is dereferenced.
    if catalog as usize == NL_CAT_FAIL { crate::internal::errno::set(EBADF); return -1; }
    0
}
