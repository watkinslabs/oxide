use super::*;
pub struct OpaqueAuth {
    oa_flavor: i32,
    _pad: i32,
    oa_base: *mut u8,
    oa_length: u32,
    _pad2: u32,
}

#[repr(C)]
pub struct Pmap {
    pm_prog: u64,
    pm_vers: u64,
    pm_prot: u64,
    pm_port: u64,
}

#[repr(C)]
pub struct PmapList {
    pml_map: Pmap,
    pml_next: *mut PmapList,
}

#[repr(C)]
pub struct AuthUnixParms {
    aup_time: u32,
    _pad: u32,
    aup_machname: *mut u8,
    aup_uid: i32,
    aup_gid: i32,
    aup_len: u32,
    _pad2: u32,
    aup_gids: *mut i32,
}

#[repr(C)]
pub struct XdrDiscrim {
    value: i32,
    proc: Option<XdrProc>,
}

// # C: bool_t xdr_des_block(XDR*, des_block*)
#[no_mangle]
pub unsafe extern "C" fn xdr_des_block(x: *mut XDR, block: *mut u8) -> i32 {
    // SAFETY: des_block is exactly 8 opaque bytes on the SunRPC wire.
    unsafe { xdr_opaque(x, block, 8) }
}

// # C: bool_t xdr_opaque_auth(XDR*, struct opaque_auth*)
#[no_mangle]
pub unsafe extern "C" fn xdr_opaque_auth(x: *mut XDR, auth: *mut OpaqueAuth) -> i32 {
    // SAFETY: flavor enum plus bounded counted auth bytes.
    unsafe {
        if xdr_enum(x, &mut (*auth).oa_flavor) == 0 { return FALSE; }
        xdr_bytes(x, &mut (*auth).oa_base, &mut (*auth).oa_length, 400)
    }
}

// # C: bool_t xdr_authunix_parms(XDR*, struct authunix_parms*)
#[no_mangle]
pub unsafe extern "C" fn xdr_authunix_parms(x: *mut XDR, p: *mut AuthUnixParms) -> i32 {
    // SAFETY: standard auth_unix credential payload.
    unsafe {
        if xdr_u_int(x, &mut (*p).aup_time) == 0 { return FALSE; }
        if xdr_string(x, &mut (*p).aup_machname, 255) == 0 { return FALSE; }
        if xdr_int(x, &mut (*p).aup_uid) == 0 { return FALSE; }
        if xdr_int(x, &mut (*p).aup_gid) == 0 { return FALSE; }
        xdr_array(x, &mut (*p).aup_gids as *mut *mut i32 as *mut *mut u8, &mut (*p).aup_len, 16, core::mem::size_of::<i32>() as u32, xdr_int_void)
    }
}

// # C: bool_t xdr_pmap(XDR*, struct pmap*)
#[no_mangle]
pub unsafe extern "C" fn xdr_pmap(x: *mut XDR, p: *mut Pmap) -> i32 {
    // SAFETY: portmapper entries are four unsigned-long fields.
    (unsafe {
        xdr_u_long(x, &mut (*p).pm_prog) != 0
            && xdr_u_long(x, &mut (*p).pm_vers) != 0
            && xdr_u_long(x, &mut (*p).pm_prot) != 0
            && xdr_u_long(x, &mut (*p).pm_port) != 0
    }) as i32
}

unsafe extern "C" fn xdr_pmap_void(x: *mut XDR, p: *mut c_void) -> i32 {
    // SAFETY: adapter for xdr_pointer over struct pmaplist.
    unsafe { xdr_pmaplist(x, p as *mut PmapList) }
}

// # C: bool_t xdr_pmaplist(XDR*, struct pmaplist*)
#[no_mangle]
pub unsafe extern "C" fn xdr_pmaplist(x: *mut XDR, p: *mut PmapList) -> i32 {
    // SAFETY: recursive pmap list: map payload followed by optional next ptr.
    unsafe {
        if xdr_pmap(x, &mut (*p).pml_map) == 0 { return FALSE; }
        xdr_pointer(x, &mut (*p).pml_next as *mut *mut PmapList as *mut *mut u8, core::mem::size_of::<PmapList>() as u32, xdr_pmap_void)
    }
}

// # C: bool_t xdr_union(XDR*, enum_t*, char*, struct xdr_discrim*, xdrproc_t)
#[no_mangle]
pub unsafe extern "C" fn xdr_union(x: *mut XDR, dscmp: *mut i32, unp: *mut c_void, choices: *const XdrDiscrim, dfault: Option<XdrProc>) -> i32 {
    // SAFETY: serialize the discriminator, then dispatch the matching arm.
    unsafe {
        if xdr_enum(x, dscmp) == 0 { return FALSE; }
        let mut c = choices;
        while !c.is_null() {
            if (*c).proc.is_none() { break; }
            if (*c).value == *dscmp {
                return (*c).proc.unwrap()(x, unp);
            }
            c = c.add(1);
        }
        if let Some(proc) = dfault { proc(x, unp) } else { FALSE }
    }
}

#[no_mangle] pub unsafe extern "C" fn xdr_accepted_reply(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_rejected_reply(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_replymsg(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_callmsg(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_callhdr(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_authdes_cred(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_authdes_verf(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_cryptkeyarg(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_cryptkeyarg2(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_cryptkeyres(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_getcredres(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_key_netstarg(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_key_netstres(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_keybuf(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_keystatus(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_netnamestr(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_rmtcall_args(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_rmtcallres(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }
#[no_mangle] pub unsafe extern "C" fn xdr_unixcred(_x: *mut XDR, _p: *mut c_void) -> i32 { FALSE }

// # C: void xdrrec_create(XDR*, unsigned, unsigned, char*, readit, writeit)
#[no_mangle]
pub unsafe extern "C" fn xdrrec_create(_x: *mut XDR, _sendsize: u32, _recvsize: u32, _handle: *mut c_void, _readit: *const c_void, _writeit: *const c_void) {}

#[no_mangle]
pub unsafe extern "C" fn xdrrec_endofrecord(_x: *mut XDR, _sendnow: i32) -> i32 { FALSE }

#[no_mangle]
pub unsafe extern "C" fn xdrrec_eof(_x: *mut XDR) -> i32 { TRUE }

#[no_mangle]
pub unsafe extern "C" fn xdrrec_skiprecord(_x: *mut XDR) -> i32 { FALSE }

// # C: void xdrstdio_create(XDR*, FILE*, enum xdr_op)
#[no_mangle]
pub unsafe extern "C" fn xdrstdio_create(_x: *mut XDR, _file: *mut c_void, _op: i32) {}
