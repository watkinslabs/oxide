//! SunRPC client/auth/portmapper compatibility exports.
#![cfg(feature = "freestanding")]

use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};

const RPC_FAILED: *const c_char = b"RPC: failed\0".as_ptr() as *const c_char;

#[repr(transparent)]
struct CreateErr(UnsafeCell<[usize; 4]>);
// SAFETY: rpc_createerr is the historical unsynchronised SunRPC global error.
unsafe impl Sync for CreateErr {}

// # C: struct rpc_createerr rpc_createerr;
#[no_mangle]
static rpc_createerr: CreateErr = CreateErr(UnsafeCell::new([0; 4]));

// # C: AUTH *authnone_create(void)
#[no_mangle]
pub extern "C" fn authnone_create() -> *mut c_void {
    core::ptr::null_mut()
}

// # C: AUTH *authunix_create(char *machname, uid_t uid, gid_t gid, int len, gid_t *aup_gids)
#[no_mangle]
pub unsafe extern "C" fn authunix_create(_machname: *const c_char, _uid: u32, _gid: u32, _len: i32, _aup_gids: *const u32) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: AUTH *authunix_create_default(void)
#[no_mangle]
pub extern "C" fn authunix_create_default() -> *mut c_void {
    core::ptr::null_mut()
}

// # C: AUTH *authdes_create(const char *name, unsigned window, struct sockaddr *syncaddr, des_block *ckey)
#[no_mangle]
pub unsafe extern "C" fn authdes_create(_name: *const c_char, _window: u32, _syncaddr: *mut c_void, _ckey: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: AUTH *authdes_pk_create(const char *name, netobj *pkey, unsigned window, struct sockaddr *syncaddr, des_block *ckey)
#[no_mangle]
pub unsafe extern "C" fn authdes_pk_create(_name: *const c_char, _pkey: *const c_void, _window: u32, _syncaddr: *mut c_void, _ckey: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: int authdes_getucred(void *adc, uid_t *uid, gid_t *gid, short *grouplen, gid_t *groups)
#[no_mangle]
pub unsafe extern "C" fn authdes_getucred(_adc: *const c_void, _uid: *mut u32, _gid: *mut u32, _grouplen: *mut i16, _groups: *mut u32) -> i32 {
    0
}

// # C: CLIENT *clnt_create(const char *host, unsigned long prog, unsigned long vers, const char *proto)
#[no_mangle]
pub unsafe extern "C" fn clnt_create(_host: *const c_char, _prog: u64, _vers: u64, _proto: *const c_char) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: CLIENT *clntraw_create(unsigned long prog, unsigned long vers)
#[no_mangle]
pub extern "C" fn clntraw_create(_prog: u64, _vers: u64) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: CLIENT *clnttcp_create(struct sockaddr_in *addr, unsigned long prog, unsigned long vers, int *sockp, unsigned sendsz, unsigned recvsz)
#[no_mangle]
pub unsafe extern "C" fn clnttcp_create(_addr: *mut c_void, _prog: u64, _vers: u64, _sockp: *mut i32, _sendsz: u32, _recvsz: u32) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: CLIENT *clntudp_create(struct sockaddr_in *addr, unsigned long prog, unsigned long vers, struct timeval wait, int *sockp)
#[no_mangle]
pub unsafe extern "C" fn clntudp_create(_addr: *mut c_void, _prog: u64, _vers: u64, _wait: u64, _sockp: *mut i32) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: CLIENT *clntudp_bufcreate(struct sockaddr_in *addr, unsigned long prog, unsigned long vers, struct timeval wait, int *sockp, unsigned sendsz, unsigned recvsz)
#[no_mangle]
pub unsafe extern "C" fn clntudp_bufcreate(_addr: *mut c_void, _prog: u64, _vers: u64, _wait: u64, _sockp: *mut i32, _sendsz: u32, _recvsz: u32) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: CLIENT *clntunix_create(struct sockaddr_un *addr, unsigned long prog, unsigned long vers, int *sockp, unsigned sendsz, unsigned recvsz)
#[no_mangle]
pub unsafe extern "C" fn clntunix_create(_addr: *mut c_void, _prog: u64, _vers: u64, _sockp: *mut i32, _sendsz: u32, _recvsz: u32) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: enum clnt_stat callrpc(char *host, unsigned long prognum, unsigned long versnum, unsigned long procnum, xdrproc_t inproc, char *in, xdrproc_t outproc, char *out)
#[no_mangle]
pub unsafe extern "C" fn callrpc(_host: *const c_char, _prognum: u64, _versnum: u64, _procnum: u64, _inproc: *const c_void, _in: *mut c_void, _outproc: *const c_void, _out: *mut c_void) -> i32 {
    -1
}

// # C: enum clnt_stat clnt_broadcast(unsigned long prog, unsigned long vers, unsigned long proc, xdrproc_t xargs, char *argsp, xdrproc_t xresults, char *resultsp, resultproc_t eachresult)
#[no_mangle]
pub unsafe extern "C" fn clnt_broadcast(_prog: u64, _vers: u64, _proc: u64, _xargs: *const c_void, _argsp: *mut c_void, _xresults: *const c_void, _resultsp: *mut c_void, _eachresult: *const c_void) -> i32 {
    -1
}

// # C: void clnt_pcreateerror(const char *s)
#[no_mangle]
pub unsafe extern "C" fn clnt_pcreateerror(_s: *const c_char) {}

// # C: void clnt_perror(CLIENT *clnt, const char *s)
#[no_mangle]
pub unsafe extern "C" fn clnt_perror(_clnt: *mut c_void, _s: *const c_char) {}

// # C: void clnt_perrno(enum clnt_stat stat)
#[no_mangle]
pub extern "C" fn clnt_perrno(_stat: i32) {}

// # C: char *clnt_spcreateerror(const char *s)
#[no_mangle]
pub unsafe extern "C" fn clnt_spcreateerror(_s: *const c_char) -> *const c_char {
    RPC_FAILED
}

// # C: char *clnt_sperror(CLIENT *clnt, const char *s)
#[no_mangle]
pub unsafe extern "C" fn clnt_sperror(_clnt: *mut c_void, _s: *const c_char) -> *const c_char {
    RPC_FAILED
}

// # C: char *clnt_sperrno(enum clnt_stat stat)
#[no_mangle]
pub extern "C" fn clnt_sperrno(_stat: i32) -> *const c_char {
    RPC_FAILED
}

// # C: struct pmaplist *pmap_getmaps(struct sockaddr_in *addr)
#[no_mangle]
pub unsafe extern "C" fn pmap_getmaps(_addr: *mut c_void) -> *mut c_void {
    core::ptr::null_mut()
}

// # C: unsigned short pmap_getport(struct sockaddr_in *addr, unsigned long prog, unsigned long vers, unsigned protocol)
#[no_mangle]
pub unsafe extern "C" fn pmap_getport(_addr: *mut c_void, _prog: u64, _vers: u64, _protocol: u32) -> u16 {
    0
}

// # C: enum clnt_stat pmap_rmtcall(struct sockaddr_in *addr, unsigned long prog, unsigned long vers, unsigned long proc, xdrproc_t xdrargs, caddr_t argsp, xdrproc_t xdrres, caddr_t resp, struct timeval tout, unsigned long *port_ptr)
#[no_mangle]
pub unsafe extern "C" fn pmap_rmtcall(_addr: *mut c_void, _prog: u64, _vers: u64, _proc: u64, _xdrargs: *const c_void, _argsp: *mut c_void, _xdrres: *const c_void, _resp: *mut c_void, _tout: u64, _port_ptr: *mut u64) -> i32 {
    -1
}

// # C: bool_t pmap_set(unsigned long prog, unsigned long vers, unsigned protocol, unsigned short port)
#[no_mangle]
pub extern "C" fn pmap_set(_prog: u64, _vers: u64, _protocol: u32, _port: u16) -> i32 {
    0
}

// # C: bool_t pmap_unset(unsigned long prog, unsigned long vers)
#[no_mangle]
pub extern "C" fn pmap_unset(_prog: u64, _vers: u64) -> i32 {
    0
}

// # C: int registerrpc(unsigned long prognum, unsigned long versnum, unsigned long procnum, char *(*progname)(char *), xdrproc_t inproc, xdrproc_t outproc)
#[no_mangle]
pub unsafe extern "C" fn registerrpc(_prognum: u64, _versnum: u64, _procnum: u64, _progname: *const c_void, _inproc: *const c_void, _outproc: *const c_void) -> i32 {
    -1
}

// # C: void get_myaddress(struct sockaddr_in *addr)
#[no_mangle]
pub unsafe extern "C" fn get_myaddress(addr: *mut u8) {
    // SAFETY: addr is a caller-owned sockaddr_in; the no-network fallback
    // writes a zero IPv4 sockaddr_in-sized record when present.
    unsafe {
        if !addr.is_null() { core::ptr::write_bytes(addr, 0, 16); }
    }
}

// # C: int getrpcport(const char *host, unsigned long prognum, unsigned long versnum, unsigned proto)
#[no_mangle]
pub unsafe extern "C" fn getrpcport(_host: *const c_char, _prognum: u64, _versnum: u64, _proto: u32) -> i32 {
    0
}

// # C: int rtime(struct sockaddr_in *addrp, struct rpc_timeval *timep, struct rpc_timeval *timeout)
#[no_mangle]
pub unsafe extern "C" fn rtime(_addrp: *mut c_void, _timep: *mut c_void, _timeout: *mut c_void) -> i32 {
    -1
}
