// DES C ABI (docs/59§6 G17a): the classic <unistd.h>/<crypt.h> setkey/encrypt
// bit-array cipher + the reentrant setkey_r/encrypt_r, plus the SunRPC
// <rpc/des_crypt.h> ecb_crypt/cbc_crypt/des_setparity byte API. Freestanding
// only; thin shims over the algorithm in `super::des`. Output is bit-for-bit
// classic DES (FIPS vectors), the contract glibc's removed copy also met.
#![cfg(feature = "freestanding")]
use super::des;
use core::cell::UnsafeCell;
use core::ffi::{c_char, c_void};

// SunRPC mode flags + status (rpc/des_crypt.h). mode bit0 = DES_DECRYPT.
const DES_DECRYPT: u32 = 0x0001;
const DESERR_NONE: i32 = 0; // DESERR_NONE — success (DES_FAILED is false)

// Process-global schedule key set by setkey(), consumed by encrypt() — matches
// glibc's static-state setkey/encrypt pair (the reentrant forms take a struct).
struct KeyState(UnsafeCell<[u8; 64]>);
// SAFETY: setkey/encrypt are the historical non-reentrant DES ABI backed by one
// process-global key; callers serialise their own use (single-threaded crypt).
unsafe impl Sync for KeyState {}
static KEY: KeyState = KeyState(UnsafeCell::new([0; 64]));

// # C: void setkey(const char *key) — install the 64-bit-array DES key
#[no_mangle]
pub unsafe extern "C" fn setkey(key: *const u8) {
    // SAFETY: key points at 64 bytes each holding one bit (glibc setkey ABI);
    // we copy them into the process-global key schedule state for encrypt().
    unsafe {
        let dst = &mut *KEY.0.get();
        for i in 0..64 { dst[i] = *key.add(i) & 1; }
    }
}

// # C: void encrypt(char *block, int edflag) — DES en/decipher block in place
#[no_mangle]
pub unsafe extern "C" fn encrypt(block: *mut u8, edflag: i32) {
    // SAFETY: block points at 64 bytes (one bit each); KEY holds the schedule
    // installed by setkey; we read+write exactly those 64 bytes in place.
    unsafe {
        let key = &*KEY.0.get();
        let mut b = [0u8; 64];
        for i in 0..64 { b[i] = *block.add(i) & 1; }
        des::des_bits_block(key, &mut b, edflag != 0);
        for i in 0..64 { *block.add(i) = b[i]; }
    }
}

// # C: void setkey_r(const char *key, struct crypt_data *data) — reentrant setkey
#[no_mangle]
pub unsafe extern "C" fn setkey_r(key: *const u8, data: *mut u8) {
    // SAFETY: data is a caller-owned struct crypt_data (≥ 64 bytes); we stash
    // the 64-bit key at its start so the matching encrypt_r can recover it.
    unsafe {
        for i in 0..64 { *data.add(i) = *key.add(i) & 1; }
    }
}

// # C: void encrypt_r(char *block, int edflag, struct crypt_data *data)
#[no_mangle]
pub unsafe extern "C" fn encrypt_r(block: *mut u8, edflag: i32, data: *const u8) {
    // SAFETY: block is 64 bit-bytes; data holds the key written by setkey_r at
    // its start. Reentrant: no shared state, transform happens in place.
    unsafe {
        let mut key = [0u8; 64];
        for i in 0..64 { key[i] = *data.add(i) & 1; }
        let mut b = [0u8; 64];
        for i in 0..64 { b[i] = *block.add(i) & 1; }
        des::des_bits_block(&key, &mut b, edflag != 0);
        for i in 0..64 { *block.add(i) = b[i]; }
    }
}

// Load 8 packed key bytes from a C pointer.
unsafe fn key8(p: *const u8) -> [u8; 8] {
    // SAFETY: p points at 8 readable bytes (a DES key buffer).
    unsafe { let mut k = [0u8; 8]; for i in 0..8 { k[i] = *p.add(i); } k }
}

// # C: int ecb_crypt(char *key, char *buf, unsigned len, unsigned mode)
#[no_mangle]
pub unsafe extern "C" fn ecb_crypt(key: *mut u8, buf: *mut u8, len: u32, mode: u32) -> i32 {
    // SAFETY: key is 8 bytes; buf is len bytes (len a multiple of 8 per the
    // SunRPC contract); each 8-byte chunk is transformed in place under ECB.
    unsafe {
        let k = key8(key);
        let decrypt = mode & DES_DECRYPT != 0;
        let n = (len as usize) & !7; // whole 8-byte blocks only
        let mut off = 0;
        while off < n {
            let mut blk = [0u8; 8];
            for i in 0..8 { blk[i] = *buf.add(off + i); }
            let out = des::des_ecb_block(&k, &blk, decrypt);
            for i in 0..8 { *buf.add(off + i) = out[i]; }
            off += 8;
        }
        DESERR_NONE
    }
}

// # C: int cbc_crypt(char *key, char *buf, unsigned len, unsigned mode, char *ivec)
#[no_mangle]
pub unsafe extern "C" fn cbc_crypt(key: *mut u8, buf: *mut u8, len: u32, mode: u32, ivec: *mut u8) -> i32 {
    // SAFETY: key is 8 bytes; buf is len bytes (multiple of 8); ivec is 8 bytes,
    // updated to the last cipher/plain block per CBC chaining, all in place.
    unsafe {
        let k = key8(key);
        let decrypt = mode & DES_DECRYPT != 0;
        let n = (len as usize) & !7;
        let mut iv = key8(ivec);
        let mut off = 0;
        while off < n {
            let mut blk = [0u8; 8];
            for i in 0..8 { blk[i] = *buf.add(off + i); }
            let out = if decrypt {
                let dec = des::des_ecb_block(&k, &blk, true);
                let mut o = [0u8; 8];
                for i in 0..8 { o[i] = dec[i] ^ iv[i]; }
                iv = blk; // next IV = this ciphertext
                o
            } else {
                let mut x = [0u8; 8];
                for i in 0..8 { x[i] = blk[i] ^ iv[i]; }
                let c = des::des_ecb_block(&k, &x, false);
                iv = c; // next IV = this ciphertext
                c
            };
            for i in 0..8 { *buf.add(off + i) = out[i]; }
            off += 8;
        }
        for i in 0..8 { *ivec.add(i) = iv[i]; }
        DESERR_NONE
    }
}

// # C: void des_setparity(char *key) — set odd parity on each of 8 key bytes
#[no_mangle]
pub unsafe extern "C" fn des_setparity(key: *mut u8) {
    // SAFETY: key is 8 bytes; we rewrite bit0 of each so the byte has odd parity
    // (the standard DES key-parity convention), in place.
    unsafe {
        for i in 0..8 {
            let b = *key.add(i);
            let ones = (b & 0xFE).count_ones();
            *key.add(i) = (b & 0xFE) | ((ones & 1 == 0) as u8); // odd total parity
        }
    }
}

// # C: int getnetname(char *name)
#[no_mangle]
pub unsafe extern "C" fn getnetname(_name: *mut c_char) -> i32 {
    0
}

// # C: int host2netname(char *netname, const char *host, const char *domain)
#[no_mangle]
pub unsafe extern "C" fn host2netname(_netname: *mut c_char, _host: *const c_char, _domain: *const c_char) -> i32 {
    0
}

// # C: int user2netname(char *netname, uid_t uid, const char *domain)
#[no_mangle]
pub unsafe extern "C" fn user2netname(_netname: *mut c_char, _uid: u32, _domain: *const c_char) -> i32 {
    0
}

// # C: int netname2host(const char *netname, char *host, int hostlen)
#[no_mangle]
pub unsafe extern "C" fn netname2host(_netname: *const c_char, _host: *mut c_char, _hostlen: i32) -> i32 {
    0
}

// # C: int netname2user(const char *netname, uid_t *uidp, gid_t *gidp,
//                       int *gidlenp, gid_t *gidlist)
#[no_mangle]
pub unsafe extern "C" fn netname2user(_netname: *const c_char, _uidp: *mut u32, _gidp: *mut u32, _gidlenp: *mut i32, _gidlist: *mut u32) -> i32 {
    0
}

// # C: int getpublickey(const char *netname, char *publickey)
#[no_mangle]
pub unsafe extern "C" fn getpublickey(_netname: *const c_char, _publickey: *mut c_char) -> i32 {
    0
}

// # C: int getsecretkey(const char *netname, char *secretkey, const char *passwd)
#[no_mangle]
pub unsafe extern "C" fn getsecretkey(_netname: *const c_char, _secretkey: *mut c_char, _passwd: *const c_char) -> i32 {
    0
}

// # C: int key_encryptsession(const char *remotename, des_block *deskey)
#[no_mangle]
pub unsafe extern "C" fn key_encryptsession(_remotename: *const c_char, _deskey: *mut c_void) -> i32 {
    -1
}

// # C: int key_decryptsession(const char *remotename, des_block *deskey)
#[no_mangle]
pub unsafe extern "C" fn key_decryptsession(_remotename: *const c_char, _deskey: *mut c_void) -> i32 {
    -1
}

// # C: int key_encryptsession_pk(const char *remotename, netobj *remotekey, des_block *deskey)
#[no_mangle]
pub unsafe extern "C" fn key_encryptsession_pk(_remotename: *const c_char, _remotekey: *const c_void, _deskey: *mut c_void) -> i32 {
    -1
}

// # C: int key_decryptsession_pk(const char *remotename, netobj *remotekey, des_block *deskey)
#[no_mangle]
pub unsafe extern "C" fn key_decryptsession_pk(_remotename: *const c_char, _remotekey: *const c_void, _deskey: *mut c_void) -> i32 {
    -1
}

// # C: int key_gendes(des_block *deskey)
#[no_mangle]
pub unsafe extern "C" fn key_gendes(_deskey: *mut c_void) -> i32 {
    -1
}

// # C: int key_setsecret(const char *key)
#[no_mangle]
pub unsafe extern "C" fn key_setsecret(_key: *const c_char) -> i32 {
    -1
}

// # C: int key_secretkey_is_set(void)
#[no_mangle]
pub extern "C" fn key_secretkey_is_set() -> i32 {
    0
}

// # C: int key_get_conv(const char *pkey, des_block *deskey)
#[no_mangle]
pub unsafe extern "C" fn key_get_conv(_pkey: *const c_char, _deskey: *mut c_void) -> i32 {
    -1
}

// # C: int key_setnet(void *arg)
#[no_mangle]
pub unsafe extern "C" fn key_setnet(_arg: *mut c_void) -> i32 {
    -1
}

// # C: void passwd2des(char *passwd, char *key)
#[no_mangle]
pub unsafe extern "C" fn passwd2des(passwd: *const c_char, key: *mut c_char) {
    // SAFETY: key is an 8-byte DES key output buffer. Fold the password bytes
    // into it deterministically, then set odd DES parity like glibc's DES API.
    unsafe {
        if key.is_null() { return; }
        for i in 0..8 { *key.add(i) = 0; }
        if !passwd.is_null() {
            let mut p = passwd as *const u8;
            let mut i = 0usize;
            while *p != 0 {
                let k = key as *mut u8;
                *k.add(i & 7) ^= *p;
                p = p.add(1);
                i += 1;
            }
        }
        des_setparity(key as *mut u8);
    }
}

// # C: int xencrypt(char *secret, char *passwd)
#[no_mangle]
pub unsafe extern "C" fn xencrypt(_secret: *mut c_char, _passwd: *const c_char) -> i32 {
    0
}

// # C: int xdecrypt(char *secret, char *passwd)
#[no_mangle]
pub unsafe extern "C" fn xdecrypt(_secret: *mut c_char, _passwd: *const c_char) -> i32 {
    0
}
