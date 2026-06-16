// ether_aton/ether_ntoa (docs/59§6 §9.1) — 48-bit MAC address <-> "x:x:x:x:x:x"
// (glibc formats lowercase hex, no zero-pad). The /etc/ethers DB functions
// (ether_hostton/ntohost/line) are a separate follow-up. C-locale only.
#![cfg(feature = "freestanding")]
use core::ffi::c_char;

#[repr(C)]
pub struct ether_addr { pub octet: [u8; 6] }

fn hexval(c: u8) -> Option<u8> {
    match c { b'0'..=b'9' => Some(c - b'0'), b'a'..=b'f' => Some(c - b'a' + 10), b'A'..=b'F' => Some(c - b'A' + 10), _ => None }
}

// # C: struct ether_addr *ether_aton_r(const char *asc, struct ether_addr *addr)
#[no_mangle]
pub unsafe extern "C" fn ether_aton_r(asc: *const c_char, addr: *mut ether_addr) -> *mut ether_addr {
    // SAFETY: asc is a NUL-terminated "xx:xx:xx:xx:xx:xx"; addr is writable. We
    // parse six ':'-separated 1-2 digit hex octets, returning null on any
    // malformed field.
    unsafe {
        let s = asc as *const u8;
        let mut i = 0usize;
        for o in 0..6 {
            let d0 = match hexval(*s.add(i)) { Some(v) => v, None => return core::ptr::null_mut() };
            i += 1;
            let mut val = d0;
            if let Some(d1) = hexval(*s.add(i)) { val = (val << 4) | d1; i += 1; }
            (*addr).octet[o] = val;
            if o < 5 {
                if *s.add(i) != b':' { return core::ptr::null_mut(); }
                i += 1;
            }
        }
        if *s.add(i) != 0 { return core::ptr::null_mut(); }
        addr
    }
}

// # C: char *ether_ntoa_r(const struct ether_addr *addr, char *buf)
#[no_mangle]
pub unsafe extern "C" fn ether_ntoa_r(addr: *const ether_addr, buf: *mut c_char) -> *mut c_char {
    // SAFETY: addr is a valid ether_addr; buf is writable for ≥18 bytes. Emit
    // lowercase hex octets joined by ':' (glibc's "%x:%x:..." — no zero pad).
    unsafe {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let b = buf as *mut u8;
        let mut p = 0usize;
        for o in 0..6 {
            let v = (*addr).octet[o];
            if v >= 0x10 { *b.add(p) = HEX[(v >> 4) as usize]; p += 1; }
            *b.add(p) = HEX[(v & 0xf) as usize]; p += 1;
            if o < 5 { *b.add(p) = b':'; p += 1; }
        }
        *b.add(p) = 0;
        buf
    }
}

// Process-global result buffers (glibc keeps these non-reentrant statics).
use core::cell::UnsafeCell;
struct AddrCell(UnsafeCell<ether_addr>);
// SAFETY: glibc's ether_aton uses a non-thread-safe process-global result;
// single-threaded callers per the documented contract.
unsafe impl Sync for AddrCell {}
static ATON_BUF: AddrCell = AddrCell(UnsafeCell::new(ether_addr { octet: [0; 6] }));
struct StrCell(UnsafeCell<[u8; 18]>);
// SAFETY: as ATON_BUF — non-reentrant process-global string result.
unsafe impl Sync for StrCell {}
static NTOA_BUF: StrCell = StrCell(UnsafeCell::new([0; 18]));

// # C: struct ether_addr *ether_aton(const char *asc) — static-buffer form.
#[no_mangle]
pub unsafe extern "C" fn ether_aton(asc: *const c_char) -> *mut ether_addr {
    // SAFETY: fill the process-global result via ether_aton_r.
    unsafe { ether_aton_r(asc, ATON_BUF.0.get()) }
}
// # C: char *ether_ntoa(const struct ether_addr *addr) — static-buffer form.
#[no_mangle]
pub unsafe extern "C" fn ether_ntoa(addr: *const ether_addr) -> *mut c_char {
    // SAFETY: fill the process-global result buffer via ether_ntoa_r.
    unsafe { ether_ntoa_r(addr, NTOA_BUF.0.get() as *mut c_char) }
}
