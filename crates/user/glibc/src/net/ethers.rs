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

// --- /etc/ethers database (MAC <-> hostname) -------------------------------
// Split a line at the first run of ' '/'\t' into (mac_field, host_field),
// stopping host at whitespace/'#'/end. Returns None if either field is empty.
fn split_ethers(line: &[u8]) -> Option<(&[u8], &[u8])> {
    let mut i = 0;
    while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
    if i >= line.len() || line[i] == b'#' { return None; }
    let m0 = i;
    while i < line.len() && line[i] != b' ' && line[i] != b'\t' { i += 1; }
    let mac = &line[m0..i];
    while i < line.len() && (line[i] == b' ' || line[i] == b'\t') { i += 1; }
    let h0 = i;
    while i < line.len() && line[i] != b' ' && line[i] != b'\t' && line[i] != b'#' { i += 1; }
    let host = &line[h0..i];
    if mac.is_empty() || host.is_empty() { None } else { Some((mac, host)) }
}

// # C: int ether_line(const char *line, struct ether_addr *addr, char *hostname)
#[no_mangle]
pub unsafe extern "C" fn ether_line(line: *const c_char, addr: *mut ether_addr, hostname: *mut c_char) -> i32 {
    // SAFETY: line is a NUL-terminated "MAC hostname" record; addr writable;
    // hostname a caller buffer large enough for the parsed name + NUL.
    unsafe {
        let lp = line as *const u8;
        let n = { let mut k = 0; while *lp.add(k) != 0 { k += 1; } k };
        let s = core::slice::from_raw_parts(lp, n);
        let (mac, host) = match split_ethers(s) { Some(v) => v, None => return -1 };
        // NUL-terminate the MAC field on a scratch buffer for ether_aton_r.
        let mut mb = [0u8; 24];
        if mac.len() >= mb.len() { return -1; }
        mb[..mac.len()].copy_from_slice(mac); mb[mac.len()] = 0;
        if ether_aton_r(mb.as_ptr() as *const c_char, addr).is_null() { return -1; }
        core::ptr::copy_nonoverlapping(host.as_ptr(), hostname as *mut u8, host.len());
        *(hostname as *mut u8).add(host.len()) = 0;
        0
    }
}

// Scan /etc/ethers calling `f(mac_field, host_field)`; stop when it returns true.
unsafe fn scan_ethers(mut f: impl FnMut(&[u8], &[u8]) -> bool) -> bool {
    // SAFETY: reads /etc/ethers into a heap Vec; splits each line.
    unsafe {
        let b = match crate::nss::shared::read_file(b"/etc/ethers\0") { Some(b) => b, None => return false };
        for line in b.split(|&c| c == b'\n') {
            if let Some((mac, host)) = split_ethers(line) { if f(mac, host) { return true; } }
        }
        false
    }
}

// # C: int ether_hostton(const char *hostname, struct ether_addr *addr)
#[no_mangle]
pub unsafe extern "C" fn ether_hostton(hostname: *const c_char, addr: *mut ether_addr) -> i32 {
    // SAFETY: hostname NUL-terminated; addr writable. Scan /etc/ethers for a
    // matching host name and parse its MAC.
    unsafe {
        let hp = hostname as *const u8;
        let hn = { let mut k = 0; while *hp.add(k) != 0 { k += 1; } k };
        let want = core::slice::from_raw_parts(hp, hn);
        let mut found = false;
        scan_ethers(|mac, host| {
            if host == want {
                let mut mb = [0u8; 24];
                if mac.len() < mb.len() {
                    mb[..mac.len()].copy_from_slice(mac); mb[mac.len()] = 0;
                    if !ether_aton_r(mb.as_ptr() as *const c_char, addr).is_null() { found = true; return true; }
                }
            }
            false
        });
        if found { 0 } else { -1 }
    }
}

// # C: int ether_ntohost(char *hostname, const struct ether_addr *addr)
#[no_mangle]
pub unsafe extern "C" fn ether_ntohost(hostname: *mut c_char, addr: *const ether_addr) -> i32 {
    // SAFETY: addr is a valid ether_addr; hostname a caller buffer. Scan
    // /etc/ethers for a line whose MAC matches addr and copy its host name.
    unsafe {
        let want = (*addr).octet;
        let mut found = false;
        scan_ethers(|mac, host| {
            let mut a = ether_addr { octet: [0; 6] };
            let mut mb = [0u8; 24];
            if mac.len() < mb.len() {
                mb[..mac.len()].copy_from_slice(mac); mb[mac.len()] = 0;
                if !ether_aton_r(mb.as_ptr() as *const c_char, &mut a).is_null() && a.octet == want {
                    core::ptr::copy_nonoverlapping(host.as_ptr(), hostname as *mut u8, host.len());
                    *(hostname as *mut u8).add(host.len()) = 0;
                    found = true; return true;
                }
            }
            false
        });
        if found { 0 } else { -1 }
    }
}
