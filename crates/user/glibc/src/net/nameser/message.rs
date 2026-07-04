use super::*;
const ENODEV: i32 = 19;

// ns_msg — 80-byte ABI per <arpa/nameser.h>. Macros (ns_msg_id/count/...) read
// these fields directly in the caller, so only the layout must match.
#[repr(C)]
pub struct NsMsg {
    msg: *const u8,            // @0  _msg
    eom: *const u8,            // @8  _eom
    id: u16,                   // @16 _id
    flags: u16,                // @18 _flags
    counts: [u16; 4],          // @20 _counts
    sections: [*const u8; 4],  // @32 _sections
    sect: i32,                 // @64 _sect
    rrnum: i32,                // @68 _rrnum
    msg_ptr: *const u8,        // @72 _msg_ptr
}

// ns_rr — 1048-byte ABI. name[1025] then type/class/ttl/rdlength/rdata.
#[repr(C)]
pub struct NsRr {
    name: [u8; 1025],          // @0
    rtype: u16,                // @1026
    rr_class: u16,             // @1028
    ttl: u32,                  // @1032
    rdlength: u16,             // @1036
    rdata: *const u8,          // @1040
}

// (mask, shift) per ns_flag (qr,opcode,aa,tc,rd,ra,z,ad,cd,rcode); glibc table.
const FLAGDATA: [(u16, u32); 10] = [
    (0x8000, 15), (0x7800, 11), (0x0400, 10), (0x0200, 9), (0x0100, 8),
    (0x0080, 7), (0x0040, 6), (0x0020, 5), (0x0010, 4), (0x000f, 0),
];

struct Out {
    buf: *mut u8,
    cap: usize,
    pos: usize,
    col: usize,
    ok: bool,
}

impl Out {
    fn new(buf: *mut c_char, cap: usize) -> Self {
        Self { buf: buf as *mut u8, cap, pos: 0, col: 0, ok: true }
    }
    unsafe fn byte(&mut self, b: u8) {
        if !self.ok { return; }
        if self.pos + 1 >= self.cap { self.ok = false; return; }
        // SAFETY: pos+1 < cap keeps room for the final NUL.
        unsafe { *self.buf.add(self.pos) = b; }
        self.pos += 1;
        self.col = if b == b'\n' { 0 } else if b == b'\t' { (self.col + 8) & !7 } else { self.col + 1 };
    }
    unsafe fn bytes(&mut self, s: &[u8]) {
        for &b in s {
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(b); }
        }
    }
    unsafe fn cstr(&mut self, s: *const c_char) {
        // SAFETY: s is a NUL-terminated C string from caller or stack scratch.
        unsafe { let mut p = s as *const u8; while *p != 0 { self.byte(*p); p = p.add(1); } }
    }
    unsafe fn dec(&mut self, mut v: u64) {
        let mut d = [0u8; 20]; let mut n = 0usize;
        if v == 0 { d[n] = b'0'; n += 1; }
        while v != 0 { d[n] = b'0' + (v % 10) as u8; v /= 10; n += 1; }
        while n != 0 {
            n -= 1;
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(d[n]); }
        }
    }
    unsafe fn hex2(&mut self, b: u8) {
        const H: &[u8; 16] = b"0123456789abcdef";
        // SAFETY: byte() performs the destination capacity check.
        unsafe {
            self.byte(H[(b >> 4) as usize]);
            self.byte(H[(b & 15) as usize]);
        }
    }
    unsafe fn tabs_to(&mut self, col: usize) {
        if self.col >= col {
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(b'\t'); }
            return;
        }
        while self.col < col {
            // SAFETY: byte() performs the destination capacity check.
            unsafe { self.byte(b'\t'); }
        }
    }
    unsafe fn finish(&mut self) -> i32 {
        if !self.ok || self.cap == 0 || self.pos >= self.cap {
            crate::internal::errno::set(EMSGSIZE);
            return -1;
        }
        // SAFETY: pos < cap, so the terminator fits.
        unsafe { *self.buf.add(self.pos) = 0; }
        self.pos as i32
    }
}

fn type_name(t: u16) -> Option<&'static [u8]> {
    Some(match t {
        1 => b"A", 2 => b"NS", 5 => b"CNAME", 6 => b"SOA", 12 => b"PTR",
        15 => b"MX", 16 => b"TXT", 28 => b"AAAA", 33 => b"SRV",
        _ => return None,
    })
}

fn class_name(c: u16) -> Option<&'static [u8]> {
    Some(match c {
        1 => b"IN", 3 => b"CHAOS", 4 => b"HS", 254 => b"NONE", 255 => b"ANY",
        _ => return None,
    })
}

unsafe fn append_domain(out: &mut Out, name: *const c_char, origin: *const c_char) {
    // SAFETY: name/origin are NUL-terminated presentation names. Canonicalizing
    // first makes ns_parserr-expanded names match ns_sprintrrf caller names.
    unsafe {
        let mut canon = [0 as c_char; 1025];
        if ns_makecanon(name, canon.as_mut_ptr(), canon.len()) < 0 { out.ok = false; return; }
        if !origin.is_null() {
            let mut ocanon = [0 as c_char; 1025];
            if ns_makecanon(origin, ocanon.as_mut_ptr(), ocanon.len()) < 0 { out.ok = false; return; }
            let n = canon.as_ptr() as *const u8;
            let o = ocanon.as_ptr() as *const u8;
            let nl = nlen(n);
            let ol = nlen(o);
            if nl == ol {
                let mut same = true;
                for i in 0..ol { if lc(*n.add(i)) != lc(*o.add(i)) { same = false; break; } }
                if same { out.byte(b'@'); return; }
            }
            if ol != 0 && nl > ol && *n.add(nl - ol - 1) == b'.' {
                let mut same = true;
                for i in 0..ol { if lc(*n.add(nl - ol + i)) != lc(*o.add(i)) { same = false; break; } }
                if same { for i in 0..(nl - ol - 1) { out.byte(*n.add(i)); } return; }
            }
        }
        out.cstr(canon.as_ptr());
    }
}

unsafe fn append_owner(out: &mut Out, name: *const c_char, origin: *const c_char) {
    // SAFETY: append_domain handles canonicalization and optional origin
    // relativization; owner names then pad to the fixed RR column.
    unsafe {
        append_domain(out, name, origin);
        out.tabs_to(24);
    }
}

unsafe fn append_ttl_class_type(out: &mut Out, class_: u16, type_: u16, ttl: u64) {
    // SAFETY: writes bounded stack-rendered TTL and static class/type labels.
    unsafe {
        let mut ttlbuf = [0 as c_char; 64];
        if ns_format_ttl(ttl, ttlbuf.as_mut_ptr(), ttlbuf.len()) < 0 { out.ok = false; return; }
        out.cstr(ttlbuf.as_ptr());
        out.byte(b' ');
        if let Some(cn) = class_name(class_) { out.bytes(cn); } else { out.dec(class_ as u64); }
        out.byte(b' ');
        if let Some(tn) = type_name(type_) { out.bytes(tn); } else { out.dec(type_ as u64); }
        out.tabs_to(40);
    }
}

unsafe fn append_name_rdata(out: &mut Out, msg: *const u8, msglen: usize, rdata: *const u8, origin: *const c_char) -> bool {
    // SAFETY: rdata points inside msg..msg+msglen for compressed-name RDATA.
    unsafe {
        let mut tmp = [0 as c_char; 1025];
        let eom = msg.add(msglen);
        if ns_name_uncompress(msg, eom, rdata, tmp.as_mut_ptr(), tmp.len()) < 0 { return false; }
        append_domain(out, tmp.as_ptr(), origin);
        true
    }
}

unsafe fn append_txt(out: &mut Out, rdata: *const u8, rdlen: usize) -> bool {
    // SAFETY: rdata is readable for rdlen bytes; TXT chunks are length-prefixed.
    unsafe {
        let mut off = 0usize; let mut first = true;
        while off < rdlen {
            let n = *rdata.add(off) as usize; off += 1;
            if off + n > rdlen { return false; }
            if !first { out.byte(b' '); } first = false;
            out.byte(b'"');
            for i in 0..n {
                let c = *rdata.add(off + i);
                if c == b'"' || c == b'\\' { out.byte(b'\\'); out.byte(c); }
                else if printable(c) || c == b' ' { out.byte(c); }
                else { out.byte(b'\\'); out.byte(b'0' + c / 100); out.byte(b'0' + (c / 10) % 10); out.byte(b'0' + c % 10); }
            }
            out.byte(b'"');
            off += n;
        }
        true
    }
}

unsafe fn append_rfc3597(out: &mut Out, type_: u16, rdata: *const u8, rdlen: usize) {
    // SAFETY: rdata readable for rdlen bytes; hex dump mirrors glibc's fallback.
    unsafe {
        out.bytes(b"\\# "); out.dec(rdlen as u64); out.bytes(b" (\t; unknown RR type "); out.dec(type_ as u64); out.byte(b'\n');
        out.byte(b'\t');
        for i in 0..rdlen {
            if i != 0 { out.byte(b' '); }
            out.hex2(*rdata.add(i));
        }
        out.bytes(b" )");
        for _ in 0..5 { out.byte(b'\t'); }
        out.bytes(b"; ...");
    }
}

unsafe fn append_rdata(out: &mut Out, msg: *const u8, msglen: usize, class_: u16, type_: u16, rdata: *const u8, rdlen: usize, origin: *const c_char) {
    // SAFETY: rdata readable for rdlen bytes; compressed names use msg/eom.
    unsafe {
        let ok = match (class_, type_) {
            (1, 1) if rdlen == 4 => { out.dec(*rdata as u64); out.byte(b'.'); out.dec(*rdata.add(1) as u64); out.byte(b'.'); out.dec(*rdata.add(2) as u64); out.byte(b'.'); out.dec(*rdata.add(3) as u64); true }
            (1, 28) if rdlen == 16 => {
                let mut a = [0u8; 16]; core::ptr::copy_nonoverlapping(rdata, a.as_mut_ptr(), 16);
                let mut tmp = [0u8; 64];
                if let Some(n) = crate::net::inet::ntop6(&a, &mut tmp) { out.bytes(&tmp[..n]); true } else { false }
            }
            (1, 2 | 5 | 12) => append_name_rdata(out, msg, msglen, rdata, origin),
            (1, 15) if rdlen >= 3 => { out.dec(rd16(rdata) as u64); out.byte(b' '); append_name_rdata(out, msg, msglen, rdata.add(2), origin) }
            (1, 16) => append_txt(out, rdata, rdlen),
            _ => false,
        };
        if !ok { append_rfc3597(out, type_, rdata, rdlen); }
    }
}

unsafe fn setsection(h: &mut NsMsg, sect: i32) {
    h.sect = sect;
    if sect == 4 { h.rrnum = -1; h.msg_ptr = core::ptr::null(); }
    else { h.rrnum = 0; h.msg_ptr = h.sections[sect as usize]; }
}
unsafe fn rd16(p: *const u8) -> u16 { unsafe { ((*p as u16) << 8) | *p.add(1) as u16 } }
unsafe fn rd32(p: *const u8) -> u32 { unsafe { ((*p as u32) << 24) | ((*p.add(1) as u32) << 16) | ((*p.add(2) as u32) << 8) | *p.add(3) as u32 } }

// # C: int ns_msg_getflag(ns_msg handle, int flag) — extract a header flag bit.
#[no_mangle]
pub extern "C" fn ns_msg_getflag(handle: NsMsg, flag: i32) -> i32 {
    if flag < 0 || flag as usize >= FLAGDATA.len() { return 0; }
    let (mask, shift) = FLAGDATA[flag as usize];
    ((handle.flags & mask) >> shift) as i32
}

// # C: int ns_skiprr(const u_char *ptr, const u_char *eom, ns_sect section, int count)
// Bytes spanned by `count` RRs of `section` (questions carry no ttl/rdata).
#[no_mangle]
pub unsafe extern "C" fn ns_skiprr(ptr: *const u8, eom: *const u8, section: i32, count: i32) -> i32 {
    // SAFETY: ptr/eom bound a DNS message; dn_skipname + rdlength advance keep
    // every read within eom.
    unsafe {
        let optr = ptr; let mut p = ptr; let mut c = count;
        while c > 0 {
            let b = crate::net::resolv_name::dn_skipname(p, eom);
            if b < 0 { crate::internal::errno::set(EMSGSIZE); return -1; }
            p = p.add(b as usize + 4); // name + type(2) + class(2)
            if section != 0 { // not ns_s_qd
                if p.add(6) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
                p = p.add(4); // ttl
                let rdlen = rd16(p) as usize; p = p.add(2 + rdlen);
            }
            c -= 1;
        }
        if p > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        (p as usize - optr as usize) as i32
    }
}

// # C: int ns_initparse(const u_char *msg, int msglen, ns_msg *handle)
#[no_mangle]
pub unsafe extern "C" fn ns_initparse(msg: *const u8, msglen: i32, handle: *mut NsMsg) -> i32 {
    // SAFETY: msg points at msglen bytes; handle is a caller ns_msg. Header (12B)
    // + per-section skip stay within eom; sections recorded for ns_parserr.
    unsafe {
        let h = &mut *handle;
        let eom = msg.add(msglen as usize);
        h.msg = msg; h.eom = eom;
        let mut p = msg;
        if p.add(2) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        h.id = rd16(p); p = p.add(2);
        if p.add(2) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        h.flags = rd16(p); p = p.add(2);
        for i in 0..4 {
            if p.add(2) > eom { crate::internal::errno::set(EMSGSIZE); return -1; }
            h.counts[i] = rd16(p); p = p.add(2);
        }
        for i in 0..4 {
            if h.counts[i] == 0 { h.sections[i] = core::ptr::null(); }
            else {
                let b = ns_skiprr(p, eom, i as i32, h.counts[i] as i32);
                if b < 0 { return -1; }
                h.sections[i] = p; p = p.add(b as usize);
            }
        }
        if p != eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        setsection(h, 4);
        0
    }
}

// # C: int ns_parserr(ns_msg *handle, ns_sect section, int rrnum, ns_rr *rr)
#[no_mangle]
pub unsafe extern "C" fn ns_parserr(handle: *mut NsMsg, section: i32, rrnum: i32, rr: *mut NsRr) -> i32 {
    // SAFETY: handle was filled by ns_initparse; rr is a caller ns_rr. Names are
    // expanded via ns_name_uncompress; every field read is eom-bounded.
    unsafe {
        let h = &mut *handle; let r = &mut *rr;
        if section < 0 || section >= 4 { crate::internal::errno::set(ENODEV); return -1; }
        if section != h.sect { setsection(h, section); }
        let mut rn = rrnum;
        if rn == -1 { rn = h.rrnum; }
        if rn < 0 || rn >= h.counts[section as usize] as i32 { crate::internal::errno::set(ENODEV); return -1; }
        if rn < h.rrnum { setsection(h, section); }
        if rn > h.rrnum {
            let b = ns_skiprr(h.msg_ptr, h.eom, section, rn - h.rrnum);
            if b < 0 { return -1; }
            h.msg_ptr = h.msg_ptr.add(b as usize); h.rrnum = rn;
        }
        let b = ns_name_uncompress(h.msg, h.eom, h.msg_ptr, r.name.as_mut_ptr() as *mut c_char, r.name.len());
        if b < 0 { return -1; }
        h.msg_ptr = h.msg_ptr.add(b as usize);
        if h.msg_ptr.add(4) > h.eom { crate::internal::errno::set(EMSGSIZE); return -1; }
        r.rtype = rd16(h.msg_ptr); r.rr_class = rd16(h.msg_ptr.add(2)); h.msg_ptr = h.msg_ptr.add(4);
        if section == 0 { r.ttl = 0; r.rdlength = 0; r.rdata = core::ptr::null(); }
        else {
            if h.msg_ptr.add(6) > h.eom { crate::internal::errno::set(EMSGSIZE); return -1; }
            r.ttl = rd32(h.msg_ptr); r.rdlength = rd16(h.msg_ptr.add(4)); h.msg_ptr = h.msg_ptr.add(6);
            if h.msg_ptr.add(r.rdlength as usize) > h.eom { crate::internal::errno::set(EMSGSIZE); return -1; }
            r.rdata = h.msg_ptr; h.msg_ptr = h.msg_ptr.add(r.rdlength as usize);
        }
        h.rrnum += 1;
        if h.rrnum > h.counts[section as usize] as i32 { setsection(h, 4); }
        0
    }
}

// # C: int ns_sprintrrf(const unsigned char *msg, size_t msglen, const char *name,
//                       ns_class class, ns_type type, unsigned long ttl,
//                       const unsigned char *rdata, size_t rdlen,
//                       const char *name_ctx, const char *origin, char *buf, size_t bufsiz)
#[no_mangle]
pub unsafe extern "C" fn ns_sprintrrf(msg: *const u8, msglen: usize, name: *const c_char, class_: i32, type_: i32, ttl: u64, rdata: *const u8, rdlen: usize, _name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, bufsiz: usize) -> i32 {
    // SAFETY: caller supplies a DNS message, owner name, RDATA bytes, and output
    // buffer. All appends are capacity-checked; compressed RDATA names are
    // expanded against msg..msg+msglen.
    unsafe {
        if msg.is_null() || name.is_null() || buf.is_null() || (rdlen != 0 && rdata.is_null()) { crate::internal::errno::set(EINVAL); return -1; }
        let mut out = Out::new(buf, bufsiz);
        append_owner(&mut out, name, origin);
        append_ttl_class_type(&mut out, class_ as u16, type_ as u16, ttl);
        append_rdata(&mut out, msg, msglen, class_ as u16, type_ as u16, rdata, rdlen, origin);
        out.finish()
    }
}

// # C: int ns_sprintrr(const ns_msg *handle, const ns_rr *rr,
//                      const char *name_ctx, const char *origin, char *buf, size_t bufsiz)
#[no_mangle]
pub unsafe extern "C" fn ns_sprintrr(handle: *const NsMsg, rr: *const NsRr, name_ctx: *const c_char, origin: *const c_char, buf: *mut c_char, bufsiz: usize) -> i32 {
    // SAFETY: handle comes from ns_initparse and rr from ns_parserr; forwards
    // message bounds plus the RR fields to ns_sprintrrf.
    unsafe {
        if handle.is_null() || rr.is_null() { crate::internal::errno::set(EINVAL); return -1; }
        let h = &*handle; let r = &*rr;
        ns_sprintrrf(h.msg, h.eom as usize - h.msg as usize, r.name.as_ptr() as *const c_char, r.rr_class as i32, r.rtype as i32, r.ttl as u64, r.rdata, r.rdlength as usize, name_ctx, origin, buf, bufsiz)
    }
}
