use super::*;
pub unsafe extern "C" fn ns_format_ttl(mut src: u64, dst: *mut c_char, dstsiz: usize) -> i32 {
    // SAFETY: dst is dstsiz bytes; fmt1 bounds every append before writing.
    unsafe {
        let d0 = dst as *mut u8;
        let mut pos = 0usize;
        let mut x = 0;
        let secs = (src % 60) as u32; src /= 60;
        let mins = (src % 60) as u32; src /= 60;
        let hours = (src % 24) as u32; src /= 24;
        let days = (src % 7) as u32; src /= 7;
        let weeks = src as u32;
        // append "<n><letter>"; bound check incl room for the NUL.
        let mut fmt1 = |n: u32, letter: u8| -> bool {
            let mut tmp = [0u8; 12]; let mut tl = 0usize; let mut v = n;
            if v == 0 { tmp[tl] = b'0'; tl += 1; }
            else { let mut digs = [0u8; 10]; let mut dn = 0; while v > 0 { digs[dn] = b'0' + (v % 10) as u8; v /= 10; dn += 1; } while dn > 0 { dn -= 1; tmp[tl] = digs[dn]; tl += 1; } }
            tmp[tl] = letter; tl += 1;
            if pos + tl + 1 > dstsiz { return false; }
            for k in 0..tl { *d0.add(pos) = tmp[k]; pos += 1; }
            true
        };
        if weeks != 0 { if !fmt1(weeks, b'W') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if days != 0  { if !fmt1(days,  b'D') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if hours != 0 { if !fmt1(hours, b'H') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if mins != 0  { if !fmt1(mins,  b'M') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1; }
        if secs != 0 || (weeks == 0 && days == 0 && hours == 0 && mins == 0) {
            if !fmt1(secs, b'S') { crate::internal::errno::set(EMSGSIZE); return -1; } x += 1;
        }
        if x > 1 { for k in 0..pos { let c = *d0.add(k); if c.is_ascii_uppercase() { *d0.add(k) = c + 32; } } }
        *d0.add(pos) = 0;
        pos as i32
    }
}

// # C: int ns_parse_ttl(const char *src, unsigned long *dst)
// Parse a TTL string ("1D1H1M1S", case-insensitive) or a bare seconds count.
#[no_mangle]
pub unsafe extern "C" fn ns_parse_ttl(src: *const c_char, dst: *mut u64) -> i32 {
    // SAFETY: src NUL-terminated; dst is a writable u64. Mirrors glibc's units.
    unsafe {
        let s = src as *const u8;
        let mut ttl = 0u64; let mut tmp = 0u64; let mut digits = 0; let mut dirty = false;
        let mut i = 0;
        loop {
            let ch = *s.add(i); i += 1;
            if ch == 0 { break; }
            if !(0x20..0x7f).contains(&ch) { crate::internal::errno::set(EINVAL); return -1; }
            if ch.is_ascii_digit() { tmp = tmp * 10 + (ch - b'0') as u64; digits += 1; continue; }
            if digits == 0 { crate::internal::errno::set(EINVAL); return -1; }
            let up = if ch.is_ascii_lowercase() { ch - 32 } else { ch };
            match up {
                b'W' => tmp *= 7 * 24 * 60 * 60,
                b'D' => tmp *= 24 * 60 * 60,
                b'H' => tmp *= 60 * 60,
                b'M' => tmp *= 60,
                b'S' => {}
                _ => { crate::internal::errno::set(EINVAL); return -1; }
            }
            ttl += tmp; tmp = 0; digits = 0; dirty = true;
        }
        if digits > 0 { if dirty { crate::internal::errno::set(EINVAL); return -1; } ttl += tmp; }
        else if !dirty { crate::internal::errno::set(EINVAL); return -1; }
        *dst = ttl;
        0
    }
}
// ns_datetosecs deferred: host glibc's range validation rejects dates beyond a
// (time/version-dependent) recent-past cutoff, so it is not safely diffable yet.
