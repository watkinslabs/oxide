// time/tz — TZif parsing + zone-aware localtime (docs/59§6 G16e). Pure parser
// over a TZif (v1/v2/v3) blob: header counts, transition times, type indices,
// ttinfo records, abbreviation table. Prefers the v2/v3 64-bit block. offset_at
// picks the ttinfo in effect for an epoch. localtime = gmtime(t + utoff) with
// tm_gmtoff/tm_isdst/tm_zone. Pure logic hosted-tested on a synthetic blob; the
// tzset/localtime C ABI + tzname/timezone/daylight globals are freestanding.

#[derive(Clone, Copy)]
pub(crate) struct ZoneMeta {
    pub width: u8, // 4 (v1) or 8 (v2/v3) transition-time width
    pub timecnt: u32,
    pub typecnt: u32,
    pub charcnt: u32,
    pub trans_off: u32,   // transition-time array
    pub typeidx_off: u32, // per-transition type index array
    pub ttinfo_off: u32,  // ttinfo[] (6 bytes each)
    pub abbr_off: u32,    // abbreviation string table
}

struct Counts { isutcnt: u32, isstdcnt: u32, leapcnt: u32, timecnt: u32, typecnt: u32, charcnt: u32 }

fn be32(b: &[u8], p: usize) -> u32 { u32::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3]]) }

// Read the 6 counts from a TZif header at `base`.
fn read_counts(b: &[u8], base: usize) -> Option<Counts> {
    if base + 44 > b.len() || &b[base..base + 4] != b"TZif" { return None; }
    Some(Counts {
        isutcnt: be32(b, base + 20), isstdcnt: be32(b, base + 24), leapcnt: be32(b, base + 28),
        timecnt: be32(b, base + 32), typecnt: be32(b, base + 36), charcnt: be32(b, base + 40),
    })
}

// Byte size of the data block following a header, for transition width `w`.
fn block_size(c: &Counts, w: u32) -> usize {
    (c.timecnt * w + c.timecnt + c.typecnt * 6 + c.charcnt + c.leapcnt * (w + 4) + c.isstdcnt + c.isutcnt) as usize
}

fn meta_from(b: &[u8], data_base: usize, c: &Counts, width: u8) -> Option<ZoneMeta> {
    let w = width as u32;
    let trans_off = data_base as u32;
    let typeidx_off = trans_off + c.timecnt * w;
    let ttinfo_off = typeidx_off + c.timecnt;
    let abbr_off = ttinfo_off + c.typecnt * 6;
    if (abbr_off + c.charcnt) as usize > b.len() { return None; }
    Some(ZoneMeta { width, timecnt: c.timecnt, typecnt: c.typecnt, charcnt: c.charcnt, trans_off, typeidx_off, ttinfo_off, abbr_off })
}

/// Parse a TZif blob, preferring the v2/v3 64-bit block when present.
/// # C: TZif (RFC 8536) parse to a ZoneMeta of byte offsets
pub(crate) fn parse_meta(b: &[u8]) -> Option<ZoneMeta> {
    let ver = *b.get(4)?;
    let c1 = read_counts(b, 0)?;
    if ver != b'2' && ver != b'3' {
        return meta_from(b, 44, &c1, 4);
    }
    let v2_hdr = 44 + block_size(&c1, 4);
    match read_counts(b, v2_hdr) {
        Some(c2) => meta_from(b, v2_hdr + 44, &c2, 8),
        None => meta_from(b, 44, &c1, 4), // truncated v2 — fall back to v1
    }
}

fn read_trans(b: &[u8], m: &ZoneMeta, i: u32) -> i64 {
    let p = (m.trans_off + i * m.width as u32) as usize;
    if m.width == 8 {
        i64::from_be_bytes([b[p], b[p + 1], b[p + 2], b[p + 3], b[p + 4], b[p + 5], b[p + 6], b[p + 7]])
    } else {
        (be32(b, p) as i32) as i64
    }
}

fn type_index(b: &[u8], m: &ZoneMeta, i: u32) -> u8 { b[(m.typeidx_off + i) as usize] }

/// ttinfo `k`: (utoff secs, isdst, abbrev index).
/// # C: read a TZif ttinfo record
fn ttinfo(b: &[u8], m: &ZoneMeta, k: u8) -> (i32, bool, u8) {
    let p = (m.ttinfo_off + k as u32 * 6) as usize;
    (be32(b, p) as i32, b[p + 4] != 0, b[p + 5])
}

// First standard (non-DST) type, else type 0 — used before the first transition.
fn first_std(b: &[u8], m: &ZoneMeta) -> u8 {
    for k in 0..m.typecnt as u8 { if !ttinfo(b, m, k).1 { return k; } }
    0
}

/// Offset/dst/abbrev-index in effect at epoch `t`.
/// # C: selects the TZif ttinfo for an epoch (last transition ≤ t)
pub(crate) fn offset_at(b: &[u8], m: &ZoneMeta, t: i64) -> (i32, bool, u8) {
    let k = if m.timecnt == 0 || t < read_trans(b, m, 0) {
        first_std(b, m)
    } else {
        let mut k = type_index(b, m, 0);
        for i in 0..m.timecnt { if read_trans(b, m, i) <= t { k = type_index(b, m, i); } else { break; } }
        k
    };
    ttinfo(b, m, k)
}

/// Byte offset (into the blob) of the abbreviation C string for `abbrind`.
/// # C: TZif abbreviation-table index → byte offset
pub(crate) fn abbr_offset(m: &ZoneMeta, abbrind: u8) -> usize { (m.abbr_off + abbrind as u32) as usize }

#[cfg(feature = "freestanding")]
pub use imp::*;

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use super::super::tm::{gmtime_into, tm};
    use crate::arch::syscall::{sys3, sys4};
    use crate::internal::errno::ret_isize;
    use crate::internal::nr;
    use crate::stdlib::env::{current_environ, find_env};
    use core::cell::UnsafeCell;
    use core::sync::atomic::{AtomicBool, Ordering};

    const TZBUF: usize = 8192;
    const AT_FDCWD: usize = (-100i64) as usize;
    const O_RDONLY: usize = 0;

    struct ZoneState { buf: [u8; TZBUF], len: usize, meta: Option<ZoneMeta>, lt: tm }
    struct ZoneCell(UnsafeCell<ZoneState>);
    // SAFETY: single global zone; mutated only by tzset and read by localtime,
    // single-threaded until per-thread locale state lands. Treated like the
    // existing process-global gmtime buffer.
    unsafe impl Sync for ZoneCell {}
    static ZONE: ZoneCell = ZoneCell(UnsafeCell::new(ZoneState {
        buf: [0; TZBUF], len: 0, meta: None,
        lt: tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() },
    }));
    static INIT: AtomicBool = AtomicBool::new(false);

    // mutable C globals (mirrors stdlib::env's `environ` newtype pattern)
    struct PtrPair(UnsafeCell<[*mut u8; 2]>);
    // SAFETY: tzname[2] is a C global; written by tzset, read by callers.
    unsafe impl Sync for PtrPair {}
    #[no_mangle]
    static tzname: PtrPair = PtrPair(UnsafeCell::new([core::ptr::null_mut(); 2]));
    struct LongCell(UnsafeCell<i64>);
    // SAFETY: timezone/daylight are C globals; written by tzset only.
    unsafe impl Sync for LongCell {}
    #[no_mangle]
    static timezone: LongCell = LongCell(UnsafeCell::new(0));
    struct IntCell(UnsafeCell<i32>);
    // SAFETY: daylight C global; written by tzset only.
    unsafe impl Sync for IntCell {}
    #[no_mangle]
    static daylight: IntCell = IntCell(UnsafeCell::new(0));

    core::arch::global_asm!(
        ".globl __daylight",
        ".set __daylight, daylight",
        ".globl __timezone",
        ".set __timezone, timezone",
        ".globl __tzname",
        ".set __tzname, tzname",
    );

    fn st() -> *mut ZoneState { ZONE.0.get() }

    // Open `path` (NUL-terminated) read-only and slurp it into the zone buffer.
    fn slurp(path: *const u8) -> bool {
        // SAFETY: openat/read/close raw syscalls; path is a valid C string and
        // the destination is our fixed-size static buffer (bounds-checked).
        unsafe {
            let fd = ret_isize(sys4(nr::OPENAT, AT_FDCWD, path as usize, O_RDONLY, 0));
            if fd < 0 { return false; }
            let s = &mut *st();
            let mut n = 0usize;
            loop {
                if n >= TZBUF { break; }
                let r = ret_isize(sys3(nr::READ, fd as usize, s.buf.as_mut_ptr().add(n) as usize, TZBUF - n));
                if r <= 0 { break; }
                n += r as usize;
            }
            sys3(nr::CLOSE, fd as usize, 0, 0);
            s.len = n;
            n > 0
        }
    }

    // Borrow the TZ environment value (without the NUL), or None.
    #[allow(clippy::manual_c_str_literals)] // byte literals are arch-portable (c_char signedness varies)
    fn tz_env() -> Option<&'static [u8]> {
        // SAFETY: current_environ is the live char** array; find_env returns a
        // pointer to the NUL-terminated value of TZ (or null). Scan its length.
        unsafe {
            let p = find_env(current_environ() as *const *const u8, b"TZ\0".as_ptr(), 2);
            if p.is_null() { return None; }
            let mut n = 0;
            while *p.add(n) != 0 { n += 1; }
            Some(core::slice::from_raw_parts(p, n))
        }
    }

    // Resolve TZ → a NUL-terminated path in `out`; returns true if filled.
    fn tz_path(out: &mut [u8; 256]) -> bool {
        match tz_env() {
            Some(v) if !v.is_empty() && v[0] == b':' => copy_path(&v[1..], out),
            Some(v) if !v.is_empty() && v[0] == b'/' => copy_path(v, out),
            Some(v) if !v.is_empty() => {
                let pre = b"/usr/share/zoneinfo/";
                if pre.len() + v.len() + 1 > out.len() { return false; }
                out[..pre.len()].copy_from_slice(pre);
                out[pre.len()..pre.len() + v.len()].copy_from_slice(v);
                out[pre.len() + v.len()] = 0;
                true
            }
            _ => copy_path(b"/etc/localtime", out),
        }
    }

    fn copy_path(p: &[u8], out: &mut [u8; 256]) -> bool {
        if p.len() + 1 > out.len() { return false; }
        out[..p.len()].copy_from_slice(p);
        out[p.len()] = 0;
        true
    }

    #[allow(clippy::manual_c_str_literals)] // byte literal is arch-portable
    fn refresh_globals() {
        // SAFETY: reads the just-parsed zone buffer to set the C globals; all
        // accesses are bounds-derived from the validated ZoneMeta.
        unsafe {
            let s = &mut *st();
            let (mut std_off, mut std_ab, mut dst_ab, mut has_dst) = (0i32, core::ptr::null_mut::<u8>(), core::ptr::null_mut::<u8>(), false);
            if let Some(m) = s.meta {
                for k in 0..m.typecnt as u8 {
                    let (off, isdst, abi) = ttinfo(&s.buf, &m, k);
                    let p = s.buf.as_ptr().add(abbr_offset(&m, abi)) as *mut u8;
                    if isdst { if dst_ab.is_null() { dst_ab = p; } has_dst = true; } else if std_ab.is_null() { std_ab = p; std_off = off; }
                }
            }
            if std_ab.is_null() { std_ab = b"UTC\0".as_ptr() as *mut u8; }
            if dst_ab.is_null() { dst_ab = std_ab; }
            (*tzname.0.get()) = [std_ab, dst_ab];
            *timezone.0.get() = -(std_off as i64); // seconds WEST of UTC
            *daylight.0.get() = has_dst as i32;
        }
    }

    // # C: void tzset(void)
    #[no_mangle]
    pub extern "C" fn tzset() {
        let mut path = [0u8; 256];
        if tz_path(&mut path) { slurp(path.as_ptr()); }
        // SAFETY: parse the slurped buffer into the global meta.
        unsafe {
            let s = &mut *st();
            s.meta = parse_meta(&s.buf[..s.len]);
        }
        refresh_globals();
        INIT.store(true, Ordering::Release);
    }

    fn ensure_init() { if !INIT.load(Ordering::Acquire) { tzset(); } }

    fn localtime_into(t: i64, out: &mut tm) {
        ensure_init();
        // SAFETY: read the global zone; offset_at indices are validated by
        // parse_meta, abbrev pointer stays within the static buffer.
        unsafe {
            let s = &*st();
            match s.meta {
                Some(m) => {
                    let (off, isdst, abi) = offset_at(&s.buf, &m, t);
                    gmtime_into(t + off as i64, out);
                    out.tm_gmtoff = off as i64;
                    out.tm_isdst = isdst as i32;
                    out.tm_zone = s.buf.as_ptr().add(abbr_offset(&m, abi));
                }
                None => gmtime_into(t, out),
            }
        }
    }

    // # C: struct tm *localtime_r(const time_t *t, struct tm *out)
    #[no_mangle]
    pub unsafe extern "C" fn localtime_r(t: *const i64, out: *mut tm) -> *mut tm {
        // SAFETY: t/out are valid per the C contract.
        unsafe { localtime_into(*t, &mut *out); out }
    }
    // # C: struct tm *localtime(const time_t *t)
    #[no_mangle]
    pub unsafe extern "C" fn localtime(t: *const i64) -> *mut tm {
        // SAFETY: t valid; result lives in the process-global zone buffer.
        unsafe { let s = &mut *st(); localtime_into(*t, &mut s.lt); &mut s.lt }
    }

    // # C: time_t mktime(struct tm *tm) — interpret fields as local time
    #[no_mangle]
    pub unsafe extern "C" fn mktime(t: *mut tm) -> i64 {
        // SAFETY: t is a valid struct tm; treat its fields as wall-clock in the
        // current zone. Estimate the UTC epoch, then correct once by the offset
        // actually in effect there (handles the standard/DST split point).
        unsafe {
            ensure_init();
            let utc_guess = super::super::tm::timegm_of(&*t);
            let s = &*st();
            let off = match s.meta { Some(m) => offset_at(&s.buf, &m, utc_guess).0 as i64, None => 0 };
            let e = utc_guess - off;
            // re-derive offset at the corrected instant and normalise tm
            let off2 = match s.meta { Some(m) => offset_at(&s.buf, &m, e).0 as i64, None => 0 };
            let e = utc_guess - off2;
            localtime_into(e, &mut *t);
            e
        }
    }

    // # C: time_t timelocal(struct tm *tm) — GNU alias of mktime
    #[no_mangle]
    pub unsafe extern "C" fn timelocal(t: *mut tm) -> i64 {
        // SAFETY: timelocal == mktime; forwards the same struct-tm contract.
        unsafe { mktime(t) }
    }

    // # C: char *ctime(const time_t *t) — asctime(localtime(t))
    #[no_mangle]
    pub unsafe extern "C" fn ctime(t: *const i64) -> *mut u8 {
        // SAFETY: t is a valid time_t; render local time into the global
        // asctime buffer (shared with asctime per the C contract).
        unsafe { let s = &mut *st(); localtime_into(*t, &mut s.lt); crate::time::cfmt::imp::asctime_static(&s.lt) }
    }
    // # C: char *ctime_r(const time_t *t, char *buf) — buf >= 26 bytes
    #[no_mangle]
    pub unsafe extern "C" fn ctime_r(t: *const i64, buf: *mut u8) -> *mut u8 {
        // SAFETY: t is a valid time_t; buf is writable for 26 bytes. Use a local
        // tm so we do not disturb the global localtime buffer.
        unsafe {
            let mut tmp = tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0,
                               tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() };
            localtime_into(*t, &mut tmp);
            let s = crate::time::cfmt::asctime_fmt(&tmp);
            core::ptr::copy_nonoverlapping(s.as_ptr(), buf, 26);
            buf
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::vec::Vec;

    // Build a TZif block (transition width `w`) for the synthetic zone:
    // type0 = UTC+0 std "UTC", type1 = UTC+3600 dst "DST", one transition→type1 at t=1000.
    fn block(w: usize) -> Vec<u8> {
        let mut v = Vec::new();
        // transitions: one at 1000
        if w == 8 { v.extend_from_slice(&1000i64.to_be_bytes()); } else { v.extend_from_slice(&1000i32.to_be_bytes()); }
        v.push(1); // type index for that transition → type1
        // ttinfo type0: utoff 0, isdst 0, abbrind 0
        v.extend_from_slice(&0i32.to_be_bytes()); v.push(0); v.push(0);
        // ttinfo type1: utoff 3600, isdst 1, abbrind 4
        v.extend_from_slice(&3600i32.to_be_bytes()); v.push(1); v.push(4);
        // abbrev table "UTC\0DST\0"
        v.extend_from_slice(b"UTC\0DST\0");
        v
    }
    fn header(ver: u8) -> Vec<u8> {
        let mut h = Vec::new();
        h.extend_from_slice(b"TZif");
        h.push(ver);
        h.extend_from_slice(&[0u8; 15]);
        for c in [0u32, 0, 0, 1, 2, 8] { h.extend_from_slice(&c.to_be_bytes()); } // isut,isstd,leap,time,type,char
        h
    }
    fn blob_v2() -> Vec<u8> {
        let mut b = header(b'2');
        b.extend_from_slice(&block(4));
        b.extend_from_slice(&header(b'2'));
        b.extend_from_slice(&block(8));
        b.extend_from_slice(b"\nUTC0\n"); // POSIX TZ footer (ignored)
        b
    }
    fn blob_v1() -> Vec<u8> {
        let mut b = header(0);
        b.extend_from_slice(&block(4));
        b
    }

    #[test]
    fn parses_v2_block() {
        let b = blob_v2();
        let m = parse_meta(&b).unwrap();
        assert_eq!(m.width, 8); // v2 block preferred over v1
        assert_eq!(m.timecnt, 1);
        assert_eq!(m.typecnt, 2);
    }

    #[test]
    fn selects_offset_across_transition() {
        for b in [blob_v1(), blob_v2()] {
            let m = parse_meta(&b).unwrap();
            // before transition → std type0
            let (off, isdst, abi) = offset_at(&b, &m, 500);
            assert_eq!((off, isdst), (0, false));
            assert_eq!(&b[abbr_offset(&m, abi)..abbr_offset(&m, abi) + 3], b"UTC");
            // after transition → dst type1
            let (off, isdst, abi) = offset_at(&b, &m, 2000);
            assert_eq!((off, isdst), (3600, true));
            assert_eq!(&b[abbr_offset(&m, abi)..abbr_offset(&m, abi) + 3], b"DST");
        }
    }

    #[test]
    fn localtime_is_gmtime_shifted() {
        use super::super::tm::{gmtime_into, tm};
        let b = blob_v2();
        let m = parse_meta(&b).unwrap();
        let t = 2000i64; // in DST, offset +3600
        let (off, _, _) = offset_at(&b, &m, t);
        let mut local = tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() };
        let mut utc = tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0, tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() };
        gmtime_into(t + off as i64, &mut local);
        gmtime_into(t, &mut utc);
        // local clock is one hour ahead of UTC at t=2000
        assert_eq!(local.tm_hour, utc.tm_hour + 1);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse_meta(b"NOPE").is_none());
        assert!(parse_meta(&[]).is_none());
    }
}
