// asctime/ctime/difftime (docs/59§6 G16). asctime renders a struct tm to the
// fixed 26-byte "Www Mmm DD HH:MM:SS YYYY\n\0" form (C11 7.27.3.1, C locale).
// ctime/ctime_r live in time::tz (they need localtime). Pure formatter is
// hosted-tested; C ABI exports freestanding-gated.
use crate::time::tm::tm;

const WDAY: [&[u8; 3]; 7] = [b"Sun", b"Mon", b"Tue", b"Wed", b"Thu", b"Fri", b"Sat"];
const MON: [&[u8; 3]; 12] = [b"Jan", b"Feb", b"Mar", b"Apr", b"May", b"Jun", b"Jul", b"Aug", b"Sep", b"Oct", b"Nov", b"Dec"];

#[inline]
fn d2(buf: &mut [u8], off: usize, v: i32) { buf[off] = b'0' + (v / 10 % 10) as u8; buf[off + 1] = b'0' + (v % 10) as u8; }

/// # C: render struct tm to the 26-byte asctime form (incl trailing \n + NUL)
pub(crate) fn asctime_fmt(t: &tm) -> [u8; 26] {
    let mut b = [b' '; 26];
    b[0..3].copy_from_slice(WDAY[(t.tm_wday as usize) % 7]);
    b[4..7].copy_from_slice(MON[(t.tm_mon as usize) % 12]);
    // mday in a width-3 field (space-padded), at [7..10)
    let md = t.tm_mday;
    if md >= 10 { d2(&mut b, 8, md); } else { b[9] = b'0' + (md % 10) as u8; }
    d2(&mut b, 11, t.tm_hour); b[13] = b':';
    d2(&mut b, 14, t.tm_min); b[16] = b':';
    d2(&mut b, 17, t.tm_sec);
    // 4-digit year at [20..24)
    let y = t.tm_year + 1900;
    b[20] = b'0' + (y / 1000 % 10) as u8;
    b[21] = b'0' + (y / 100 % 10) as u8;
    b[22] = b'0' + (y / 10 % 10) as u8;
    b[23] = b'0' + (y % 10) as u8;
    b[24] = b'\n';
    b[25] = 0;
    b
}

#[cfg(feature = "freestanding")]
pub(crate) mod imp {
    use super::*;
    use core::cell::UnsafeCell;

    struct Buf(UnsafeCell<[u8; 26]>);
    // SAFETY: asctime/ctime return a pointer to this process-global buffer;
    // single-threaded until TLS (G11) makes it per-thread.
    unsafe impl Sync for Buf {}
    static BUF: Buf = Buf(UnsafeCell::new([0u8; 26]));

    /// # C: format t into the process-global asctime buffer, return its address
    pub(crate) unsafe fn asctime_static(t: &tm) -> *mut u8 {
        // SAFETY: BUF is the single process-global asctime buffer; write the
        // 26-byte rendering and hand back a pointer into it (glibc contract).
        unsafe { let p = BUF.0.get(); *p = asctime_fmt(t); (*p).as_mut_ptr() }
    }

    // # C: char *asctime(const struct tm *tm)
    #[no_mangle]
    pub unsafe extern "C" fn asctime(t: *const tm) -> *mut u8 {
        // SAFETY: t is a valid struct tm; result lives in the global buffer.
        unsafe { asctime_static(&*t) }
    }
    // # C: char *asctime_r(const struct tm *tm, char *buf) — buf >= 26 bytes
    #[no_mangle]
    pub unsafe extern "C" fn asctime_r(t: *const tm, buf: *mut u8) -> *mut u8 {
        // SAFETY: t is a valid struct tm; buf is writable for 26 bytes.
        unsafe { let s = asctime_fmt(&*t); core::ptr::copy_nonoverlapping(s.as_ptr(), buf, 26); buf }
    }
    // # C: double difftime(time_t t1, time_t t0)
    #[no_mangle]
    pub extern "C" fn difftime(t1: i64, t0: i64) -> f64 { (t1 - t0) as f64 }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn tmz() -> tm {
        tm { tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0,
             tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null() }
    }
    #[test]
    fn asctime_canonical() {
        // Thu Nov 24 18:22:48 1986  (the classic K&R example)
        let mut t = tmz();
        t.tm_wday = 4; t.tm_mon = 10; t.tm_mday = 24;
        t.tm_hour = 18; t.tm_min = 22; t.tm_sec = 48; t.tm_year = 86;
        assert_eq!(&asctime_fmt(&t), b"Thu Nov 24 18:22:48 1986\n\0");
        // single-digit mday is space-padded
        t.tm_mday = 3; t.tm_wday = 0; t.tm_mon = 0; t.tm_year = 100;
        assert_eq!(&asctime_fmt(&t)[..11], b"Sun Jan  3 ");
        assert_eq!(&asctime_fmt(&t)[20..24], b"2000");
    }
}
