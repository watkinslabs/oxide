// Calendar conversion (docs/59§6 G10). Pure civil-calendar math
// (H. Hinnant's days_from_civil / civil_from_days) for gmtime/timegm;
// localtime == gmtime (UTC only until TZ at G16). struct tm matches the
// glibc layout. gmtime/timegm differentially tested vs host over random
// epochs.

#[repr(C)]
pub struct tm {
    pub tm_sec: i32,
    pub tm_min: i32,
    pub tm_hour: i32,
    pub tm_mday: i32,
    pub tm_mon: i32,
    pub tm_year: i32,
    pub tm_wday: i32,
    pub tm_yday: i32,
    pub tm_isdst: i32,
    pub tm_gmtoff: i64,
    pub tm_zone: *const u8,
}
const _: () = {
    assert!(core::mem::offset_of!(tm, tm_gmtoff) == 40);
    assert!(core::mem::offset_of!(tm, tm_zone) == 48);
    assert!(core::mem::size_of::<tm>() == 56);
};

// (year, month[1..=12], day[1..=31]) from days since 1970-01-01.
fn civil_from_days(z0: i64) -> (i64, i64, i64) {
    let z = z0 + 719468;
    let era = (if z >= 0 { z } else { z - 146096 }) / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (y + if m <= 2 { 1 } else { 0 }, m, d)
}

fn days_from_civil(y0: i64, m: i64, d: i64) -> i64 {
    let y = if m <= 2 { y0 - 1 } else { y0 };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let doy = (153 * (if m > 2 { m - 3 } else { m + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146097 + doe - 719468
}

static GMT: [u8; 4] = *b"GMT\0";

/// # C: fill *out from epoch seconds (UTC)
pub(crate) fn gmtime_into(t: i64, out: &mut tm) {
    let days = t.div_euclid(86400);
    let secs = t.rem_euclid(86400);
    out.tm_hour = (secs / 3600) as i32;
    out.tm_min = ((secs % 3600) / 60) as i32;
    out.tm_sec = (secs % 60) as i32;
    out.tm_wday = ((days.rem_euclid(7) + 4) % 7) as i32;
    let (y, m, d) = civil_from_days(days);
    out.tm_year = (y - 1900) as i32;
    out.tm_mon = (m - 1) as i32;
    out.tm_mday = d as i32;
    out.tm_yday = (days - days_from_civil(y, 1, 1)) as i32;
    out.tm_isdst = 0;
    out.tm_gmtoff = 0;
    out.tm_zone = GMT.as_ptr();
}

/// # C: epoch seconds from a struct tm (UTC)
pub(crate) fn timegm_of(t: &tm) -> i64 {
    let days = days_from_civil(t.tm_year as i64 + 1900, t.tm_mon as i64 + 1, t.tm_mday as i64);
    days * 86400 + t.tm_hour as i64 * 3600 + t.tm_min as i64 * 60 + t.tm_sec as i64
}

#[cfg(feature = "freestanding")]
mod imp {
    use super::*;
    use core::cell::UnsafeCell;

    struct Buf(UnsafeCell<tm>);
    // SAFETY: gmtime/localtime return a pointer to this process-global tm;
    // single-threaded until TLS (G11) makes it per-thread.
    unsafe impl Sync for Buf {}
    static BUF: Buf = Buf(UnsafeCell::new(tm {
        tm_sec: 0, tm_min: 0, tm_hour: 0, tm_mday: 0, tm_mon: 0, tm_year: 0,
        tm_wday: 0, tm_yday: 0, tm_isdst: 0, tm_gmtoff: 0, tm_zone: core::ptr::null(),
    }));
    /// # C: address of the process-global gmtime/localtime buffer
    fn gmtime_buf() -> *mut tm { BUF.0.get() }

    // # C: struct tm *gmtime_r(const time_t *t, struct tm *out)
    #[no_mangle]
    pub unsafe extern "C" fn gmtime_r(t: *const i64, out: *mut tm) -> *mut tm {
        // SAFETY: t/out are valid per the C contract.
        unsafe { gmtime_into(*t, &mut *out); out }
    }
    // # C: struct tm *gmtime(const time_t *t)
    #[no_mangle]
    pub unsafe extern "C" fn gmtime(t: *const i64) -> *mut tm {
        // SAFETY: t is valid; result lives in the process-global buffer.
        unsafe { gmtime_into(*t, &mut *gmtime_buf()); gmtime_buf() }
    }
    // # C: time_t timegm(struct tm *tm)
    #[no_mangle]
    pub unsafe extern "C" fn timegm(t: *mut tm) -> i64 {
        // SAFETY: t is a valid, fully-initialised struct tm.
        unsafe { timegm_of(&*t) }
    }
    // localtime/localtime_r/mktime are zone-aware and live in time::tz (G16e).
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    proptest! {
        #[test]
        fn gmtime_matches_host(t in -62135596800i64..253402300799) { // year 1..9999
            let mut ours = tm { tm_sec:0,tm_min:0,tm_hour:0,tm_mday:0,tm_mon:0,tm_year:0,tm_wday:0,tm_yday:0,tm_isdst:0,tm_gmtoff:0,tm_zone:core::ptr::null() };
            gmtime_into(t, &mut ours);
            // SAFETY: host gmtime_r into a local libc::tm.
            let h: libc::tm = unsafe { let mut h = core::mem::zeroed(); libc::gmtime_r(&t, &mut h); h };
            prop_assert_eq!((ours.tm_sec,ours.tm_min,ours.tm_hour,ours.tm_mday,ours.tm_mon,ours.tm_year,ours.tm_wday,ours.tm_yday),
                            (h.tm_sec,h.tm_min,h.tm_hour,h.tm_mday,h.tm_mon,h.tm_year,h.tm_wday,h.tm_yday), "t={}", t);
        }
        #[test]
        fn timegm_roundtrips(t in -62135596800i64..253402300799) {
            let mut tmv = tm { tm_sec:0,tm_min:0,tm_hour:0,tm_mday:0,tm_mon:0,tm_year:0,tm_wday:0,tm_yday:0,tm_isdst:0,tm_gmtoff:0,tm_zone:core::ptr::null() };
            gmtime_into(t, &mut tmv);
            prop_assert_eq!(timegm_of(&tmv), t);
        }
    }
}
