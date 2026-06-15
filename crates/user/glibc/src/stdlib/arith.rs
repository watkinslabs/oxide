// Integer arithmetic helpers (docs/59§6 G7). Trivial, freestanding-only.
// abs(INT_MIN) returns INT_MIN (wrapping), matching glibc.
#![cfg(feature = "freestanding")]

#[repr(C)]
pub struct div_t { pub quot: i32, pub rem: i32 }
#[repr(C)]
pub struct ldiv_t { pub quot: i64, pub rem: i64 }
#[repr(C)]
pub struct lldiv_t { pub quot: i64, pub rem: i64 }
#[repr(C)]
pub struct imaxdiv_t { pub quot: i64, pub rem: i64 }

// # C: int abs(int)
#[no_mangle]
pub extern "C" fn abs(x: i32) -> i32 { x.wrapping_abs() }
// # C: long labs(long)
#[no_mangle]
pub extern "C" fn labs(x: i64) -> i64 { x.wrapping_abs() }
// # C: long long llabs(long long)
#[no_mangle]
pub extern "C" fn llabs(x: i64) -> i64 { x.wrapping_abs() }
// # C: intmax_t imaxabs(intmax_t) — intmax_t is i64 on LP64
#[no_mangle]
pub extern "C" fn imaxabs(x: i64) -> i64 { x.wrapping_abs() }

// # C: div_t div(int num, int den)
#[no_mangle]
pub extern "C" fn div(num: i32, den: i32) -> div_t { div_t { quot: num / den, rem: num % den } }
// # C: ldiv_t ldiv(long, long)
#[no_mangle]
pub extern "C" fn ldiv(num: i64, den: i64) -> ldiv_t { ldiv_t { quot: num / den, rem: num % den } }
// # C: lldiv_t lldiv(long long, long long)
#[no_mangle]
pub extern "C" fn lldiv(num: i64, den: i64) -> lldiv_t { lldiv_t { quot: num / den, rem: num % den } }
// # C: imaxdiv_t imaxdiv(intmax_t num, intmax_t den) — intmax_t is i64 on LP64
#[no_mangle]
pub extern "C" fn imaxdiv(num: i64, den: i64) -> imaxdiv_t { imaxdiv_t { quot: num / den, rem: num % den } }
