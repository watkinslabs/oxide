// <strings.h> bit scan: ffs/ffsl/ffsll — index (1-based) of the least
// significant set bit, 0 if the argument is 0 (docs/59§6 G4). C ABI only.
#![cfg(feature = "freestanding")]

// # C: int ffs(int i)
#[no_mangle]
pub extern "C" fn ffs(i: i32) -> i32 { if i == 0 { 0 } else { i.trailing_zeros() as i32 + 1 } }
// # C: int __ffs(int i)
#[no_mangle]
pub extern "C" fn __ffs(i: i32) -> i32 { ffs(i) }
// # C: int ffsl(long i)
#[no_mangle]
pub extern "C" fn ffsl(i: i64) -> i32 { if i == 0 { 0 } else { i.trailing_zeros() as i32 + 1 } }
// # C: int ffsll(long long i)
#[no_mangle]
pub extern "C" fn ffsll(i: i64) -> i32 { if i == 0 { 0 } else { i.trailing_zeros() as i32 + 1 } }
