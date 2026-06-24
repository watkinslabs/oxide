// C23 <stdbit.h> bit utilities (docs/59§6 §9.1). Pure bit ops over unsigned
// char/short/int/long/long long (uc/us/ui/ul/ull). Count/index/width fns return unsigned int (u32);
// bit_floor/bit_ceil return the operand type; has_single_bit returns _Bool(int).
// Generated: 14 ops x 5 types.
#![cfg(feature = "freestanding")]

// ---- uc (u8) ----
#[no_mangle] pub extern "C" fn stdc_leading_zeros_uc(x: u8) -> u32 { x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_leading_ones_uc(x: u8) -> u32 { (!x).leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_zeros_uc(x: u8) -> u32 { x.trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_ones_uc(x: u8) -> u32 { (!x).trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_first_leading_zero_uc(x: u8) -> u32 { if x == u8::MAX { 0 } else { (!x).leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_leading_one_uc(x: u8) -> u32 { if x == 0 { 0 } else { x.leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_zero_uc(x: u8) -> u32 { if x == u8::MAX { 0 } else { (!x).trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_one_uc(x: u8) -> u32 { if x == 0 { 0 } else { x.trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_count_ones_uc(x: u8) -> u32 { x.count_ones() }
#[no_mangle] pub extern "C" fn stdc_count_zeros_uc(x: u8) -> u32 { x.count_zeros() }
#[no_mangle] pub extern "C" fn stdc_has_single_bit_uc(x: u8) -> i32 { (x != 0 && x & x.wrapping_sub(1) == 0) as i32 }
#[no_mangle] pub extern "C" fn stdc_bit_width_uc(x: u8) -> u32 { 8 - x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_bit_floor_uc(x: u8) -> u8 { if x == 0 { 0 } else { (1 as u8) << (8 - 1 - x.leading_zeros()) } }
#[no_mangle] pub extern "C" fn stdc_bit_ceil_uc(x: u8) -> u8 { if x <= 1 { 1 } else { let w = 8 - (x - 1).leading_zeros(); if w >= 8 { 0 } else { (1 as u8) << w } } }

// ---- us (u16) ----
#[no_mangle] pub extern "C" fn stdc_leading_zeros_us(x: u16) -> u32 { x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_leading_ones_us(x: u16) -> u32 { (!x).leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_zeros_us(x: u16) -> u32 { x.trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_ones_us(x: u16) -> u32 { (!x).trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_first_leading_zero_us(x: u16) -> u32 { if x == u16::MAX { 0 } else { (!x).leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_leading_one_us(x: u16) -> u32 { if x == 0 { 0 } else { x.leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_zero_us(x: u16) -> u32 { if x == u16::MAX { 0 } else { (!x).trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_one_us(x: u16) -> u32 { if x == 0 { 0 } else { x.trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_count_ones_us(x: u16) -> u32 { x.count_ones() }
#[no_mangle] pub extern "C" fn stdc_count_zeros_us(x: u16) -> u32 { x.count_zeros() }
#[no_mangle] pub extern "C" fn stdc_has_single_bit_us(x: u16) -> i32 { (x != 0 && x & x.wrapping_sub(1) == 0) as i32 }
#[no_mangle] pub extern "C" fn stdc_bit_width_us(x: u16) -> u32 { 16 - x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_bit_floor_us(x: u16) -> u16 { if x == 0 { 0 } else { (1 as u16) << (16 - 1 - x.leading_zeros()) } }
#[no_mangle] pub extern "C" fn stdc_bit_ceil_us(x: u16) -> u16 { if x <= 1 { 1 } else { let w = 16 - (x - 1).leading_zeros(); if w >= 16 { 0 } else { (1 as u16) << w } } }

// ---- ui (u32) ----
#[no_mangle] pub extern "C" fn stdc_leading_zeros_ui(x: u32) -> u32 { x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_leading_ones_ui(x: u32) -> u32 { (!x).leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_zeros_ui(x: u32) -> u32 { x.trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_ones_ui(x: u32) -> u32 { (!x).trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_first_leading_zero_ui(x: u32) -> u32 { if x == u32::MAX { 0 } else { (!x).leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_leading_one_ui(x: u32) -> u32 { if x == 0 { 0 } else { x.leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_zero_ui(x: u32) -> u32 { if x == u32::MAX { 0 } else { (!x).trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_one_ui(x: u32) -> u32 { if x == 0 { 0 } else { x.trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_count_ones_ui(x: u32) -> u32 { x.count_ones() }
#[no_mangle] pub extern "C" fn stdc_count_zeros_ui(x: u32) -> u32 { x.count_zeros() }
#[no_mangle] pub extern "C" fn stdc_has_single_bit_ui(x: u32) -> i32 { (x != 0 && x & x.wrapping_sub(1) == 0) as i32 }
#[no_mangle] pub extern "C" fn stdc_bit_width_ui(x: u32) -> u32 { 32 - x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_bit_floor_ui(x: u32) -> u32 { if x == 0 { 0 } else { (1 as u32) << (32 - 1 - x.leading_zeros()) } }
#[no_mangle] pub extern "C" fn stdc_bit_ceil_ui(x: u32) -> u32 { if x <= 1 { 1 } else { let w = 32 - (x - 1).leading_zeros(); if w >= 32 { 0 } else { (1 as u32) << w } } }

// ---- ul (u64 on Oxide's LP64 targets) ----
#[no_mangle] pub extern "C" fn stdc_leading_zeros_ul(x: u64) -> u32 { x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_leading_ones_ul(x: u64) -> u32 { (!x).leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_zeros_ul(x: u64) -> u32 { x.trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_ones_ul(x: u64) -> u32 { (!x).trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_first_leading_zero_ul(x: u64) -> u32 { if x == u64::MAX { 0 } else { (!x).leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_leading_one_ul(x: u64) -> u32 { if x == 0 { 0 } else { x.leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_zero_ul(x: u64) -> u32 { if x == u64::MAX { 0 } else { (!x).trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_one_ul(x: u64) -> u32 { if x == 0 { 0 } else { x.trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_count_ones_ul(x: u64) -> u32 { x.count_ones() }
#[no_mangle] pub extern "C" fn stdc_count_zeros_ul(x: u64) -> u32 { x.count_zeros() }
#[no_mangle] pub extern "C" fn stdc_has_single_bit_ul(x: u64) -> i32 { (x != 0 && x & x.wrapping_sub(1) == 0) as i32 }
#[no_mangle] pub extern "C" fn stdc_bit_width_ul(x: u64) -> u32 { 64 - x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_bit_floor_ul(x: u64) -> u64 { if x == 0 { 0 } else { (1 as u64) << (64 - 1 - x.leading_zeros()) } }
#[no_mangle] pub extern "C" fn stdc_bit_ceil_ul(x: u64) -> u64 { if x <= 1 { 1 } else { let w = 64 - (x - 1).leading_zeros(); if w >= 64 { 0 } else { (1 as u64) << w } } }

// ---- ull (u64) ----
#[no_mangle] pub extern "C" fn stdc_leading_zeros_ull(x: u64) -> u32 { x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_leading_ones_ull(x: u64) -> u32 { (!x).leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_zeros_ull(x: u64) -> u32 { x.trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_trailing_ones_ull(x: u64) -> u32 { (!x).trailing_zeros() }
#[no_mangle] pub extern "C" fn stdc_first_leading_zero_ull(x: u64) -> u32 { if x == u64::MAX { 0 } else { (!x).leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_leading_one_ull(x: u64) -> u32 { if x == 0 { 0 } else { x.leading_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_zero_ull(x: u64) -> u32 { if x == u64::MAX { 0 } else { (!x).trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_first_trailing_one_ull(x: u64) -> u32 { if x == 0 { 0 } else { x.trailing_zeros() + 1 } }
#[no_mangle] pub extern "C" fn stdc_count_ones_ull(x: u64) -> u32 { x.count_ones() }
#[no_mangle] pub extern "C" fn stdc_count_zeros_ull(x: u64) -> u32 { x.count_zeros() }
#[no_mangle] pub extern "C" fn stdc_has_single_bit_ull(x: u64) -> i32 { (x != 0 && x & x.wrapping_sub(1) == 0) as i32 }
#[no_mangle] pub extern "C" fn stdc_bit_width_ull(x: u64) -> u32 { 64 - x.leading_zeros() }
#[no_mangle] pub extern "C" fn stdc_bit_floor_ull(x: u64) -> u64 { if x == 0 { 0 } else { (1 as u64) << (64 - 1 - x.leading_zeros()) } }
#[no_mangle] pub extern "C" fn stdc_bit_ceil_ull(x: u64) -> u64 { if x <= 1 { 1 } else { let w = 64 - (x - 1).leading_zeros(); if w >= 64 { 0 } else { (1 as u64) << w } } }
