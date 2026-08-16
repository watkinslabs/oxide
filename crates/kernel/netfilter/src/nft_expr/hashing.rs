//! Byte-oriented Jenkins hash. The word-oriented form the conntrack table
//! uses cannot serve here: a `hash` expression hashes an arbitrary byte span
//! whose length need not be a whole number of words, and the tail handling is
//! what makes two spans of different length hash differently.

/// # C: O(1)
fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c); *a ^= c.rotate_left(4);  *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a); *b ^= a.rotate_left(6);  *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b); *c ^= b.rotate_left(8);  *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c); *a ^= c.rotate_left(16); *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a); *b ^= a.rotate_left(19); *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b); *c ^= b.rotate_left(4);  *b = b.wrapping_add(*a);
}

/// # C: O(1)
fn final_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b; *c = c.wrapping_sub(b.rotate_left(14));
    *a ^= *c; *a = a.wrapping_sub(c.rotate_left(11));
    *b ^= *a; *b = b.wrapping_sub(a.rotate_left(25));
    *c ^= *b; *c = c.wrapping_sub(b.rotate_left(16));
    *a ^= *c; *a = a.wrapping_sub(c.rotate_left(4));
    *b ^= *a; *b = b.wrapping_sub(a.rotate_left(14));
    *c ^= *b; *c = c.wrapping_sub(b.rotate_left(24));
}

const JHASH_INITVAL: u32 = 0xdead_beef;

/// # C: O(1)
fn word(k: &[u8], at: usize) -> u32 {
    u32::from_ne_bytes([k[at], k[at + 1], k[at + 2], k[at + 3]])
}

/// Jenkins hash over a byte span. # C: O(len)
pub fn jhash(key: &[u8], initval: u32) -> u32 {
    let seed = JHASH_INITVAL.wrapping_add(key.len() as u32).wrapping_add(initval);
    let (mut a, mut b, mut c) = (seed, seed, seed);
    let mut k = key;
    while k.len() > 12 {
        a = a.wrapping_add(word(k, 0));
        b = b.wrapping_add(word(k, 4));
        c = c.wrapping_add(word(k, 8));
        mix(&mut a, &mut b, &mut c);
        k = &k[12..];
    }
    if k.is_empty() { return c; }
    for (i, &byte) in k.iter().enumerate() {
        let shift = (i % 4) as u32 * 8;
        let add = (byte as u32) << shift;
        match i / 4 { 0 => a = a.wrapping_add(add),
                      1 => b = b.wrapping_add(add),
                      _ => c = c.wrapping_add(add) }
    }
    final_mix(&mut a, &mut b, &mut c);
    c
}

/// Map a hash onto `0..range` without the low-bucket bias a modulo has.
/// # C: O(1)
pub fn reciprocal_scale(value: u32, range: u32) -> u32 {
    (((value as u64) * (range as u64)) >> 32) as u32
}
