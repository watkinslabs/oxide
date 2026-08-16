//! Tuple hashing. Two hashes exist and they are not interchangeable:
//! the conntrack table hash mixes the whole tuple, while the NAT
//! source hash mixes only the source end plus the protocol, so every
//! flow from one client lands in the same bucket and a prior source
//! mapping can be found again.

use crate::tuple::{Tuple, addr_len};

const JHASH_INITVAL: u32 = 0xdeadbeef;

#[inline]
fn rol32(v: u32, n: u32) -> u32 { v.rotate_left(n) }

#[inline]
fn mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *a = a.wrapping_sub(*c); *a ^= rol32(*c, 4);  *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a); *b ^= rol32(*a, 6);  *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b); *c ^= rol32(*b, 8);  *b = b.wrapping_add(*a);
    *a = a.wrapping_sub(*c); *a ^= rol32(*c, 16); *c = c.wrapping_add(*b);
    *b = b.wrapping_sub(*a); *b ^= rol32(*a, 19); *a = a.wrapping_add(*c);
    *c = c.wrapping_sub(*b); *c ^= rol32(*b, 4);  *b = b.wrapping_add(*a);
}

#[inline]
fn final_mix(a: &mut u32, b: &mut u32, c: &mut u32) {
    *c ^= *b; *c = c.wrapping_sub(rol32(*b, 14));
    *a ^= *c; *a = a.wrapping_sub(rol32(*c, 11));
    *b ^= *a; *b = b.wrapping_sub(rol32(*a, 25));
    *c ^= *b; *c = c.wrapping_sub(rol32(*b, 16));
    *a ^= *c; *a = a.wrapping_sub(rol32(*c, 4));
    *b ^= *a; *b = b.wrapping_sub(rol32(*a, 14));
    *c ^= *b; *c = c.wrapping_sub(rol32(*b, 24));
}

/// Jenkins hash over a 32-bit word sequence — the same construction the
/// reference's tuple hashes are built on, so bucket spread has the same
/// characteristics rather than the collision profile of an ad-hoc mix.
/// # C: O(N_words)
pub fn jhash2(words: &[u32], initval: u32) -> u32 {
    let mut a = JHASH_INITVAL.wrapping_add((words.len() as u32) << 2).wrapping_add(initval);
    let mut b = a;
    let mut c = a;
    let mut i = 0;
    while i + 3 < words.len() {
        a = a.wrapping_add(words[i]);
        b = b.wrapping_add(words[i + 1]);
        c = c.wrapping_add(words[i + 2]);
        mix(&mut a, &mut b, &mut c);
        i += 3;
    }
    match words.len() - i {
        3 => { c = c.wrapping_add(words[i + 2]);
               b = b.wrapping_add(words[i + 1]);
               a = a.wrapping_add(words[i]); final_mix(&mut a, &mut b, &mut c); }
        2 => { b = b.wrapping_add(words[i + 1]);
               a = a.wrapping_add(words[i]); final_mix(&mut a, &mut b, &mut c); }
        1 => { a = a.wrapping_add(words[i]); final_mix(&mut a, &mut b, &mut c); }
        _ => {}
    }
    c
}

fn addr_words(bytes: &[u8], out: &mut [u32; 4]) -> usize {
    let n = bytes.len() / 4;
    for (i, slot) in out.iter_mut().take(n).enumerate() {
        *slot = u32::from_be_bytes([bytes[i * 4], bytes[i * 4 + 1],
                                    bytes[i * 4 + 2], bytes[i * 4 + 3]]);
    }
    n
}

/// Whole-tuple hash used by the conntrack table. Every field that
/// distinguishes two flows participates: dropping one (the zone, the
/// destination port, the protocol) merges distinct connections into one
/// bucket entry and lets a packet match the wrong flow.
/// # C: O(1)
pub fn tuple_hash(t: &Tuple, seed: u32) -> u32 {
    let mut words = [0u32; 12];
    let mut n = 0;
    let alen = addr_len(t.l3num);
    let mut tmp = [0u32; 4];
    let k = addr_words(&t.src.addr.0[..alen], &mut tmp);
    words[n..n + k].copy_from_slice(&tmp[..k]); n += k;
    let k = addr_words(&t.dst.addr.0[..alen], &mut tmp);
    words[n..n + k].copy_from_slice(&tmp[..k]); n += k;
    words[n] = ((t.src.proto.port as u32) << 16) | (t.dst.proto.port as u32); n += 1;
    words[n] = ((t.dst.proto.icmp_type as u32) << 24)
        | ((t.dst.proto.icmp_code as u32) << 16)
        | ((t.protonum as u32) << 8) | (t.l3num as u32); n += 1;
    words[n] = t.zone as u32; n += 1;
    jhash2(&words[..n], seed)
}

/// Source-only hash for the NAT bysource table. It deliberately excludes the
/// destination so that every flow from the same client/port collides into one
/// bucket — that collision is the mechanism by which a previously chosen
/// source mapping is found and reused.
/// # C: O(1)
pub fn src_hash(t: &Tuple, seed: u32) -> u32 {
    let mut words = [0u32; 7];
    let mut n = 0;
    let alen = addr_len(t.l3num);
    let mut tmp = [0u32; 4];
    let k = addr_words(&t.src.addr.0[..alen], &mut tmp);
    words[n..n + k].copy_from_slice(&tmp[..k]); n += k;
    words[n] = t.src.proto.port as u32; n += 1;
    words[n] = ((t.protonum as u32) << 8) | (t.l3num as u32); n += 1;
    words[n] = t.zone as u32; n += 1;
    jhash2(&words[..n], seed)
}

/// Map a hash onto `0..range` without a modulo bias toward low buckets —
/// the reference's `reciprocal_scale`. # C: O(1)
pub fn reciprocal_scale(val: u32, range: u32) -> u32 {
    (((val as u64) * (range as u64)) >> 32) as u32
}
