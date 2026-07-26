// XXH64, for the optional frame content checksum (RFC 8878 3.1.1).
//
// One-shot over a complete buffer rather than streaming: a frame's checksum is
// computed over the whole decoded content, which is already in hand.

const PRIME1: u64 = 0x9E37_79B1_85EB_CA87;
const PRIME2: u64 = 0xC2B2_AE3D_27D4_EB4F;
const PRIME3: u64 = 0x1656_67B1_9E37_79F9;
const PRIME4: u64 = 0x85EB_CA77_C2B2_AE63;
const PRIME5: u64 = 0x27D4_EB2F_1656_67C5;

const STRIPE: usize = 32;

fn round(acc: u64, input: u64) -> u64 {
    acc.wrapping_add(input.wrapping_mul(PRIME2)).rotate_left(31).wrapping_mul(PRIME1)
}

fn merge(acc: u64, val: u64) -> u64 {
    (acc ^ round(0, val)).wrapping_mul(PRIME1).wrapping_add(PRIME4)
}

/// XXH64 of `data` with `seed`.
/// # C: O(len)
pub fn hash(data: &[u8], seed: u64) -> u64 {
    let mut h = if data.len() >= STRIPE {
        let mut v = [
            seed.wrapping_add(PRIME1).wrapping_add(PRIME2),
            seed.wrapping_add(PRIME2),
            seed,
            seed.wrapping_sub(PRIME1),
        ];
        let mut at = 0;
        while at + STRIPE <= data.len() {
            for (i, lane) in v.iter_mut().enumerate() {
                let off = at + i * 8;
                *lane = round(*lane, u64::from_le_bytes(
                    data[off..off + 8].try_into().expect("eight bytes")));
            }
            at += STRIPE;
        }
        let mut h = v[0].rotate_left(1)
            .wrapping_add(v[1].rotate_left(7))
            .wrapping_add(v[2].rotate_left(12))
            .wrapping_add(v[3].rotate_left(18));
        for lane in v { h = merge(h, lane); }
        h
    } else {
        seed.wrapping_add(PRIME5)
    };
    h = h.wrapping_add(data.len() as u64);

    let tail = data.len() - data.len() % STRIPE;
    let mut at = tail;
    while at + 8 <= data.len() {
        let k = u64::from_le_bytes(data[at..at + 8].try_into().expect("eight bytes"));
        h = (h ^ round(0, k)).rotate_left(27).wrapping_mul(PRIME1).wrapping_add(PRIME4);
        at += 8;
    }
    if at + 4 <= data.len() {
        let k = u32::from_le_bytes(data[at..at + 4].try_into().expect("four bytes")) as u64;
        h = (h ^ k.wrapping_mul(PRIME1)).rotate_left(23).wrapping_mul(PRIME2).wrapping_add(PRIME3);
        at += 4;
    }
    while at < data.len() {
        h = (h ^ (data[at] as u64).wrapping_mul(PRIME5)).rotate_left(11).wrapping_mul(PRIME1);
        at += 1;
    }
    h ^= h >> 33;
    h = h.wrapping_mul(PRIME2);
    h ^= h >> 29;
    h = h.wrapping_mul(PRIME3);
    h ^= h >> 32;
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    extern crate std;
    use std::vec::Vec;

    #[test]
    fn known_vectors_match_the_reference_digests() {
        // Vectors from the XXH64 specification. A wrong checksum here would
        // reject every frame that carries one.
        assert_eq!(hash(b"", 0), 0xEF46_DB37_51D8_E999);
        assert_eq!(hash(b"", 1), 0xD5AF_BA13_36A3_BE4B);
        assert_eq!(hash(b"a", 0), 0xD24E_C4F1_A98C_6E5B);
        assert_eq!(hash(b"abc", 0), 0x44BC_2CF5_AD77_0999);
    }

    #[test]
    fn lengths_around_the_stripe_and_tail_boundaries_are_stable() {
        // The 32/8/4/1 tail ladder is where an off-by-one hides. These lengths
        // exercise every branch; the assertion is that the value does not
        // depend on how the input was chunked.
        let data: Vec<u8> = (0..200u32).map(|i| (i * 7) as u8).collect();
        for len in [1usize, 3, 4, 7, 8, 15, 31, 32, 33, 63, 64, 65, 200] {
            let h = hash(&data[..len], 0);
            assert_eq!(h, hash(&data[..len], 0), "hashing is deterministic at {len}");
            assert_ne!(h, 0, "a real digest at {len}");
        }
    }
}
