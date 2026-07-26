// SMix1/SMix2/SMix orchestration (alg-yescrypt-opt.c smix1/smix2/smix),
// p==1 only (see `kdf.rs` for why: yescrypt's own smix() "second pass" for
// p>1 reads V in the OTHER mode's word convention, which we don't
// implement — real `$y$` hashes, and every hash gensalt_yescrypt_rn ever
// produces, use p=1, so this is not a real-world gap).
extern crate alloc;
use alloc::vec::Vec;
use super::salsa::{Block, block_from_bytes, block_to_bytes, shuffle, unshuffle, integerify, blockmix_salsa8, blockmix_salsa8_xor, p2floor};
use super::pwxform::{PwxCtx, SBYTES, blockmix_pwx, blockmix_xor_pwx, blockmix_xor_save_pwx};

// Every SMix1/SMix2 call shuffles at load and unshuffles at store,
// UNCONDITIONALLY (matching the reference exactly) — including classic-mode
// calls, whose intermediate (non-final) V entries are consumed directly as
// raw bytes by S-box seeding (see salsa.rs's `blockmix_salsa8` doc).
fn store_slot(b: &mut [u8], slot: &[Block]) {
    for (i, blk) in slot.iter().enumerate() {
        let natural = unshuffle(blk);
        block_to_bytes(&natural, &mut b[i * 64..i * 64 + 64]);
    }
}

fn load_slot(b: &[u8], s: usize) -> Vec<Block> {
    (0..s).map(|i| shuffle(&block_from_bytes(&b[i * 64..i * 64 + 64]))).collect()
}

/// SMix1: fills `v` (`n` slots of `2r` blocks each) and leaves the SMix1
/// result written back into `b` (`128*r` bytes). `ctx=None` is classic
/// scrypt block-mixing (also used for WORM and for S-box seeding);
/// `ctx=Some` is yescrypt-RW pwxform mixing.
/// # C: O(r*n)
pub fn smix1(b: &mut [u8], r: usize, n: u32, ctx: Option<&mut PwxCtx>) -> Vec<Block> {
    let s = 2 * r;
    let mut v: Vec<Block> = Vec::with_capacity(s * n as usize);
    let mut cur = load_slot(b, s);
    v.extend_from_slice(&cur);

    let final_out = match ctx {
        None => {
            for _ in 1..n {
                cur = blockmix_salsa8(&cur);
                v.extend_from_slice(&cur);
            }
            blockmix_salsa8(&cur)
        }
        Some(ctx) => {
            let mut y = blockmix_pwx(&cur, ctx);
            v.extend_from_slice(&y);
            cur = blockmix_pwx(&y, ctx);
            v.extend_from_slice(&cur);
            let mut j = integerify(&cur[s - 1]);

            let mut np: u32 = 2;
            while np < n {
                let m = if np < n / 2 { np } else { n - 1 - np };
                let mut i = 1u32;
                while i < m {
                    j = (j & (np - 1)) + (i - 1);
                    let (new_y, j1) = blockmix_xor_pwx(&cur, &v[(j as usize) * s..(j as usize + 1) * s], ctx);
                    v.extend_from_slice(&new_y);
                    y = new_y;
                    j = j1;

                    j = (j & (np - 1)) + i;
                    let (new_x, j2) = blockmix_xor_pwx(&y, &v[(j as usize) * s..(j as usize + 1) * s], ctx);
                    v.extend_from_slice(&new_x);
                    cur = new_x;
                    j = j2;

                    i += 2;
                }
                np <<= 1;
            }
            np >>= 1;
            j = (j & (np - 1)) + (n - 2 - np);
            let (new_y, j1) = blockmix_xor_pwx(&cur, &v[(j as usize) * s..(j as usize + 1) * s], ctx);
            v.extend_from_slice(&new_y);
            y = new_y;
            j = j1;
            j = (j & (np - 1)) + (n - 1 - np);
            let (final_out, _) = blockmix_xor_pwx(&y, &v[(j as usize) * s..(j as usize + 1) * s], ctx);
            final_out
        }
    };
    store_slot(b, &final_out);
    v
}

/// SMix2: `Nloop` sequential (optionally random-read/write) blockmix steps
/// starting from `b`'s current content, final result written back to `b`.
/// `v` has `n` slots; RW mode mutates `v[j]` slots in place ("_save").
/// # C: O(r*nloop)
pub fn smix2(b: &mut [u8], r: usize, n: u32, nloop: u64, v: &mut [Block], ctx: Option<&mut PwxCtx>) {
    if nloop == 0 { return; }
    let s = 2 * r;
    let mut cur = load_slot(b, s);
    let mut j = (integerify(&cur[s - 1]) as u64 & (n as u64 - 1)) as u32;

    match ctx {
        None => {
            for _ in 0..nloop {
                let (new_val, j1) = blockmix_salsa8_xor(&cur, &v[(j as usize) * s..(j as usize + 1) * s]);
                cur = new_val;
                j = j1 & (n - 1);
            }
        }
        Some(ctx) => {
            for _ in 0..nloop {
                let jn = blockmix_xor_save_pwx(&mut cur, &mut v[(j as usize) * s..(j as usize + 1) * s], ctx);
                j = jn & (n - 1);
            }
        }
    }
    store_slot(b, &cur);
}

/// Seed a pwxform S-box: a classic-scrypt SMix1(r=1, N=Sbytes/128) pass
/// using `bp_head` (the first 128 bytes of a stream's B chunk) as input,
/// which is ALSO mutated in place (matches alg-yescrypt-opt.c smix()'s
/// `smix1(Bp, 1, Sbytes/128, 0, Si, ...)` call).
/// # C: O(Sbytes)
fn seed_sbox(bp_head: &mut [u8]) -> Vec<u8> {
    let n = (SBYTES / 128) as u32;
    let v = smix1(bp_head, 1, n, None);
    let mut sbox = alloc::vec![0u8; SBYTES];
    for (i, blk) in v.iter().enumerate() { block_to_bytes(blk, &mut sbox[i * 64..i * 64 + 64]); }
    sbox
}

/// Top-level SMix (p==1 only): `b` is `128*r` bytes, mutated to the final
/// SMix result. `passwd` is the running 32-byte "sha256" key (mutated via
/// the RW S-box-seeding HMAC step, matching yescrypt_kdf_body's `passwd`).
/// # C: O(r*n)
pub fn smix(b: &mut [u8], r: usize, n: u32, t: u32, rw: bool, passwd: &mut [u8; 32]) {
    let nchunk = n;
    let mut nloop_all: u64 = nchunk as u64;
    if rw {
        if t <= 1 {
            if t != 0 { nloop_all *= 2; }
            nloop_all = (nloop_all + 2) / 3;
        } else {
            nloop_all *= (t - 1) as u64;
        }
    } else if t != 0 {
        if t == 1 { nloop_all += (nloop_all + 1) / 2; }
        nloop_all *= t as u64;
    }
    let mut nloop_rw: u64 = if rw { nloop_all } else { 0 };
    nloop_all += 1; nloop_all &= !1u64;
    nloop_rw += 1; nloop_rw &= !1u64;

    if rw {
        let sbox = seed_sbox(&mut b[0..128]);
        let mut ctx = PwxCtx::new(sbox);
        let key = b[(128 * r - 64)..128 * r].to_vec();
        *passwd = super::hmac::hmac_sha256(&key, passwd);
        let mut v = smix1(b, r, n, Some(&mut ctx));
        smix2(b, r, p2floor(n as u64) as u32, nloop_rw, &mut v, Some(&mut ctx));
    } else {
        let mut v = smix1(b, r, n, None);
        smix2(b, r, p2floor(n as u64) as u32, nloop_rw, &mut v, None);
        if nloop_all > nloop_rw {
            smix2(b, r, n, nloop_all - nloop_rw, &mut v, None);
        }
    }
}

#[cfg(test)]
mod tests {
    /// RFC 7914 §12 test vector #1: scrypt("", "", N=16, r=1, p=1, 64).
    /// Validates blockmix_salsa8/smix1/smix2's classic path end-to-end,
    /// independent of yescrypt's pwxform/RW machinery entirely.
    #[test]
    fn classic_scrypt_matches_rfc7914_vector1() {
        let dk = crate::yescrypt::kdf::classic_scrypt(b"", b"", 16, 1, 1, 64);
        let want: [u8; 64] = [
            0x77, 0xd6, 0x57, 0x62, 0x38, 0x65, 0x7b, 0x20, 0x3b, 0x19, 0xca, 0x42, 0xc1, 0x8a,
            0x04, 0x97, 0xf1, 0x6b, 0x48, 0x44, 0xe3, 0x07, 0x4a, 0xe8, 0xdf, 0xdf, 0xfa, 0x3f,
            0xed, 0xe2, 0x14, 0x42, 0xfc, 0xd0, 0x06, 0x9d, 0xed, 0x09, 0x48, 0xf8, 0x32, 0x6a,
            0x75, 0x3a, 0x0f, 0xc8, 0x1f, 0x17, 0xe8, 0xd3, 0xe0, 0xfb, 0x2e, 0x0d, 0x36, 0x28,
            0xcf, 0x35, 0xe2, 0x0c, 0x38, 0xd1, 0x89, 0x06,
        ];
        assert_eq!(dk, want);
    }

    /// RFC 7914 §12 test vector #3: scrypt("password","NaCl",N=1024,r=8,p=16,64).
    #[test]
    fn classic_scrypt_matches_rfc7914_vector3() {
        let dk = crate::yescrypt::kdf::classic_scrypt(b"password", b"NaCl", 1024, 8, 16, 64);
        let want: [u8; 64] = [
            0xfd, 0xba, 0xbe, 0x1c, 0x9d, 0x34, 0x72, 0x00, 0x78, 0x56, 0xe7, 0x19, 0x0d, 0x01,
            0xe9, 0xfe, 0x7c, 0x6a, 0xd7, 0xcb, 0xc8, 0x23, 0x78, 0x30, 0xe7, 0x73, 0x76, 0x63,
            0x4b, 0x37, 0x31, 0x62, 0x2e, 0xaf, 0x30, 0xd9, 0x2e, 0x22, 0xa3, 0x88, 0x6f, 0xf1,
            0x09, 0x27, 0x9d, 0x98, 0x30, 0xda, 0xc7, 0x27, 0xaf, 0xb9, 0x4a, 0x83, 0xee, 0x6d,
            0x83, 0x60, 0xcb, 0xdf, 0xa2, 0xcc, 0x06, 0x40,
        ];
        assert_eq!(dk, want);
    }
}
