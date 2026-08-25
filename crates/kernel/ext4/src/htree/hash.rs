const DX_HASH_LEGACY: u8 = 0;
const DX_HASH_HALF_MD4: u8 = 1;
const DX_HASH_TEA: u8 = 2;
const DX_HASH_LEGACY_UNSIGNED: u8 = 3;
const DX_HASH_HALF_MD4_UNSIGNED: u8 = 4;
const DX_HASH_TEA_UNSIGNED: u8 = 5;
const EXT4_HTREE_EOF_32: u32 = 0x7fff_ffff;

/// Compute the ext4 directory hash major value for `name`.
/// `version` is the dx_root's stored `hash_version`; `seed` is the fs
/// `s_hash_seed` (default constants used when all-zero).
/// # C: O(name.len())
pub fn dirhash_major(name: &[u8], version: u8, seed: &[u32; 4]) -> u32 {
    let mut buf: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];
    if seed.iter().any(|&w| w != 0) { buf = *seed; }
    let (mut major, _minor) = match version {
        DX_HASH_LEGACY | DX_HASH_LEGACY_UNSIGNED => (dx_hack_hash(name, version == DX_HASH_LEGACY), 0),
        DX_HASH_HALF_MD4 | DX_HASH_HALF_MD4_UNSIGNED => {
            let signed = version == DX_HASH_HALF_MD4;
            let mut p = name; let mut inb = [0u32; 8];
            loop { str2hashbuf(p, &mut inb, 8, signed); half_md4_transform(&mut buf, &inb);
                if p.len() <= 32 { break; } p = &p[32..]; }
            (buf[1], buf[2])
        }
        DX_HASH_TEA | DX_HASH_TEA_UNSIGNED => {
            let signed = version == DX_HASH_TEA;
            let mut p = name; let mut inb = [0u32; 4];
            loop { str2hashbuf(p, &mut inb, 4, signed); tea_transform(&mut buf, &inb);
                if p.len() <= 16 { break; } p = &p[16..]; }
            (buf[0], buf[1])
        }
        _ => (0, 0),
    };
    major &= !1;
    if major == (EXT4_HTREE_EOF_32 << 1) { major = (EXT4_HTREE_EOF_32 - 1) << 1; }
    major
}

const DELTA: u32 = 0x9E37_79B9;
fn tea_transform(buf: &mut [u32; 4], inb: &[u32]) {
    let mut sum = 0u32; let (mut b0, mut b1) = (buf[0], buf[1]);
    let (a, b, c, d) = (inb[0], inb[1], inb[2], inb[3]);
    for _ in 0..16 {
        sum = sum.wrapping_add(DELTA);
        b0 = b0.wrapping_add(((b1 << 4).wrapping_add(a)) ^ (b1.wrapping_add(sum)) ^ ((b1 >> 5).wrapping_add(b)));
        b1 = b1.wrapping_add(((b0 << 4).wrapping_add(c)) ^ (b0.wrapping_add(sum)) ^ ((b0 >> 5).wrapping_add(d)));
    }
    buf[0] = buf[0].wrapping_add(b0); buf[1] = buf[1].wrapping_add(b1);
}

#[inline] fn f(x: u32, y: u32, z: u32) -> u32 { z ^ (x & (y ^ z)) }
#[inline] fn g(x: u32, y: u32, z: u32) -> u32 { (x & y).wrapping_add((x ^ y) & z) }
#[inline] fn h(x: u32, y: u32, z: u32) -> u32 { x ^ y ^ z }
const K1: u32 = 0;
const K2: u32 = 0x5A82_7999;
const K3: u32 = 0x6ED9_EBA1;

fn half_md4_transform(buf: &mut [u32; 4], inb: &[u32; 8]) {
    let (mut a, mut b, mut c, mut d) = (buf[0], buf[1], buf[2], buf[3]);
    macro_rules! round { ($fn:ident, $a:ident, $b:ident, $c:ident, $d:ident, $x:expr, $s:expr) => {
        $a = $a.wrapping_add($fn($b, $c, $d)).wrapping_add($x); $a = ($a << $s) | ($a >> (32 - $s));
    }; }
    round!(f, a, b, c, d, inb[0].wrapping_add(K1), 3); round!(f, d, a, b, c, inb[1].wrapping_add(K1), 7);
    round!(f, c, d, a, b, inb[2].wrapping_add(K1), 11); round!(f, b, c, d, a, inb[3].wrapping_add(K1), 19);
    round!(f, a, b, c, d, inb[4].wrapping_add(K1), 3); round!(f, d, a, b, c, inb[5].wrapping_add(K1), 7);
    round!(f, c, d, a, b, inb[6].wrapping_add(K1), 11); round!(f, b, c, d, a, inb[7].wrapping_add(K1), 19);
    round!(g, a, b, c, d, inb[1].wrapping_add(K2), 3); round!(g, d, a, b, c, inb[3].wrapping_add(K2), 5);
    round!(g, c, d, a, b, inb[5].wrapping_add(K2), 9); round!(g, b, c, d, a, inb[7].wrapping_add(K2), 13);
    round!(g, a, b, c, d, inb[0].wrapping_add(K2), 3); round!(g, d, a, b, c, inb[2].wrapping_add(K2), 5);
    round!(g, c, d, a, b, inb[4].wrapping_add(K2), 9); round!(g, b, c, d, a, inb[6].wrapping_add(K2), 13);
    round!(h, a, b, c, d, inb[3].wrapping_add(K3), 3); round!(h, d, a, b, c, inb[7].wrapping_add(K3), 9);
    round!(h, c, d, a, b, inb[2].wrapping_add(K3), 11); round!(h, b, c, d, a, inb[6].wrapping_add(K3), 15);
    round!(h, a, b, c, d, inb[1].wrapping_add(K3), 3); round!(h, d, a, b, c, inb[5].wrapping_add(K3), 9);
    round!(h, c, d, a, b, inb[0].wrapping_add(K3), 11); round!(h, b, c, d, a, inb[4].wrapping_add(K3), 15);
    buf[0] = buf[0].wrapping_add(a); buf[1] = buf[1].wrapping_add(b);
    buf[2] = buf[2].wrapping_add(c); buf[3] = buf[3].wrapping_add(d);
}

fn str2hashbuf(msg: &[u8], out: &mut [u32], num: usize, signed: bool) {
    let mut pad = (msg.len() as u32) | ((msg.len() as u32) << 8); pad |= pad << 16;
    let mut val = pad; let len = msg.len().min(num * 4); let mut oi = 0; let mut written = 0;
    for (i, byte) in msg.iter().take(len).enumerate() {
        let cv = if signed { (*byte as i8) as i32 } else { *byte as i32 };
        val = (cv as u32).wrapping_add(val << 8);
        if i % 4 == 3 { out[oi] = val; oi += 1; written += 1; val = pad; }
    }
    if written < num { out[oi] = val; written += 1; }
    while written < num { out[written] = pad; written += 1; }
}

fn dx_hack_hash(name: &[u8], signed: bool) -> u32 {
    let (mut hash0, mut hash1) = (0x12a3fe2du32, 0x37abe8f9u32);
    for &b in name {
        let c = if signed { (b as i8) as i32 } else { b as i32 };
        let hash = hash1.wrapping_add(hash0 ^ (c as u32).wrapping_mul(7152373));
        hash1 = hash0; hash0 = if hash & 0x8000_0000 != 0 { hash.wrapping_sub(0x7fff_ffff) } else { hash };
    }
    hash0
}
