// Reed-Solomon over GF(2^8), the RS8 codec used by Linux persistent_ram.
//
// The public layer deliberately exposes only block-sized encode/decode.  Zone
// layout owns where parity lives; this module owns the field arithmetic and
// the correction bound.  The primitive polynomial and first root match the
// reference defaults: 0x11d, roots alpha^0 .. alpha^(ecc_size-1).

use alloc::vec;
use alloc::vec::Vec;

struct Field {
    exp: [u8; 512],
    log: [u8; 256],
}

impl Field {
    fn new() -> Field {
        let mut f = Field { exp: [0; 512], log: [0; 256] };
        let mut x = 1u16;
        for i in 0..255usize {
            f.exp[i] = x as u8;
            f.log[x as usize] = i as u8;
            x <<= 1;
            if x & 0x100 != 0 { x ^= 0x11d; }
        }
        for i in 255..512 { f.exp[i] = f.exp[i - 255]; }
        f
    }

    fn mul(&self, a: u8, b: u8) -> u8 {
        if a == 0 || b == 0 { return 0; }
        self.exp[self.log[a as usize] as usize + self.log[b as usize] as usize]
    }

    fn div(&self, a: u8, b: u8) -> Option<u8> {
        if a == 0 { return Some(0); }
        if b == 0 { return None; }
        let la = self.log[a as usize] as i16;
        let lb = self.log[b as usize] as i16;
        Some(self.exp[(la - lb).rem_euclid(255) as usize])
    }

    fn pow(&self, a: u8, n: usize) -> u8 {
        if a == 0 { return if n == 0 { 1 } else { 0 }; }
        self.exp[(self.log[a as usize] as usize * n) % 255]
    }
}

fn generator(f: &Field, nsym: usize) -> [u8; 33] {
    let mut g = [0; 33];
    if nsym > 32 { return g; }
    g[0] = 1;
    for i in 0..nsym {
        let root = f.exp[i];
        for j in (1..=i + 1).rev() {
            g[j] ^= f.mul(g[j - 1], root);
        }
    }
    g
}

/// Encode `data` into the supplied parity bytes.
pub fn encode(data: &[u8], parity: &mut [u8]) {
    if parity.is_empty() || parity.len() > 32 { return; }
    let f = Field::new();
    let g = generator(&f, parity.len());
    parity.fill(0);
    for &byte in data {
        let feedback = byte ^ parity[0];
        parity.copy_within(1.., 0);
        let last = parity.len() - 1;
        parity[last] = 0;
        for j in 0..parity.len() {
            parity[j] ^= f.mul(g[j + 1], feedback);
        }
    }
}

fn evaluate(f: &Field, polynomial: &[u8], x: u8) -> u8 {
    let mut out = 0;
    for &byte in polynomial { out = f.mul(out, x) ^ byte; }
    out
}

/// Correct a codeword in place. Returns the number of corrected symbols, or
/// `None` when the corruption exceeds the configured RS correction bound.
pub fn decode(data: &mut [u8], parity: &mut [u8]) -> Option<usize> {
    if parity.is_empty() { return Some(0); }
    let f = Field::new();
    let nsym = parity.len();
    let mut codeword = Vec::with_capacity(data.len() + nsym);
    codeword.extend_from_slice(data);
    codeword.extend_from_slice(parity);

    let mut synd = vec![0u8; nsym];
    let mut nonzero = false;
    for (i, s) in synd.iter_mut().enumerate() {
        *s = evaluate(&f, &codeword, f.exp[i]);
        nonzero |= *s != 0;
    }
    if !nonzero { return Some(0); }

    // Berlekamp-Massey, with locator coefficients in ascending order.
    let mut locator = vec![0u8; nsym + 1];
    let mut old = vec![0u8; nsym + 1];
    locator[0] = 1;
    old[0] = 1;
    let mut degree = 0usize;
    let mut shift = 1usize;
    let mut scale = 1u8;
    for n in 0..nsym {
        let mut discrepancy = synd[n];
        for i in 1..=degree { discrepancy ^= f.mul(locator[i], synd[n - i]); }
        if discrepancy == 0 {
            shift += 1;
            continue;
        }
        let previous = locator.clone();
        let factor = f.div(discrepancy, scale)?;
        for i in 0..=nsym - shift {
            locator[i + shift] ^= f.mul(factor, old[i]);
        }
        if 2 * degree <= n {
            degree = n + 1 - degree;
            old = previous;
            scale = discrepancy;
            shift = 1;
        } else {
            shift += 1;
        }
    }
    if degree == 0 || degree > nsym / 2 { return None; }

    // A symbol at position p contributes X^k to syndrome k, where
    // X = alpha^(codeword_len - 1 - p).  With the ascending locator produced
    // above, the Chien evaluation uses that same field element.
    let ncode = codeword.len();
    let mut positions = Vec::with_capacity(degree);
    for p in 0..ncode {
        let exponent = (ncode - 1 - p) % 255;
        if evaluate(&f, &locator[..=degree], f.exp[exponent]) == 0 {
            positions.push(p);
        }
    }
    if positions.len() != degree { return None; }

    // Solve the Vandermonde system S_k = sum(error_j * X_j^k) directly.
    // This is small (the default corrects at most eight symbols) and avoids
    // making the zone layer depend on a second Forney-convention transform.
    let e = positions.len();
    let mut matrix = vec![vec![0u8; e + 1]; e];
    for row in 0..e {
        matrix[row][e] = synd[row];
        for (col, &p) in positions.iter().enumerate() {
            let x = f.pow(f.exp[(ncode - 1 - p) % 255], row);
            matrix[row][col] = x;
        }
    }
    for col in 0..e {
        let pivot = (col..e).find(|&row| matrix[row][col] != 0)?;
        matrix.swap(col, pivot);
        let inv = f.div(1, matrix[col][col])?;
        for j in col..=e { matrix[col][j] = f.mul(matrix[col][j], inv); }
        for row in 0..e {
            if row == col { continue; }
            let factor = matrix[row][col];
            if factor == 0 { continue; }
            for j in col..=e {
                matrix[row][j] ^= f.mul(factor, matrix[col][j]);
            }
        }
    }
    for (row, &p) in positions.iter().enumerate() {
        codeword[p] ^= matrix[row][e];
    }
    if syndromes_zero(&f, &codeword, nsym) {
        data.copy_from_slice(&codeword[..data.len()]);
        parity.copy_from_slice(&codeword[data.len()..]);
        Some(e)
    } else {
        None
    }
}

fn syndromes_zero(f: &Field, codeword: &[u8], nsym: usize) -> bool {
    (0..nsym).all(|i| evaluate(f, codeword, f.exp[i]) == 0)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use alloc::vec;
    use alloc::vec::Vec;

    #[test]
    fn corrects_eight_symbols() {
        let data: Vec<u8> = (0u8..128).map(|v| v.wrapping_mul(37)).collect();
        let mut parity = vec![0; 16];
        encode(&data, &mut parity);
        let original = data.clone();
        let mut damaged = data;
        for (i, mask) in [(0, 1), (7, 2), (19, 4), (31, 8), (64, 16), (88, 32), (111, 64), (127, 128)] {
            damaged[i] ^= mask;
        }
        assert_eq!(decode(&mut damaged, &mut parity), Some(8));
        assert_eq!(damaged, original);
    }

    #[test]
    fn refuses_nine_symbol_errors_for_sixteen_parity_symbols() {
        let mut data = vec![0x5a; 128];
        let mut parity = vec![0; 16];
        encode(&data, &mut parity);
        for i in 0..9 { data[i] ^= (i as u8) + 1; }
        assert_eq!(decode(&mut data, &mut parity), None);
    }
}
