// The RSA key itself and the raw primitive. Padding lives in `pkcs1`.

use alloc::vec::Vec;

use mpi::Mpi;

use crate::der::{self, Reader, TAG_INTEGER, TAG_SEQUENCE};
use crate::PkeyError;

/// Modulus sizes in BITS that this kernel will use a key at. An RSA key of any
/// other size is refused when it is set, so an odd-sized key never reaches the
/// arithmetic: sizes outside this set are either too weak to be worth the
/// arithmetic or too large to bound the work a caller can ask for.
pub const RSA_KEY_SIZES: [usize; 6] = [512, 1024, 1536, 2048, 3072, 4096];

/// An RSA key. The private exponent is present only for a key that was parsed
/// from private material, and its absence is what makes sign and decrypt
/// EOPNOTSUPP rather than a wrong answer.
#[derive(Clone, Debug)]
pub struct RsaKey {
    n: Mpi,
    e: Mpi,
    d: Option<Mpi>,
    /// Modulus size in bytes — every padded block is exactly this wide.
    k: usize,
}

impl RsaKey {
    /// Build from raw big-endian components, applying the key-size rule.
    /// # C: O(len)
    pub fn new(n: &[u8], e: &[u8], d: Option<&[u8]>) -> Result<Self, PkeyError> {
        let n = Mpi::from_be_bytes(n);
        let e = Mpi::from_be_bytes(e);
        if n.is_zero() || e.is_zero() { return Err(PkeyError::BadKey); }
        let k = n.limb_size();
        if !RSA_KEY_SIZES.contains(&(k * 8)) { return Err(PkeyError::BadKey); }
        let d = match d {
            None => None,
            Some(b) => {
                let d = Mpi::from_be_bytes(b);
                if d.is_zero() { return Err(PkeyError::BadKey); }
                Some(d)
            }
        };
        Ok(Self { n, e, d, k })
    }

    /// Modulus size in bytes. # C: O(1)
    pub fn size(&self) -> usize { self.k }

    /// Modulus size in bits — what the query reports as the key size.
    /// # C: O(1)
    pub fn bits(&self) -> usize { self.k * 8 }

    /// Whether private operations are available. # C: O(1)
    pub fn is_private(&self) -> bool { self.d.is_some() }

    /// The public primitive `m^e mod n`, zero-padded to the modulus width. An
    /// input that is not less than the modulus has no representative and is
    /// refused rather than silently reduced. # C: O(bits(e) * limbs(n)^2)
    pub fn public_op(&self, input: &[u8]) -> Result<Vec<u8>, PkeyError> {
        self.primitive(input, &self.e)
    }

    /// The private primitive `c^d mod n`. # C: O(bits(d) * limbs(n)^2)
    pub fn private_op(&self, input: &[u8]) -> Result<Vec<u8>, PkeyError> {
        let d = self.d.as_ref().ok_or(PkeyError::NoPrivateKey)?;
        self.primitive(input, d)
    }

    fn primitive(&self, input: &[u8], exp: &Mpi) -> Result<Vec<u8>, PkeyError> {
        let m = Mpi::from_be_bytes(input);
        if m >= self.n { return Err(PkeyError::Invalid); }
        let c = m.powm(exp, &self.n).ok_or(PkeyError::Invalid)?;
        c.to_be_bytes(self.k).ok_or(PkeyError::Invalid)
    }
}

/// `RSAPublicKey ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }`.
/// # C: O(len)
pub fn parse_public(der_bytes: &[u8]) -> Result<RsaKey, PkeyError> {
    let body = der::parse_exact(der_bytes, TAG_SEQUENCE)?;
    let mut r = Reader::new(body);
    let n = der::positive_integer(r.expect(TAG_INTEGER)?)?;
    let e = der::positive_integer(r.expect(TAG_INTEGER)?)?;
    r.end()?;
    RsaKey::new(n, e, None)
}

/// `RSAPrivateKey ::= SEQUENCE { version INTEGER, modulus INTEGER,
/// publicExponent INTEGER, privateExponent INTEGER, prime1, prime2,
/// exponent1, exponent2, coefficient }`. The primes are read past but not
/// retained: the Chinese-remainder speedup is an optimisation, and holding a
/// second copy of the key's secrets to implement it would be a second thing
/// to keep consistent. # C: O(len)
pub fn parse_private(der_bytes: &[u8]) -> Result<RsaKey, PkeyError> {
    let body = der::parse_exact(der_bytes, TAG_SEQUENCE)?;
    let mut r = Reader::new(body);
    let version = der::positive_integer(r.expect(TAG_INTEGER)?)?;
    // Version 1 is a multi-prime key, whose extra primes this does not read.
    if version != [0] { return Err(PkeyError::BadKey); }
    let n = der::positive_integer(r.expect(TAG_INTEGER)?)?;
    let e = der::positive_integer(r.expect(TAG_INTEGER)?)?;
    let d = der::positive_integer(r.expect(TAG_INTEGER)?)?;
    RsaKey::new(n, e, Some(d))
}
