// The parsed key a caller holds, and the one place an encoding name plus an
// operation becomes a calculation.

use alloc::string::String;
use alloc::vec::Vec;

use crate::pkcs1::{self, HashPrefix};
use crate::rsa::{self, RsaKey};
use crate::{pkcs8, x509, PkeyError};

/// Encoding names. `raw` means the caller supplies and receives unpadded
/// values; `pkcs1` selects the v1.5 encodings.
pub const ENCODING_RAW: &str = "raw";
pub const ENCODING_PKCS1: &str = "pkcs1";
/// The digest name a signature encoding uses when the caller names none: the
/// empty DigestInfo prefix, i.e. the caller signs a bare value.
pub const HASH_NONE: &str = "none";

/// The four operations a key can be asked for.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Operation { Encrypt, Decrypt, Sign, Verify }

/// What a key can do and how wide its inputs and outputs are.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct KeyQuery {
    /// Key size in BITS.
    pub key_size: u32,
    /// Largest raw input a signature operation accepts.
    pub max_data_size: u16,
    pub max_sig_size: u16,
    pub max_enc_size: u16,
    pub max_dec_size: u16,
    pub can_encrypt: bool,
    pub can_decrypt: bool,
    pub can_sign: bool,
    pub can_verify: bool,
}

/// A parsed asymmetric key.
pub struct AsymmetricKey {
    /// Public-key algorithm name.
    pub algo: &'static str,
    /// The blob format the key came in — what the key subsystem reports as
    /// the identifier type.
    pub id_type: &'static str,
    /// A name the blob proposes for itself, used when the caller supplies
    /// none. A private-key blob carries no name, so it has none to propose.
    pub description: Option<String>,
    /// Certificate identifiers retained by the keyring for `id:` / `ex:`
    /// search. Private-key blobs have none.
    pub ids: Vec<Vec<u8>>,
    key: RsaKey,
}

/// The `X509` identifier type.
pub const ID_TYPE_X509: &str = "X509";
/// The `PKCS8` identifier type.
pub const ID_TYPE_PKCS8: &str = "PKCS8";

impl AsymmetricKey {
    /// Parse a key blob, trying each format the kernel knows in registration
    /// order. A blob that is neither is not a key — the LAST parser's
    /// complaint is not reported, because "this is not a PKCS#8 key" says
    /// nothing useful about a corrupt certificate. # C: O(len)
    pub fn parse(blob: &[u8]) -> Result<Self, PkeyError> {
        if let Ok(cert) = x509::parse(blob) {
            if cert.algo != "rsa" { return Err(PkeyError::NoPackage); }
            let key = rsa::parse_public(&cert.key)?;
            // The name a certificate proposes is its subject followed by the
            // subject key identifier, or the serial number when it has none.
            let mut ids = Vec::new();
            if let Some(skid) = cert.skid.as_ref() { ids.push(skid.clone()); }
            ids.push(cert.serial.clone());
            let mut desc = cert.subject;
            desc.push_str(": ");
            let id = cert.skid.unwrap_or(cert.serial);
            for b in &id { push_hex(&mut desc, *b); }
            return Ok(Self { algo: cert.algo, id_type: ID_TYPE_X509, description: Some(desc), ids, key });
        }
        let (algo, private) = pkcs8::parse(blob)?;
        if algo != "rsa" { return Err(PkeyError::NoPackage); }
        let key = rsa::parse_private(&private)?;
        Ok(Self { algo, id_type: ID_TYPE_PKCS8, description: None, ids: Vec::new(), key })
    }

    /// Whether this key can perform private operations. # C: O(1)
    pub fn is_private(&self) -> bool { self.key.is_private() }

    /// Describe what the key supports under `encoding`/`hash`.
    ///
    /// The encoding is what decides the answer: `raw` gives an unpadded
    /// primitive that can encrypt and decrypt but cannot express a signature,
    /// while `pkcs1` adds signing and verification. A hash name is meaningful
    /// only to a signature encoding — naming one alongside `raw` is a
    /// contradiction rather than a harmless extra. # C: O(1)
    pub fn query(&self, encoding: &str, hash: Option<&str>) -> Result<KeyQuery, PkeyError> {
        let scheme = self.resolve(encoding, hash, Operation::Sign)?;
        let k = self.key.size() as u16;
        let private = self.key.is_private();
        Ok(match scheme {
            Scheme::Raw => KeyQuery {
                key_size: self.key.bits() as u32,
                max_data_size: k, max_sig_size: k, max_enc_size: k, max_dec_size: k,
                can_encrypt: true, can_decrypt: private, can_sign: false, can_verify: false,
            },
            Scheme::Pkcs1(_) => KeyQuery {
                key_size: self.key.bits() as u32,
                max_data_size: k, max_sig_size: k, max_enc_size: k, max_dec_size: k,
                can_encrypt: true, can_decrypt: private, can_sign: private, can_verify: true,
            },
        })
    }

    /// Encrypt, decrypt or sign. `rand` supplies the encryption padding, which
    /// must be unpredictable — the same message must not encrypt to the same
    /// ciphertext twice. # C: O(rsa)
    pub fn eds<R: FnMut(&mut [u8])>(&self, op: Operation, encoding: &str, hash: Option<&str>,
        input: &[u8], rand: R) -> Result<Vec<u8>, PkeyError>
    {
        let scheme = self.resolve(encoding, hash, op)?;
        match (op, scheme) {
            (Operation::Encrypt, Scheme::Raw) => self.key.public_op(input),
            (Operation::Decrypt, Scheme::Raw) => self.key.private_op(input),
            (Operation::Encrypt, Scheme::Pkcs1(_)) => pkcs1::encrypt(&self.key, input, rand),
            (Operation::Decrypt, Scheme::Pkcs1(_)) => pkcs1::decrypt(&self.key, input),
            (Operation::Sign, Scheme::Pkcs1(p)) => pkcs1::sign(&self.key, p, input),
            // A raw primitive has no way to say "this is a signature", so
            // signing without an encoding is not a weaker signature, it is not
            // one at all.
            (Operation::Sign, Scheme::Raw) => Err(PkeyError::Invalid),
            (Operation::Verify, _) => Err(PkeyError::Unsupported),
        }
    }

    /// Verify `sig` over `digest`. # C: O(rsa)
    pub fn verify(&self, encoding: &str, hash: Option<&str>, digest: &[u8], sig: &[u8])
        -> Result<(), PkeyError>
    {
        match self.resolve(encoding, hash, Operation::Verify)? {
            Scheme::Pkcs1(p) => pkcs1::verify(&self.key, p, sig, digest),
            // There is no registered signature algorithm for an unencoded RSA
            // value, so there is nothing to verify with.
            Scheme::Raw => Err(PkeyError::NoAlgorithm),
        }
    }

    /// Which calculation an encoding and operation select.
    ///
    /// A signature encoding is selected for signing and verification only; the
    /// same `pkcs1` name asks for the encryption encoding when the operation
    /// is encrypt or decrypt, which is why the hash name is accepted but
    /// unused there. # C: O(prefixes)
    fn resolve(&self, encoding: &str, hash: Option<&str>, op: Operation)
        -> Result<Scheme, PkeyError>
    {
        if self.algo != "rsa" { return Err(PkeyError::NoPackage); }
        match encoding {
            ENCODING_PKCS1 => {
                if matches!(op, Operation::Sign | Operation::Verify) {
                    let name = hash.unwrap_or(HASH_NONE);
                    let p = pkcs1::hash_prefix(name).ok_or(PkeyError::NoAlgorithm)?;
                    Ok(Scheme::Pkcs1(p))
                } else {
                    Ok(Scheme::Pkcs1(pkcs1::hash_prefix(HASH_NONE).expect("the empty prefix is always present")))
                }
            }
            // Unpadded RSA cannot distinguish one digest algorithm from
            // another, so naming one is a request the encoding cannot honour.
            ENCODING_RAW => if hash.is_some() { Err(PkeyError::Invalid) } else { Ok(Scheme::Raw) },
            _ => Err(PkeyError::Invalid),
        }
    }
}

/// The calculation an encoding selects.
#[derive(Copy, Clone)]
enum Scheme {
    Raw,
    Pkcs1(&'static HashPrefix),
}

fn push_hex(s: &mut String, b: u8) {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    s.push(DIGITS[(b >> 4) as usize] as char);
    s.push(DIGITS[(b & 0xf) as usize] as char);
}
