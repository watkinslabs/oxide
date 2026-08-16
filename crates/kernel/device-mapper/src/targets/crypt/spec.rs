//! Parsing the cipher specification and the key a `crypt` table line carries.
//!
//! The whole grammar is here and nothing else parses it, because the cipher
//! string decides how the key is split — and a key split the wrong way
//! produces a device that encrypts consistently and decrypts nothing anyone
//! else wrote.

extern crate alloc;
use alloc::string::{String, ToString};
use alloc::vec::Vec;

use syscall::errno::Errno;

use crate::target::DmResult;

/// Chaining mode named by the middle field of a cipher specification.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ChainMode {
    /// Cipher-block chaining, the mode a first-generation encrypted volume uses.
    Cbc,
    /// Tweakable narrow-block mode, what a modern encrypted volume uses.
    Xts,
    /// Electronic codebook. Present because the grammar admits it; a volume
    /// written with it leaks its own structure.
    Ecb,
}

/// How the initialisation vector for a sector is produced.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IvMode {
    /// Low 32 bits of the sector number, little endian, in the first word.
    Plain,
    /// The whole sector number, little endian, in the first eight bytes.
    Plain64,
    /// The whole sector number, big endian, in the LAST eight bytes.
    Plain64Be,
    /// All zeros.
    Null,
    /// Big-endian `(sector << shift) + 1` in the last eight bytes, for a
    /// cipher whose block is smaller than a sector.
    Benbi,
    /// The sector number encrypted under a key derived by hashing the bulk
    /// key, so the IV is unpredictable without the key.
    Essiv(String),
    /// The sector's byte offset encrypted under the bulk key itself.
    Eboiv,
}

/// A parsed cipher specification.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CipherSpec {
    /// Bulk cipher name; only `aes` is implemented.
    pub cipher: String,
    /// Keys the cipher string asked to be cut from the key material.
    pub key_count: u32,
    /// Chaining mode.
    pub chain: ChainMode,
    /// Initialisation-vector generator.
    pub iv: IvMode,
    /// The text as given, echoed by the table report so a reload reproduces it.
    pub text: String,
}

/// Parse `<cipher>[:<keycount>]-<chainmode>-<ivmode>[:<ivopts>]`.
///
/// Split from the LEFT for the cipher and from the RIGHT for the IV mode: a
/// cipher name may contain a dash, and so may an IV option, but the chaining
/// mode never does. # C: O(s.len())
pub fn parse_cipher(s: &str) -> DmResult<CipherSpec> {
    let (head, rest) = s.split_once('-').ok_or(Errno::Einval)?;
    let (chain_str, iv_str) = rest.split_once('-').ok_or(Errno::Einval)?;

    let (cipher, key_count) = match head.split_once(':') {
        Some((c, n)) => (c, crate::args::parse_u32(n).ok_or(Errno::Einval)?),
        None => (head, 1),
    };
    if key_count == 0 { return Err(Errno::Einval); }

    let chain = match chain_str {
        "cbc" => ChainMode::Cbc,
        "xts" => ChainMode::Xts,
        "ecb" => ChainMode::Ecb,
        _ => return Err(Errno::Einval),
    };

    let (iv_name, iv_opts) = match iv_str.split_once(':') {
        Some((n, o)) => (n, Some(o)),
        None => (iv_str, None),
    };
    let iv = match iv_name {
        "plain" => IvMode::Plain,
        "plain64" => IvMode::Plain64,
        "plain64be" => IvMode::Plain64Be,
        "null" => IvMode::Null,
        "benbi" => IvMode::Benbi,
        "eboiv" => IvMode::Eboiv,
        // The hash is not optional: it selects the key the sector number is
        // encrypted under, so two volumes differing only in it are different
        // volumes.
        "essiv" => IvMode::Essiv(iv_opts.ok_or(Errno::Einval)?.to_string()),
        _ => return Err(Errno::Enotsup),
    };

    Ok(CipherSpec { cipher: cipher.to_string(), key_count, chain, iv, text: s.to_string() })
}

/// How the key was given on the table line.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum KeySource {
    /// Literal key bytes, written as hex.
    Hex(Vec<u8>),
    /// A reference into the kernel keyring: size, type and description.
    Keyring {
        /// Key length in bytes the reference promises.
        size: u32,
        /// Keyring type name.
        key_type: String,
        /// Key description.
        desc: String,
    },
}

impl KeySource {
    /// Length in bytes of the key this source yields. # C: O(1)
    pub fn len(&self) -> usize {
        match self { Self::Hex(k) => k.len(), Self::Keyring { size, .. } => *size as usize }
    }
    /// Whether the source yields no key at all. # C: O(1)
    pub fn is_empty(&self) -> bool { self.len() == 0 }
}

/// Parse the key field: hex digits, or `:<size>:<type>:<description>`.
/// # C: O(s.len())
pub fn parse_key(s: &str) -> DmResult<KeySource> {
    if let Some(rest) = s.strip_prefix(':') {
        let mut it = rest.splitn(3, ':');
        let size = crate::args::parse_u32(it.next().ok_or(Errno::Einval)?).ok_or(Errno::Einval)?;
        let key_type = it.next().ok_or(Errno::Einval)?.to_string();
        let desc = it.next().ok_or(Errno::Einval)?.to_string();
        if !matches!(key_type.as_str(), "logon" | "user" | "encrypted" | "trusted") {
            return Err(Errno::Einval);
        }
        return Ok(KeySource::Keyring { size, key_type, desc });
    }
    // A key that is not a whole number of bytes is a typo, not a short key.
    if s.is_empty() || s.len() % 2 != 0 { return Err(Errno::Einval); }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for pair in b.chunks_exact(2) {
        let hi = hex_digit(pair[0]).ok_or(Errno::Einval)?;
        let lo = hex_digit(pair[1]).ok_or(Errno::Einval)?;
        out.push((hi << 4) | lo);
    }
    Ok(KeySource::Hex(out))
}

fn hex_digit(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Render key bytes as the lowercase hex the table report prints.
/// # C: O(key.len())
pub fn key_hex(key: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(key.len() * 2);
    for b in key {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 0xf) as usize] as char);
    }
    s
}

/// Optional table-line features a `crypt` target accepts.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Features {
    /// Pass discards through to the backing device. Off by default because a
    /// discard reveals which sectors of an encrypted volume hold nothing.
    pub allow_discards: bool,
    /// Encrypt on the CPU that submitted.
    pub same_cpu_crypt: bool,
    /// Submit from the encrypting CPU rather than handing off.
    pub submit_from_crypt_cpus: bool,
    /// Decrypt inline rather than on a worker.
    pub no_read_workqueue: bool,
    /// Encrypt inline rather than on a worker.
    pub no_write_workqueue: bool,
    /// Count IVs in units of `sector_size` rather than 512-byte sectors.
    pub iv_large_sectors: bool,
    /// Run the workers at raised priority.
    pub high_priority: bool,
    /// Encryption unit in bytes; a power of two from 512 to 4096.
    pub sector_size: u32,
    /// Integrity tag bytes per sector, and the integrity profile name.
    pub integrity: Option<(u32, String)>,
    /// Bytes of the key reserved for the integrity profile.
    pub integrity_key_size: Option<u32>,
}

/// Parse the optional-argument group that follows the five fixed fields.
/// # C: O(argv.len())
pub fn parse_features(argv: &[&str]) -> DmResult<Features> {
    let mut f = Features { sector_size: crate::uapi::SECTOR_BYTES as u32, ..Default::default() };
    if argv.is_empty() { return Ok(f); }
    let count = crate::args::parse_u32(argv[0]).ok_or(Errno::Einval)? as usize;
    if count > 9 || count > argv.len() - 1 { return Err(Errno::Einval); }
    for a in &argv[1..=count] {
        match *a {
            "allow_discards" => f.allow_discards = true,
            "same_cpu_crypt" => f.same_cpu_crypt = true,
            "submit_from_crypt_cpus" => f.submit_from_crypt_cpus = true,
            "no_read_workqueue" => f.no_read_workqueue = true,
            "no_write_workqueue" => f.no_write_workqueue = true,
            "iv_large_sectors" => f.iv_large_sectors = true,
            "high_priority" => f.high_priority = true,
            _ if a.starts_with("sector_size:") => {
                let v = crate::args::parse_u32(&a["sector_size:".len()..]).ok_or(Errno::Einval)?;
                if !(512..=4096).contains(&v) || !v.is_power_of_two() { return Err(Errno::Einval); }
                f.sector_size = v;
            }
            _ if a.starts_with("integrity:") => {
                let rest = &a["integrity:".len()..];
                let (n, kind) = rest.split_once(':').ok_or(Errno::Einval)?;
                let n = crate::args::parse_u32(n).ok_or(Errno::Einval)?;
                if !matches!(kind, "aead" | "none") { return Err(Errno::Einval); }
                f.integrity = Some((n, kind.to_string()));
            }
            _ if a.starts_with("integrity_key_size:") => {
                f.integrity_key_size =
                    Some(crate::args::parse_u32(&a["integrity_key_size:".len()..]).ok_or(Errno::Einval)?);
            }
            _ => return Err(Errno::Einval),
        }
    }
    Ok(f)
}

/// Render the feature group back the way the table report prints it: a count
/// followed by exactly the words that are set. # C: O(N_features)
pub fn features_text(f: &Features) -> String {
    let mut words: Vec<String> = Vec::new();
    if f.allow_discards { words.push("allow_discards".to_string()); }
    if f.same_cpu_crypt { words.push("same_cpu_crypt".to_string()); }
    if f.submit_from_crypt_cpus { words.push("submit_from_crypt_cpus".to_string()); }
    if f.no_read_workqueue { words.push("no_read_workqueue".to_string()); }
    if f.no_write_workqueue { words.push("no_write_workqueue".to_string()); }
    if f.high_priority { words.push("high_priority".to_string()); }
    if f.iv_large_sectors { words.push("iv_large_sectors".to_string()); }
    if f.sector_size != crate::uapi::SECTOR_BYTES as u32 {
        words.push(alloc::format!("sector_size:{}", f.sector_size));
    }
    if let Some((n, kind)) = &f.integrity { words.push(alloc::format!("integrity:{n}:{kind}")); }
    if let Some(n) = f.integrity_key_size { words.push(alloc::format!("integrity_key_size:{n}")); }
    if words.is_empty() { return String::new(); }
    let mut s = words.len().to_string();
    for w in words { s.push(' '); s.push_str(&w); }
    s
}
