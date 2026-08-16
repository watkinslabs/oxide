//! The numbers file encryption is defined by: modes, policy flags, the stored
//! context's layout, and the derivation contexts that keep one master key's
//! subkeys apart.

/// Cipher modes, as a policy names them.
pub const MODE_AES_256_XTS: u8 = 1;
pub const MODE_AES_256_CTS: u8 = 4;
pub const MODE_AES_128_CBC: u8 = 5;
pub const MODE_AES_128_CTS: u8 = 6;
pub const MODE_SM4_XTS: u8 = 7;
pub const MODE_SM4_CTS: u8 = 8;
pub const MODE_ADIANTUM: u8 = 9;
pub const MODE_AES_256_HCTR2: u8 = 10;
/// Highest mode number the format assigns.
pub const MODE_MAX: u8 = MODE_AES_256_HCTR2;

/// Filename padding, encoded as the low two bits of the flags.
pub const FLAGS_PAD_4: u8 = 0x00;
pub const FLAGS_PAD_8: u8 = 0x01;
pub const FLAGS_PAD_16: u8 = 0x02;
pub const FLAGS_PAD_32: u8 = 0x03;
pub const FLAGS_PAD_MASK: u8 = 0x03;
/// Encrypt with a per-mode key and carry the file's nonce in every IV.
pub const FLAG_DIRECT_KEY: u8 = 0x04;
/// Put the inode number in the IV's high half; key is per (mode, volume).
pub const FLAG_IV_INO_LBLK_64: u8 = 0x08;
/// Add a hash of the inode number to the IV; key is per (mode, volume).
pub const FLAG_IV_INO_LBLK_32: u8 = 0x10;

/// Policy versions. The first one's version BYTE is zero, which is not its
/// name — a policy written with a `1` there is a different, invalid thing.
pub const POLICY_V1: u8 = 0;
pub const POLICY_V2: u8 = 2;
/// Context versions. The v1 CONTEXT is version 1 even though the v1 POLICY is
/// version 0; the two numbering schemes do not agree and never have.
pub const CONTEXT_V1: u8 = 1;
pub const CONTEXT_V2: u8 = 2;

/// Widths of the two ways a policy names its master key.
pub const KEY_DESCRIPTOR_SIZE: usize = 8;
pub const KEY_IDENTIFIER_SIZE: usize = 16;
/// The per-file random value mixed into every derivation and IV.
pub const FILE_NONCE_SIZE: usize = 16;

/// Master key bounds. Below the minimum no mode has its security strength;
/// above the maximum the format has nowhere to put the bytes.
pub const MIN_KEY_SIZE: usize = 16;
pub const MAX_RAW_KEY_SIZE: usize = 64;

// ------------------------------------------------------------ context layout

/// v1 context: version, two modes, flags, the 8-byte descriptor, the nonce.
pub const CTX_VERSION: usize = 0;
pub const CTX_CONTENTS_MODE: usize = 1;
pub const CTX_FILENAMES_MODE: usize = 2;
pub const CTX_FLAGS: usize = 3;
pub const CTX_V1_DESCRIPTOR: usize = 4;
pub const CTX_V1_NONCE: usize = CTX_V1_DESCRIPTOR + KEY_DESCRIPTOR_SIZE;
pub const CONTEXT_V1_SIZE: usize = CTX_V1_NONCE + FILE_NONCE_SIZE;

/// v2 context: the same head, then the data-unit size, three reserved bytes,
/// the 16-byte identifier, the nonce.
pub const CTX_V2_LOG2_DU: usize = 4;
pub const CTX_V2_RESERVED: usize = 5;
pub const CTX_V2_RESERVED_LEN: usize = 3;
pub const CTX_V2_IDENTIFIER: usize = CTX_V2_RESERVED + CTX_V2_RESERVED_LEN;
pub const CTX_V2_NONCE: usize = CTX_V2_IDENTIFIER + KEY_IDENTIFIER_SIZE;
pub const CONTEXT_V2_SIZE: usize = CTX_V2_NONCE + FILE_NONCE_SIZE;

const _: () = assert!(CONTEXT_V1_SIZE == 28);
const _: () = assert!(CONTEXT_V2_SIZE == 40);

/// The attribute the context is stored under, within the encryption index.
pub const XATTR_NAME: &[u8] = b"c";

// ------------------------------------------------- key-derivation contexts

/// First byte of every derivation's info string, so no two purposes can
/// derive the same bytes from one master key.
pub const HKDF_KEY_IDENTIFIER: u8 = 1;
pub const HKDF_PER_FILE_ENC_KEY: u8 = 2;
pub const HKDF_DIRECT_KEY: u8 = 3;
pub const HKDF_IV_INO_LBLK_64_KEY: u8 = 4;
pub const HKDF_DIRHASH_KEY: u8 = 5;
pub const HKDF_IV_INO_LBLK_32_KEY: u8 = 6;
pub const HKDF_INODE_HASH_KEY: u8 = 7;

/// The prefix every derivation's info string carries, terminator included.
pub const HKDF_PREFIX: &[u8] = b"fscrypt\0";

// ------------------------------------------------------------------- names

/// Shortest filename message. A shorter name is zero-padded up to this before
/// it is encrypted, so no ciphertext name is ever shorter.
pub const FNAME_MIN_MSG_LEN: usize = 16;

/// A no-key name carries the directory hash, up to this many ciphertext
/// bytes, and — only when the ciphertext is longer — a digest of the rest.
pub const NOKEY_BYTES: usize = 149;
pub const NOKEY_DIRHASH: usize = 8;
pub const NOKEY_SHA256: usize = 32;
pub const NOKEY_NAME_MAX: usize = NOKEY_DIRHASH + NOKEY_BYTES + NOKEY_SHA256;
/// The same, once base64url-encoded; it must fit a name.
pub const NOKEY_NAME_MAX_ENCODED: usize = (NOKEY_NAME_MAX * 4).div_ceil(3);

const _: () = assert!(NOKEY_NAME_MAX == 189);
const _: () = assert!(NOKEY_NAME_MAX_ENCODED == 252);
const _: () = assert!(NOKEY_NAME_MAX_ENCODED <= crate::uapi::NAME_LEN);

/// Widest IV any mode uses.
pub const MAX_IV_SIZE: usize = 32;

// --------------------------------------------------------- volume-level facts

/// This format's inode numbers fit in 32 bits and are never renumbered, which
/// is what the two inode-in-the-IV policies require of a volume.
pub const HAS_32BIT_INODES: bool = true;
pub const HAS_STABLE_INODES: bool = true;
/// A data unit may be smaller than a block on this format.
pub const SUPPORTS_SUBBLOCK_DATA_UNITS: bool = true;
/// Smallest log2 data-unit size a policy may name.
pub const MIN_LOG2_DATA_UNIT_SIZE: u8 = 9;
