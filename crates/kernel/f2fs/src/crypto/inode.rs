//! An inode's encryption, assembled: the policy it stores, the key that
//! policy names, and the operations that key makes possible.
//!
//! Which key an inode uses is decided by ONE of the policy's derivation flags,
//! and each produces a different key from the same master key:
//!
//! - default: a key per FILE, from the file's nonce.
//! - direct: a key per MODE, with the file's nonce moved into every IV.
//! - inode-in-IV: a key per (mode, volume), with the inode number in the IV.
//!
//! The older policy version has only two of these and derives them with a
//! block cipher rather than a derivation function. All of them decrypt their
//! own output, so a wrong choice is a file that reads as noise on the next
//! machine and nowhere else.

use alloc::vec::Vec;

use super::cipher::{Cipher, CONTENTS_ALIGNMENT};
use super::key::{self, MasterKey};
use super::mode::Mode;
use super::policy::{Context, FsFacts, InodeFacts, KeyId, Policy};
use super::uapi::*;
use super::{fname, iv, support, FscryptError};

/// Everything an encrypted inode needs to read and write itself.
#[derive(Clone)]
pub struct Info {
    policy: Policy,
    nonce: [u8; FILE_NONCE_SIZE],
    mode: Mode,
    cipher: Cipher,
    du_bits: u8,
    ino: u32,
    hashed_ino: u32,
    dirhash_key: Option<siphash::Key>,
}

/// The volume identity a per-mode key is derived against, so one master key
/// used on two volumes does not produce one key.
pub type Uuid = [u8; 16];

impl Info {
    /// Set up `ctx`'s encryption for an inode, given the master key it names.
    ///
    /// The key's SIZE is checked against the policy version: the older
    /// derivation cannot stretch, so it needs a master key at least as long as
    /// the key it produces, while the newer one needs only the security
    /// strength of the mode.
    /// # C: O(1)
    pub fn setup(
        ctx: &Context,
        inode: &InodeFacts,
        fs: &FsFacts,
        mk: &MasterKey,
        uuid: &Uuid,
        ino: u32,
    ) -> Result<Self, FscryptError> {
        support::check(&ctx.policy, inode, fs)?;
        let p = ctx.policy;
        let mode = p.mode_for(inode)?;
        let min = if p.version == POLICY_V1 { mode.key_size } else { mode.security_strength };
        if mk.size() < min { return Err(FscryptError::KeyTooShort); }
        // A v2 policy names its key by a hash of the key, so the wrong key is
        // caught here rather than producing bytes that are not the file's.
        if let KeyId::Identifier(id) = p.key {
            if mk.identifier() != id { return Err(FscryptError::KeyMismatch); }
        }
        let mut hashed_ino = 0u32;
        let raw = Self::derive(&p, &ctx.nonce, mode, mk, uuid, ino, &mut hashed_ino)?;
        let cipher = Cipher::prepare(mode, &raw)?;
        // Only a case-folding directory hashes plaintext, and only the newer
        // policy can derive the key for it — which is why the older one is
        // refused on such a directory rather than falling back.
        let dirhash_key = if inode.is_dir && inode.casefolded && p.version == POLICY_V2 {
            Some(mk.siphash_key(HKDF_DIRHASH_KEY, &[&ctx.nonce])?)
        } else {
            None
        };
        Ok(Self {
            policy: p, nonce: ctx.nonce, mode, cipher,
            du_bits: p.data_unit_bits(fs), ino, hashed_ino, dirhash_key,
        })
    }

    /// The raw key bytes this inode encrypts with. # C: O(1)
    fn derive(
        p: &Policy,
        nonce: &[u8; FILE_NONCE_SIZE],
        mode: Mode,
        mk: &MasterKey,
        uuid: &Uuid,
        ino: u32,
        hashed_ino: &mut u32,
    ) -> Result<Vec<u8>, FscryptError> {
        if p.version == POLICY_V1 {
            // The older version's direct key IS the master key; there is no
            // derivation to interpose, which is the reason it was replaced.
            if p.flags & FLAG_DIRECT_KEY != 0 {
                return Ok(Vec::from(&mk.raw()[..mode.key_size]));
            }
            return key::v1_file_key(mk.raw(), nonce, mode.key_size);
        }
        let mut out = alloc::vec![0u8; mode.key_size];
        let mode_num = [mode.num];
        if p.flags & FLAG_DIRECT_KEY != 0 {
            mk.expand(HKDF_DIRECT_KEY, &[&mode_num], &mut out)?;
        } else if p.flags & FLAG_IV_INO_LBLK_64 != 0 {
            mk.expand(HKDF_IV_INO_LBLK_64_KEY, &[&mode_num, uuid], &mut out)?;
        } else if p.flags & FLAG_IV_INO_LBLK_32 != 0 {
            mk.expand(HKDF_IV_INO_LBLK_32_KEY, &[&mode_num, uuid], &mut out)?;
            // The inode number is hashed rather than used directly, so that
            // adding it to the index cannot make two files' IVs collide in a
            // predictable way.
            let k = mk.siphash_key(HKDF_INODE_HASH_KEY, &[])?;
            *hashed_ino = siphash::siphash_1u64(u64::from(ino), &k) as u32;
        } else {
            mk.expand(HKDF_PER_FILE_ENC_KEY, &[nonce], &mut out)?;
        }
        Ok(out)
    }

    /// The policy this inode is encrypted under. # C: O(1)
    pub fn policy(&self) -> &Policy { &self.policy }

    /// The mode this inode's own key belongs to — the contents mode for a
    /// regular file, the filenames mode for a directory or a link. # C: O(1)
    pub fn mode(&self) -> Mode { self.mode }

    /// Bytes of one contents encryption unit. # C: O(1)
    pub fn data_unit_size(&self) -> usize { 1usize << self.du_bits }

    /// The IV for data unit `index`. # C: O(1)
    fn unit_iv(&self, index: u64) -> [u8; 16] {
        iv::block_iv(&iv::generate(self.policy.flags, &self.nonce, self.ino, self.hashed_ino, index))
    }

    /// Encrypt one data unit of file contents in place.
    ///
    /// `index` counts data units from the start of the file, which is NOT the
    /// block number when the policy sets a smaller unit.
    /// # C: O(len(buf))
    pub fn encrypt_data_unit(&self, index: u64, buf: &mut [u8]) -> Result<(), FscryptError> {
        if buf.is_empty() || buf.len() % CONTENTS_ALIGNMENT != 0 {
            return Err(FscryptError::BadLength(buf.len()));
        }
        self.cipher.encrypt(&self.unit_iv(index), buf)
    }

    /// Decrypt one data unit of file contents in place. # C: O(len(buf))
    pub fn decrypt_data_unit(&self, index: u64, buf: &mut [u8]) -> Result<(), FscryptError> {
        if buf.is_empty() || buf.len() % CONTENTS_ALIGNMENT != 0 {
            return Err(FscryptError::BadLength(buf.len()));
        }
        self.cipher.decrypt(&self.unit_iv(index), buf)
    }

    /// Encrypt or decrypt a whole buffer of file contents starting at data
    /// unit `first`, one unit at a time. # C: O(len(buf))
    pub fn crypt_contents(&self, first: u64, buf: &mut [u8], encrypt: bool)
        -> Result<(), FscryptError> {
        let du = self.data_unit_size();
        if buf.is_empty() || buf.len() % du != 0 { return Err(FscryptError::BadLength(buf.len())); }
        for (i, unit) in buf.chunks_exact_mut(du).enumerate() {
            let index = first + i as u64;
            if encrypt { self.encrypt_data_unit(index, unit)?; }
            else { self.decrypt_data_unit(index, unit)?; }
        }
        Ok(())
    }

    /// The stored length a name of `orig_len` bytes takes in this directory.
    /// # C: O(1)
    pub fn encrypted_name_size(&self, orig_len: usize) -> Option<usize> {
        fname::encrypted_size(orig_len, self.policy.padding(), crate::uapi::NAME_LEN)
    }

    /// The ciphertext a directory entry stores for `name`.
    ///
    /// The two names that are never encrypted pass through unchanged.
    /// # C: O(len(name))
    pub fn encrypt_name(&self, name: &[u8]) -> Result<Vec<u8>, FscryptError> {
        if crate::hash::is_dot_or_dotdot(name) { return Ok(Vec::from(name)); }
        let olen = self.encrypted_name_size(name.len()).ok_or(FscryptError::NameTooLong)?;
        // A name that pads past the cap cannot be stored: the padding is not
        // optional, so there is no shorter form of it.
        if olen < name.len() { return Err(FscryptError::NameTooLong); }
        let mut buf = fname::padded(name, olen)?;
        // Names carry no index of their own; every name in a directory is
        // encrypted at index zero, which is what lets a lookup encrypt the
        // query and compare ciphertext.
        self.cipher.encrypt(&self.unit_iv(0), &mut buf)?;
        Ok(buf)
    }

    /// The plaintext of a stored entry name. # C: O(len(disk))
    pub fn decrypt_name(&self, disk: &[u8]) -> Result<Vec<u8>, FscryptError> {
        if crate::hash::is_dot_or_dotdot(disk) { return Ok(Vec::from(disk)); }
        if disk.len() < FNAME_MIN_MSG_LEN { return Err(FscryptError::CorruptName); }
        let mut buf = Vec::from(disk);
        self.cipher.decrypt(&self.unit_iv(0), &mut buf)?;
        let n = fname::unpad(&buf).len();
        buf.truncate(n);
        Ok(buf)
    }

    /// The directory hash of a plaintext name, for a directory that both folds
    /// case and encrypts.
    ///
    /// Such a directory cannot hash the stored bytes — two spellings of one
    /// name encrypt differently — so it hashes the FOLDED PLAINTEXT under a
    /// key derived from the master key. The result is not the format's own
    /// name hash and is not comparable with it.
    /// # C: O(len(name))
    pub fn dirhash(&self, folded_name: &[u8]) -> Option<u32> {
        let k = self.dirhash_key.as_ref()?;
        Some(siphash::siphash(folded_name, k) as u32)
    }

    /// Whether this inode has a keyed directory hash. # C: O(1)
    pub fn has_dirhash_key(&self) -> bool { self.dirhash_key.is_some() }
}
