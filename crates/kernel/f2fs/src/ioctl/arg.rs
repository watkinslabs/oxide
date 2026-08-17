//! Reading and writing the fixed argument structures byte by byte.
//!
//! Every structure is handled as bytes rather than as a repr-C type, because
//! the layout is the ABI: a field that moves because the compiler chose
//! different padding would change what a caller's memory means, and no test
//! could see it. Offsets come from [`super::uapi`], which derives the command
//! numbers from the same sizes, so the two cannot disagree.
//!
//! A payload shorter than the structure it must hold is reported as a faulted
//! access, which is what a caller that passed such a buffer would have got.

use alloc::vec::Vec;

use syscall::errno::Errno;

use super::uapi::*;

/// Little-endian sixteen-bit field at `at`. # C: O(1)
pub fn u16_at(b: &[u8], at: usize) -> Result<u16, Errno> {
    let s = b.get(at..at + 2).ok_or(Errno::Efault)?;
    Ok(u16::from_le_bytes([s[0], s[1]]))
}

/// Little-endian thirty-two-bit field at `at`. # C: O(1)
pub fn u32_at(b: &[u8], at: usize) -> Result<u32, Errno> {
    let s = b.get(at..at + 4).ok_or(Errno::Efault)?;
    Ok(u32::from_le_bytes([s[0], s[1], s[2], s[3]]))
}

/// Little-endian sixty-four-bit field at `at`. # C: O(1)
pub fn u64_at(b: &[u8], at: usize) -> Result<u64, Errno> {
    let s = b.get(at..at + 8).ok_or(Errno::Efault)?;
    let mut w = [0u8; 8];
    w.copy_from_slice(s);
    Ok(u64::from_le_bytes(w))
}

/// A single byte at `at`. # C: O(1)
pub fn u8_at(b: &[u8], at: usize) -> Result<u8, Errno> {
    b.get(at).copied().ok_or(Errno::Efault)
}

/// `n` bytes starting at `at`. # C: O(n)
pub fn bytes_at(b: &[u8], at: usize, n: usize) -> Result<&[u8], Errno> {
    b.get(at..at + n).ok_or(Errno::Efault)
}

/// Store a little-endian thirty-two-bit field. # C: O(1)
pub fn put_u32(b: &mut [u8], at: usize, v: u32) -> Result<(), Errno> {
    let s = b.get_mut(at..at + 4).ok_or(Errno::Efault)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Store a little-endian sixty-four-bit field. # C: O(1)
pub fn put_u64(b: &mut [u8], at: usize, v: u64) -> Result<(), Errno> {
    let s = b.get_mut(at..at + 8).ok_or(Errno::Efault)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Store a little-endian sixteen-bit field. # C: O(1)
pub fn put_u16(b: &mut [u8], at: usize, v: u16) -> Result<(), Errno> {
    let s = b.get_mut(at..at + 2).ok_or(Errno::Efault)?;
    s.copy_from_slice(&v.to_le_bytes());
    Ok(())
}

/// Which master key a command names, and by which of the two naming schemes.
///
/// The older scheme lets a caller claim any eight-byte name for any key; the
/// newer derives a sixteen-byte name FROM the key so it cannot be claimed.
/// Both are on the wire, so both are here, and the difference is preserved
/// rather than collapsed — a policy written under one names nothing under the
/// other.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum KeySpec {
    Descriptor([u8; 8]),
    Identifier([u8; 16]),
}

/// Decode a key specifier from a fixed-size record at `at`. # C: O(1)
pub fn key_spec(b: &[u8], at: usize) -> Result<KeySpec, Errno> {
    // The reserved word must be zero: a caller setting it is asking for
    // something this build does not define, and accepting it would make a
    // later definition a behaviour change nobody could see coming.
    if u32_at(b, at + SPEC_RESERVED)? != 0 { return Err(Errno::Einval); }
    match u32_at(b, at + SPEC_TYPE)? {
        KEY_SPEC_TYPE_DESCRIPTOR => {
            let mut d = [0u8; 8];
            d.copy_from_slice(bytes_at(b, at + SPEC_UNION, 8)?);
            Ok(KeySpec::Descriptor(d))
        }
        KEY_SPEC_TYPE_IDENTIFIER => {
            let mut d = [0u8; 16];
            d.copy_from_slice(bytes_at(b, at + SPEC_UNION, 16)?);
            Ok(KeySpec::Identifier(d))
        }
        _ => Err(Errno::Einval),
    }
}

/// Write a key specifier back into a reply payload. # C: O(1)
pub fn put_key_spec(b: &mut [u8], at: usize, k: &KeySpec) -> Result<(), Errno> {
    match k {
        KeySpec::Descriptor(d) => {
            put_u32(b, at + SPEC_TYPE, KEY_SPEC_TYPE_DESCRIPTOR)?;
            b.get_mut(at + SPEC_UNION..at + SPEC_UNION + 8).ok_or(Errno::Efault)?
                .copy_from_slice(d);
        }
        KeySpec::Identifier(d) => {
            put_u32(b, at + SPEC_TYPE, KEY_SPEC_TYPE_IDENTIFIER)?;
            b.get_mut(at + SPEC_UNION..at + SPEC_UNION + 16).ok_or(Errno::Efault)?
                .copy_from_slice(d);
        }
    }
    Ok(())
}

/// A key being added, and how the caller wants it named.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AddKey {
    pub spec: KeySpec,
    pub flags: u32,
    /// Non-zero when the key is to be taken from a provisioning key rather
    /// than from the argument's own bytes.
    pub key_id: u32,
    pub raw_size: u32,
}

/// Decode the fixed part of the add-key argument.
///
/// The raw key sits past the fixed part, so it is fetched separately and is
/// not decoded here — this reports the size the copy layer must fetch.
/// `cap_sys_admin` decides the one check that is a permission rather than a
/// shape, and it belongs in the same pass because its position in the order
/// is observable: a caller with a malformed reserved word AND no capability
/// must see the shape error.
/// # C: O(1)
pub fn add_key(b: &[u8], cap_sys_admin: bool) -> Result<AddKey, Errno> {
    let spec = key_spec(b, ADD_KEY_SPECIFIER)?;
    for i in 0..ADD_KEY_RESERVED_WORDS {
        if u32_at(b, ADD_KEY_RESERVED + i * 4)? != 0 { return Err(Errno::Einval); }
    }
    // A key named by a descriptor is named by something the caller CHOSE
    // rather than by the key's own contents, so any caller could claim the
    // name a policy refers to and have the wrong key used for it.
    if matches!(spec, KeySpec::Descriptor(_)) && !cap_sys_admin { return Err(Errno::Eacces); }
    let flags = u32_at(b, ADD_KEY_FLAGS)?;
    if flags != 0 {
        if flags & !ADD_KEY_FLAG_HW_WRAPPED != 0 { return Err(Errno::Einval); }
        if !matches!(spec, KeySpec::Identifier(_)) { return Err(Errno::Einval); }
    }
    let key_id = u32_at(b, ADD_KEY_KEY_ID)?;
    let raw_size = u32_at(b, ADD_KEY_RAW_SIZE)?;
    if key_id != 0 {
        // The key comes from elsewhere, so carrying bytes here as well would
        // leave two answers to which key was added.
        if raw_size != 0 { return Err(Errno::Einval); }
    } else if (raw_size as usize) < crate::crypto::uapi::MIN_KEY_SIZE
        || raw_size as usize > MAX_RAW_KEY
    {
        return Err(Errno::Einval);
    }
    Ok(AddKey { spec, flags, key_id, raw_size })
}

/// Decode a remove-key argument, applying the same descriptor-naming rule the
/// add path applies. # C: O(1)
pub fn remove_key(b: &[u8], cap_sys_admin: bool) -> Result<KeySpec, Errno> {
    let spec = key_spec(b, REMOVE_KEY_SPECIFIER)?;
    for i in 0..REMOVE_KEY_RESERVED_WORDS {
        if u32_at(b, REMOVE_KEY_RESERVED + i * 4)? != 0 { return Err(Errno::Einval); }
    }
    if matches!(spec, KeySpec::Descriptor(_)) && !cap_sys_admin { return Err(Errno::Eacces); }
    Ok(spec)
}

/// Decode a key-status argument. Unlike add and remove, naming a key by a
/// descriptor here reveals nothing a caller could not learn by trying to use
/// it, so no capability is required. # C: O(1)
pub fn key_status(b: &[u8]) -> Result<KeySpec, Errno> {
    let spec = key_spec(b, KEY_STATUS_SPECIFIER)?;
    for i in 0..KEY_STATUS_RESERVED_WORDS {
        if u32_at(b, KEY_STATUS_RESERVED + i * 4)? != 0 { return Err(Errno::Einval); }
    }
    Ok(spec)
}

/// The extended file-attribute record, as both directions carry it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub struct FsxAttr {
    pub xflags: u32,
    pub extsize: u32,
    pub nextents: u32,
    pub projid: u32,
    pub cowextsize: u32,
}

/// Decode the extended file-attribute record. # C: O(1)
pub fn fsxattr(b: &[u8]) -> Result<FsxAttr, Errno> {
    // The trailing pad must be zero for the same reason the reserved words
    // must be: a later field defined there would otherwise arrive already set.
    for i in 0..8 {
        if u8_at(b, FSX_PAD + i)? != 0 { return Err(Errno::Einval); }
    }
    Ok(FsxAttr {
        xflags: u32_at(b, FSX_XFLAGS)?,
        extsize: u32_at(b, FSX_EXTSIZE)?,
        nextents: u32_at(b, FSX_NEXTENTS)?,
        projid: u32_at(b, FSX_PROJID)?,
        cowextsize: u32_at(b, FSX_COWEXTSIZE)?,
    })
}

/// Encode the extended file-attribute record. # C: O(1)
pub fn put_fsxattr(fa: &FsxAttr) -> Result<Vec<u8>, Errno> {
    let mut b = alloc::vec![0u8; FSXATTR_SIZE as usize];
    put_u32(&mut b, FSX_XFLAGS, fa.xflags)?;
    put_u32(&mut b, FSX_EXTSIZE, fa.extsize)?;
    put_u32(&mut b, FSX_NEXTENTS, fa.nextents)?;
    put_u32(&mut b, FSX_PROJID, fa.projid)?;
    put_u32(&mut b, FSX_COWEXTSIZE, fa.cowextsize)?;
    Ok(b)
}

/// What a caller asked for when turning verity on, with the salt and the
/// signature already fetched from the buffers the argument named.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerityEnable {
    pub hash_algorithm: u32,
    pub block_size: u32,
    pub salt: Vec<u8>,
    pub sig: Vec<u8>,
}

/// The two lengths and two addresses the enable argument names, which the
/// copy layer needs before it can fetch either buffer. # C: O(1)
pub fn verity_enable_head(b: &[u8]) -> Result<VerityEnableHead, Errno> {
    if u32_at(b, VE_VERSION)? != VERITY_ENABLE_VERSION { return Err(Errno::Einval); }
    if u32_at(b, VE_RESERVED1)? != 0 { return Err(Errno::Einval); }
    for i in 0..11 {
        if u64_at(b, VE_RESERVED2 + i * 8)? != 0 { return Err(Errno::Einval); }
    }
    // The tree's block size is a shift, so a size that is not a power of two
    // describes a tree that cannot be indexed. Refused BEFORE the two length
    // ceilings, because an unrepresentable geometry is the wider fault.
    let block_size = u32_at(b, VE_BLOCK_SIZE)?;
    if !block_size.is_power_of_two() { return Err(Errno::Einval); }
    let salt_size = u32_at(b, VE_SALT_SIZE)?;
    let sig_size = u32_at(b, VE_SIG_SIZE)?;
    if salt_size as usize > VERITY_MAX_SALT { return Err(Errno::Emsgsize); }
    if sig_size as usize > VERITY_MAX_SIGNATURE { return Err(Errno::Emsgsize); }
    Ok(VerityEnableHead {
        hash_algorithm: u32_at(b, VE_HASH_ALGORITHM)?,
        block_size,
        salt_size,
        salt_ptr: u64_at(b, VE_SALT_PTR)?,
        sig_size,
        sig_ptr: u64_at(b, VE_SIG_PTR)?,
    })
}

/// The fixed part of the verity-enable argument.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct VerityEnableHead {
    pub hash_algorithm: u32,
    pub block_size: u32,
    pub salt_size: u32,
    pub salt_ptr: u64,
    pub sig_size: u32,
    pub sig_ptr: u64,
}

/// What the read-metadata argument names.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ReadMetadata {
    pub kind: u64,
    pub offset: u64,
    pub length: u64,
    pub buf_ptr: u64,
}

/// Decode the read-metadata argument. # C: O(1)
pub fn read_metadata(b: &[u8]) -> Result<ReadMetadata, Errno> {
    if u64_at(b, VRM_RESERVED)? != 0 { return Err(Errno::Einval); }
    let offset = u64_at(b, VRM_OFFSET)?;
    let asked = u64_at(b, VRM_LENGTH)?;
    // A span that wraps names memory that does not exist. Checked on the
    // caller's own numbers, before the length is clamped: clamping first
    // would make an overflowing request look like an ordinary short one.
    if offset.checked_add(asked).is_none() { return Err(Errno::Einval); }
    let kind = u64_at(b, VRM_TYPE)?;
    match kind {
        VERITY_METADATA_TYPE_MERKLE_TREE | VERITY_METADATA_TYPE_DESCRIPTOR
        | VERITY_METADATA_TYPE_SIGNATURE => {}
        _ => return Err(Errno::Einval),
    }
    Ok(ReadMetadata {
        kind,
        offset,
        // The byte count comes back in a signed result, so a longer request
        // is SHORTENED rather than refused — a caller asking for everything
        // gets what fits and asks again from where it stopped.
        length: asked.min(i32::MAX as u64),
        buf_ptr: u64_at(b, VRM_BUF_PTR)?,
    })
}

#[cfg(test)]
#[path = "../tests/ioctl/arg.rs"]
mod tests;
