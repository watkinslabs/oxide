// Registered key types — the `key_type_lookup` table each type's
// `register_key_type` populates. An unregistered type name is ENODEV out of
// the create-or-update path and ENOKEY out of the lookup itself, which is what
// `KEYCTL_SEARCH` and `KEYCTL_RESTRICT_KEYRING` surface.
//
// Each type also owns its `preparse` payload contract (`PayloadRule`) and the
// quota charge that payload incurs, because both are per-type facts that
// `add_key`/`KEYCTL_UPDATE` must apply BEFORE the key is minted.
//
// `asymmetric`, `encrypted` and `trusted` are separate CONFIG symbols whose
// payload machinery (X.509 parsing, TPM sealing) this kernel does not build,
// so their names are unregistered.

use syscall::errno::Errno;
use super::uapi::*;

/// A type's `preparse` payload contract. The rule runs before the key is
/// minted or updated, so a bad payload is EINVAL rather than a key with
/// nonsense in it.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum PayloadRule {
    /// `keyring_preparse`: `datalen != 0` is EINVAL — a keyring carries no
    /// payload, its content is its links.
    Empty,
    /// `user_preparse`: a non-NULL payload of 1..=32767 bytes. Zero-length,
    /// oversized, or a NULL pointer with a nonzero length is EINVAL. The whole
    /// payload is charged to the owner's byte quota.
    UserDefined,
    /// `big_key_preparse`: a non-NULL payload of 1..=1048576 bytes, charged a
    /// FLAT quota regardless of size — the payload lives outside the key.
    Big,
}

/// Upper payload bound for the user-defined types.
pub const USER_PAYLOAD_MAX: u64 = 32767;
/// Upper payload bound for `big_key`.
pub const BIG_PAYLOAD_MAX: u64 = 1024 * 1024;
/// The flat byte quota a `big_key` payload is charged.
pub const BIG_QUOTA: u64 = 16;

/// The `struct key_type` fields the permission / perm-default / payload logic
/// consults.
pub struct KeyType {
    pub name: &'static str,
    /// `type->read` present — absent means `KEYCTL_READ` is EOPNOTSUPP.
    pub readable: bool,
    /// `type->update` present — absent means `add_key` on an existing
    /// type+description mints a SECOND key instead of updating it, and
    /// `KEYCTL_UPDATE` is EOPNOTSUPP.
    pub updatable: bool,
    /// `type == &key_type_keyring`.
    pub is_keyring: bool,
    /// `type->vet_description` present and requiring a qualified
    /// `subsystem:key` description.
    pub vet_colon: bool,
    /// `type->lookup_restriction` present — absent makes
    /// `KEYCTL_RESTRICT_KEYRING` with this type name ENOENT.
    pub restrictable: bool,
    /// `type->preparse`'s payload contract.
    pub payload_rule: PayloadRule,
}

/// `key_types_list` in registration order.
static TYPES: &[KeyType] = &[
    // The keyring type has NO `.update` method: re-adding a keyring of the
    // same name mints a distinct keyring, and `KEYCTL_UPDATE` on one is
    // EOPNOTSUPP. It still gets `KEY_POS_WRITE` by default because
    // `default_perm` names the keyring type explicitly.
    KeyType { name: "keyring", readable: true,  updatable: false, is_keyring: true,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::Empty },
    KeyType { name: "user",    readable: true,  updatable: true,  is_keyring: false,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::UserDefined },
    // `logon` deliberately omits `.read`: the payload is write-only.
    KeyType { name: "logon",   readable: false, updatable: true,  is_keyring: false,
              vet_colon: true,  restrictable: false, payload_rule: PayloadRule::UserDefined },
    // `big_key` takes a payload up to 1 MiB. Linux offloads anything past a
    // small threshold into an encrypted shmem file so it can be swapped; that
    // is a storage decision with no syscall-visible effect — the same bytes
    // come back out of `KEYCTL_READ` either way — so the payload is held
    // inline here. What IS syscall-visible is the flat 16-byte quota charge,
    // which is why a big_key does not consume the owner's byte quota in
    // proportion to its size.
    KeyType { name: "big_key", readable: true,  updatable: true,  is_keyring: false,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::Big },
];

/// Linux `key_type_lookup`. # C: O(types)
pub fn lookup(name: &str) -> Option<&'static KeyType> {
    TYPES.iter().find(|t| t.name == name)
}

/// The keyring type itself, for the paths that mint keyrings directly.
/// # C: O(types)
pub fn keyring_type() -> &'static KeyType {
    lookup("keyring").expect("the keyring type is registered unconditionally")
}

/// `logon_vet_description`: require a QUALIFIED description — one containing a
/// `:` that is not the first character. The suffix may be empty; only a
/// missing colon and a leading colon are rejected. # C: O(desc)
pub fn vet_description(t: &KeyType, desc: &str) -> Result<(), Errno> {
    if !t.vet_colon { return Ok(()); }
    match desc.find(':') {
        None | Some(0) => Err(Errno::Einval),
        Some(_) => Ok(()),
    }
}

/// A leading `.` names a kernel-internal keyring, so `add_key` refuses to mint
/// one from userspace with EPERM. The test is a PREFIX test on the type name,
/// matching the syscall's `strncmp(type, "keyring", 7)`, and it is applied at
/// the syscall entry — ahead of the payload copy — so a bad payload pointer
/// cannot mask it. # C: O(1)
pub fn dot_reserved(key_type: &str, desc: &str) -> bool {
    desc.starts_with('.') && key_type.starts_with("keyring")
}

/// The type's `preparse` payload check. `have_ptr` is whether userspace passed
/// a non-NULL payload pointer: a NULL pointer reaches `preparse` as a NULL
/// `prep->data`, which the user-defined and big_key preparsers reject with
/// EINVAL rather than treating as a zero-length payload. # C: O(1)
pub fn vet_payload(t: &KeyType, len: u64, have_ptr: bool) -> Result<(), Errno> {
    match t.payload_rule {
        PayloadRule::Empty => if len != 0 { Err(Errno::Einval) } else { Ok(()) },
        PayloadRule::UserDefined =>
            if len == 0 || len > USER_PAYLOAD_MAX || !have_ptr { Err(Errno::Einval) } else { Ok(()) },
        PayloadRule::Big =>
            if len == 0 || len > BIG_PAYLOAD_MAX || !have_ptr { Err(Errno::Einval) } else { Ok(()) },
    }
}

/// The byte quota a payload of `len` bytes costs under this type — Linux's
/// `prep->quotalen`, which `generic_key_instantiate` reserves and `*_update`
/// re-reserves as a delta. The user-defined types charge the payload itself;
/// `big_key` charges a flat 16; a keyring charges nothing beyond its
/// description. # C: O(1)
pub fn payload_quota(t: &KeyType, len: u64) -> u64 {
    match t.payload_rule {
        PayloadRule::Empty => 0,
        PayloadRule::UserDefined => len,
        PayloadRule::Big => BIG_QUOTA,
    }
}

/// `key_create_or_update` with `KEY_PERM_UNDEF`:
///
/// ```text
/// perm  = KEY_POS_VIEW | KEY_POS_SEARCH | KEY_POS_LINK | KEY_POS_SETATTR;
/// perm |= KEY_USR_VIEW;
/// if (type->read)                                perm |= KEY_POS_READ;
/// if (type == &key_type_keyring || type->update) perm |= KEY_POS_WRITE;
/// ```
///
/// Note the USER byte is `KEY_USR_VIEW` alone — a key's owner gets nothing
/// but VIEW from the user byte, and reaches READ/WRITE only by possessing it.
/// # C: O(1)
pub fn default_perm(t: &KeyType) -> u32 {
    let mut perm = KEY_POS_VIEW | KEY_POS_SEARCH | KEY_POS_LINK | KEY_POS_SETATTR | KEY_USR_VIEW;
    if t.readable { perm |= KEY_POS_READ; }
    if t.is_keyring || t.updatable { perm |= KEY_POS_WRITE; }
    perm
}
