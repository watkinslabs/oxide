// Registered key types — the `key_type_lookup` table each type's
// `register_key_type` populates. An unregistered type name is ENODEV out of
// the create-or-update path and ENOKEY out of the lookup itself, which is what
// `KEYCTL_SEARCH` and `KEYCTL_RESTRICT_KEYRING` surface.
//
// Each type also owns its `preparse` payload contract (`PayloadRule`) and the
// quota charge that payload incurs, because both are per-type facts that
// `add_key`/`KEYCTL_UPDATE` must apply BEFORE the key is minted.
//
// `encrypted` and `trusted` need TPM sealing this kernel has no driver for,
// so their names are unregistered. `asymmetric` IS registered: its payload is
// an X.509 certificate or a PKCS#8 private key, parsed by `pkey`.

use alloc::string::String;
use alloc::vec::Vec;
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
    /// The asymmetric-key parsers: the payload must decode as a key blob, and
    /// the blob may propose the key's description. A flat quota, because the
    /// stored material is the parsed key rather than the blob's length.
    Asymmetric,
}

/// Upper payload bound for the user-defined types.
pub const USER_PAYLOAD_MAX: u64 = 32767;
/// Upper payload bound for `big_key`.
pub const BIG_PAYLOAD_MAX: u64 = 1024 * 1024;
/// The flat byte quota a `big_key` payload is charged.
pub const BIG_QUOTA: u64 = 16;
/// The flat byte quota an asymmetric key is charged.
pub const ASYMMETRIC_QUOTA: u64 = 100;

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
    /// Whether the type's preparse can PROPOSE a description, which is what
    /// lets a caller add a key without naming it. Every other type leaves an
    /// absent description as EINVAL.
    pub describes_itself: bool,
    /// `KEY_TYPE_NET_DOMAIN`: this type's keys are indexed under the creating
    /// task's NETWORK namespace instead of the single default domain. Two keys
    /// of the same type and description in different network namespaces are
    /// then different keys and neither search finds the other's — which is the
    /// point for a type caching an answer that is only true on one network.
    pub net_domain: bool,
}

/// `key_types_list` in registration order.
static TYPES: &[KeyType] = &[
    // The keyring type has NO `.update` method: re-adding a keyring of the
    // same name mints a distinct keyring, and `KEYCTL_UPDATE` on one is
    // EOPNOTSUPP. It still gets `KEY_POS_WRITE` by default because
    // `default_perm` names the keyring type explicitly.
    KeyType { name: "keyring", readable: true,  updatable: false, is_keyring: true,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::Empty, describes_itself: false, net_domain: false },
    KeyType { name: "user",    readable: true,  updatable: true,  is_keyring: false,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::UserDefined, describes_itself: false, net_domain: false },
    // `logon` deliberately omits `.read`: the payload is write-only.
    KeyType { name: "logon",   readable: false, updatable: true,  is_keyring: false,
              vet_colon: true,  restrictable: false, payload_rule: PayloadRule::UserDefined, describes_itself: false, net_domain: false },
    // `big_key` takes a payload up to 1 MiB. Linux offloads anything past a
    // small threshold into an encrypted shmem file so it can be swapped; that
    // is a storage decision with no syscall-visible effect — the same bytes
    // come back out of `KEYCTL_READ` either way — so the payload is held
    // inline here. What IS syscall-visible is the flat 16-byte quota charge,
    // which is why a big_key does not consume the owner's byte quota in
    // proportion to its size.
    KeyType { name: "big_key", readable: true,  updatable: true,  is_keyring: false,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::Big, describes_itself: false, net_domain: false },
    // The instantiation authorisation token. Registered like any other type,
    // and unreachable from userspace by name for the same reason Linux's is:
    // `key_get_type_from_user` rejects a `.`-prefixed name with EPERM, so no
    // caller can `add_key` one or aim `KEYCTL_SEARCH` at the type. Its payload
    // is the requester's callout info, which `KEYCTL_READ` hands to the helper
    // holding the token — that is how `/sbin/request-key` learns what it was
    // asked to build.
    KeyType { name: REQKEY_AUTH_TYPE, readable: true, updatable: false, is_keyring: false,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::Empty, describes_itself: false, net_domain: false },
    // An asymmetric key holds parsed public-key material. It has no `read`
    // method — the point of the type is that operations happen inside the
    // kernel and the key material never comes back out — and no `update`: a
    // key whose material could be swapped underneath a caller that already
    // queried it would let a signature be verified against a different key
    // than the one that was checked.
    KeyType { name: ASYMMETRIC_KEY_TYPE, readable: false, updatable: false, is_keyring: false,
              vet_colon: false, restrictable: true, payload_rule: PayloadRule::Asymmetric,
              describes_itself: true, net_domain: false },
    // The kernel's DNS answer cache. Its keys are NETWORK-NAMESPACE scoped:
    // the same name resolves to different addresses on different networks, so
    // an answer cached by a task in one network namespace must never be found
    // by a task in another. That scoping is the domain tag, and this is the
    // type that consumes it.
    KeyType { name: DNS_RESOLVER_KEY_TYPE, readable: true, updatable: false, is_keyring: false,
              vet_colon: false, restrictable: false, payload_rule: PayloadRule::UserDefined,
              describes_itself: false, net_domain: true },
];

/// The authorisation-token type, for the paths that mint one directly.
/// # C: O(types)
pub fn auth_type() -> &'static KeyType {
    lookup(REQKEY_AUTH_TYPE).expect("the authorisation-token type is registered unconditionally")
}

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
        // The blob's own decoding is the length rule; `preparse_blob` applies
        // it, because a length test cannot tell a certificate from noise.
        PayloadRule::Asymmetric =>
            if len == 0 || len > BIG_PAYLOAD_MAX || !have_ptr { Err(Errno::Einval) } else { Ok(()) },
    }
}

/// The part of `preparse` that only the payload's own parser can answer: does
/// the blob decode, and what description does it propose for itself? A type
/// with no parser accepts any payload its length rule allowed and proposes
/// nothing. # C: O(len)
pub struct PreparsedPayload {
    pub description: Option<String>,
    pub asymmetric_ids: Vec<Vec<u8>>,
    pub asymmetric_name_id: Option<Vec<u8>>,
}

/// Decode the type-owned metadata that instantiation keeps with the payload.
/// # C: O(len)
pub fn preparse_blob(t: &KeyType, payload: &[u8]) -> Result<PreparsedPayload, Errno> {
    match t.payload_rule {
        PayloadRule::Asymmetric => {
            let key = pkey::AsymmetricKey::parse(payload)
                .map_err(super::ops::pkey::errno_for)?;
            Ok(PreparsedPayload {
                description: key.description, asymmetric_ids: key.ids, asymmetric_name_id: key.name_id,
            })
        }
        _ => Ok(PreparsedPayload {
            description: None, asymmetric_ids: Vec::new(), asymmetric_name_id: None,
        }),
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
        PayloadRule::Asymmetric => ASYMMETRIC_QUOTA,
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
