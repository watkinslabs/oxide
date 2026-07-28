// Registered key types — Linux `key_type_lookup` (`security/keys/key.c`) over
// the `key_types_list` that each type's `register_key_type` populates. An
// unregistered type name is ENODEV out of `key_create_or_update` and ENOKEY
// out of `key_type_lookup` itself, which is what `KEYCTL_SEARCH` and
// `KEYCTL_RESTRICT_KEYRING` surface.
//
// The registered set is this kernel's configuration, mirroring
// `security/keys/{keyring,user_defined}.c` — the three types built
// unconditionally by Linux. `big_key`, `asymmetric`, `encrypted` and
// `trusted` are separate CONFIG symbols whose payload machinery (shmem
// offload, X.509 parsing, TPM) this kernel does not build, so their names are
// unregistered exactly as on a `CONFIG_BIG_KEYS=n CONFIG_ASYMMETRIC_KEY_TYPE=n
// CONFIG_ENCRYPTED_KEYS=n CONFIG_TRUSTED_KEYS=n` Linux.

use syscall::errno::Errno;
use super::uapi::*;

/// The `struct key_type` fields the permission/perm-default logic consults.
pub struct KeyType {
    pub name: &'static str,
    /// `type->read` present — absent means `KEYCTL_READ` is EOPNOTSUPP.
    pub readable: bool,
    /// `type->update` present — absent means `add_key` on an existing
    /// type+description mints a second key instead of updating, and
    /// `KEYCTL_UPDATE` is EOPNOTSUPP.
    pub updatable: bool,
    /// `type == &key_type_keyring`.
    pub is_keyring: bool,
    /// `type->vet_description` present and requiring `subsystem:key` form
    /// (`logon_vet_description`, `security/keys/user_defined.c`).
    pub vet_colon: bool,
    /// `type->lookup_restriction` present — absent makes
    /// `KEYCTL_RESTRICT_KEYRING` with this type name ENOENT.
    pub restrictable: bool,
}

/// `key_types_list` in registration order.
static TYPES: &[KeyType] = &[
    KeyType { name: "keyring", readable: true,  updatable: true,  is_keyring: true,
              vet_colon: false, restrictable: false },
    KeyType { name: "user",    readable: true,  updatable: true,  is_keyring: false,
              vet_colon: false, restrictable: false },
    // `key_type_logon` deliberately omits `.read`: the payload is write-only.
    KeyType { name: "logon",   readable: false, updatable: true,  is_keyring: false,
              vet_colon: true,  restrictable: false },
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

/// `logon_vet_description`: require a `subsystem:key` description with a
/// non-empty prefix AND suffix. # C: O(desc)
pub fn vet_description(t: &KeyType, desc: &str) -> Result<(), Errno> {
    if !t.vet_colon { return Ok(()); }
    match desc.find(':') {
        Some(0) | None => Err(Errno::Einval),
        Some(i) if i + 1 == desc.len() => Err(Errno::Einval),
        Some(_) => Ok(()),
    }
}

/// Linux `key_create_or_update` with `KEY_PERM_UNDEF`:
///
/// ```text
/// perm  = KEY_POS_VIEW | KEY_POS_SEARCH | KEY_POS_LINK | KEY_POS_SETATTR;
/// perm |= KEY_USR_VIEW;
/// if (type->read)                             perm |= KEY_POS_READ;
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
