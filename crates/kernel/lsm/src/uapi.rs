// Numbers userspace sees: module identities, attribute selectors and the
// context record the attribute calls exchange.

/// Undefined module identity. Never used outside the kernel.
pub const LSM_ID_UNDEF: u64 = 0;
pub const LSM_ID_CAPABILITY: u64 = 100;
pub const LSM_ID_SELINUX: u64 = 101;
pub const LSM_ID_SMACK: u64 = 102;
pub const LSM_ID_TOMOYO: u64 = 103;
pub const LSM_ID_APPARMOR: u64 = 104;
pub const LSM_ID_YAMA: u64 = 105;
pub const LSM_ID_LOADPIN: u64 = 106;
pub const LSM_ID_SAFESETID: u64 = 107;
pub const LSM_ID_LOCKDOWN: u64 = 108;
pub const LSM_ID_BPF: u64 = 109;
pub const LSM_ID_LANDLOCK: u64 = 110;
pub const LSM_ID_IMA: u64 = 111;
pub const LSM_ID_EVM: u64 = 112;
pub const LSM_ID_IPE: u64 = 113;

/// First identity a module may claim. Everything below is reserved.
pub const LSM_ID_FIRST_ASSIGNED: u64 = 100;

pub const LSM_ATTR_UNDEF: u32 = 0;
pub const LSM_ATTR_CURRENT: u32 = 100;
pub const LSM_ATTR_EXEC: u32 = 101;
pub const LSM_ATTR_FSCREATE: u32 = 102;
pub const LSM_ATTR_KEYCREATE: u32 = 103;
pub const LSM_ATTR_PREV: u32 = 104;
pub const LSM_ATTR_SOCKCREATE: u32 = 105;

/// Attribute call asked for exactly one module's answer.
pub const LSM_FLAG_SINGLE: u32 = 0x0001;

/// Byte length of the fixed head of one context record: four 64-bit words
/// (identity, flags, total length, context length) ahead of the context
/// bytes themselves.
pub const LSM_CTX_HEAD_BYTES: usize = 32;

/// Offsets of the four words in one context record.
pub const LSM_CTX_OFF_ID: usize = 0;
pub const LSM_CTX_OFF_FLAGS: usize = 8;
pub const LSM_CTX_OFF_LEN: usize = 16;
pub const LSM_CTX_OFF_CTX_LEN: usize = 24;

/// Whether an identity is one this kernel knows. # C: O(1)
pub fn id_name(id: u64) -> Option<&'static str> {
    Some(match id {
        LSM_ID_CAPABILITY => "capability",
        LSM_ID_SELINUX => "selinux",
        LSM_ID_SMACK => "smack",
        LSM_ID_TOMOYO => "tomoyo",
        LSM_ID_APPARMOR => "apparmor",
        LSM_ID_YAMA => "yama",
        LSM_ID_LOADPIN => "loadpin",
        LSM_ID_SAFESETID => "safesetid",
        LSM_ID_LOCKDOWN => "lockdown",
        LSM_ID_BPF => "bpf",
        LSM_ID_LANDLOCK => "landlock",
        LSM_ID_IMA => "ima",
        LSM_ID_EVM => "evm",
        LSM_ID_IPE => "ipe",
        _ => return None,
    })
}

#[cfg(test)]
#[path = "tests/uapi.rs"]
mod tests;
