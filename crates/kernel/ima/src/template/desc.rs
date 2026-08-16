// Template descriptors: the named formats and the field identifiers a format
// expands to. A name that resolves to the wrong field list changes what every
// later attestation quote covers.

use alloc::vec::Vec;

use crate::limits::{IMA_TEMPLATE_FIELD_ID_MAX_LEN, IMA_TEMPLATE_NUM_FIELDS_MAX};

/// A template field identity.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FieldId {
    /// Fixed-size file digest, no algorithm prefix.
    D,
    /// Event name, truncated to the fixed maximum.
    N,
    /// File digest prefixed `algo:\0`.
    DNg,
    /// File digest prefixed `type:algo:\0`.
    DNgV2,
    /// Event name, no length limit.
    NNg,
    /// File signature from the integrity xattr.
    Sig,
    /// Measured buffer contents.
    Buf,
    /// Digest matching the appended module signature.
    DModsig,
    /// Raw appended module signature.
    Modsig,
    /// Portable EVM signature.
    Evmsig,
    /// Inode owner.
    Iuid,
    /// Inode group.
    Igid,
    /// Inode mode.
    Imode,
    /// Names of the EVM-protected xattrs present.
    Xattrnames,
    /// Lengths of those xattr values.
    Xattrlengths,
    /// Those xattr values.
    Xattrvalues,
}

impl FieldId {
    /// Field for a format identifier, `None` when unknown. # C: O(n)
    pub fn by_id(id: &str) -> Option<Self> {
        if id.len() > IMA_TEMPLATE_FIELD_ID_MAX_LEN { return None; }
        Some(match id {
            "d" => Self::D, "n" => Self::N, "d-ng" => Self::DNg, "d-ngv2" => Self::DNgV2,
            "n-ng" => Self::NNg, "sig" => Self::Sig, "buf" => Self::Buf,
            "d-modsig" => Self::DModsig, "modsig" => Self::Modsig, "evmsig" => Self::Evmsig,
            "iuid" => Self::Iuid, "igid" => Self::Igid, "imode" => Self::Imode,
            "xattrnames" => Self::Xattrnames, "xattrlengths" => Self::Xattrlengths,
            "xattrvalues" => Self::Xattrvalues,
            _ => return None,
        })
    }

    /// Format identifier of this field. # C: O(1)
    pub fn id(self) -> &'static str {
        match self {
            Self::D => "d", Self::N => "n", Self::DNg => "d-ng", Self::DNgV2 => "d-ngv2",
            Self::NNg => "n-ng", Self::Sig => "sig", Self::Buf => "buf",
            Self::DModsig => "d-modsig", Self::Modsig => "modsig", Self::Evmsig => "evmsig",
            Self::Iuid => "iuid", Self::Igid => "igid", Self::Imode => "imode",
            Self::Xattrnames => "xattrnames", Self::Xattrlengths => "xattrlengths",
            Self::Xattrvalues => "xattrvalues",
        }
    }
}

/// A named template and the format string it expands.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TemplateDesc {
    pub name: &'static str,
    pub fmt: &'static str,
}

/// Name of the original template, whose record layout omits the per-entry data
/// length and whose digest field carries no length prefix.
pub const TEMPLATE_IMA_NAME: &str = "ima";
/// Format of the original template.
pub const TEMPLATE_IMA_FMT: &str = "d|n";

/// The built-in templates, in registry order.
pub const BUILTIN: [TemplateDesc; 8] = [
    TemplateDesc { name: TEMPLATE_IMA_NAME, fmt: TEMPLATE_IMA_FMT },
    TemplateDesc { name: "ima-ng", fmt: "d-ng|n-ng" },
    TemplateDesc { name: "ima-sig", fmt: "d-ng|n-ng|sig" },
    TemplateDesc { name: "ima-ngv2", fmt: "d-ngv2|n-ng" },
    TemplateDesc { name: "ima-sigv2", fmt: "d-ngv2|n-ng|sig" },
    TemplateDesc { name: "ima-buf", fmt: "d-ng|n-ng|buf" },
    TemplateDesc { name: "ima-modsig", fmt: "d-ng|n-ng|sig|d-modsig|modsig" },
    TemplateDesc {
        name: "evm-sig",
        fmt: "d-ng|n-ng|evmsig|xattrnames|xattrlengths|xattrvalues|iuid|igid|imode",
    },
];

/// Resolve a template by name or by its exact format string. # C: O(n)
pub fn lookup_desc(name: &str) -> Option<&'static TemplateDesc> {
    BUILTIN.iter().find(|d| d.name == name || d.fmt == name)
}

/// Expand a format string to its field list. Rejects an unknown field
/// identifier, an empty format, and more fields than a template may hold.
/// # C: O(n)
pub fn parse_fmt(fmt: &str) -> Option<Vec<FieldId>> {
    if fmt.is_empty() { return None; }
    let mut out = Vec::new();
    for part in fmt.split('|') {
        if out.len() == IMA_TEMPLATE_NUM_FIELDS_MAX { return None; }
        out.push(FieldId::by_id(part)?);
    }
    Some(out)
}

impl TemplateDesc {
    /// Field list of this template. # C: O(n)
    pub fn fields(&self) -> Vec<FieldId> {
        parse_fmt(self.fmt).expect("builtin template format is well formed")
    }
    /// True for the original template, whose record layout differs. # C: O(1)
    pub fn is_original(&self) -> bool { self.name == TEMPLATE_IMA_NAME }
    /// Whether the template references an appended module signature. # C: O(n)
    pub fn has_modsig(&self) -> bool {
        self.fields().iter().any(|f| matches!(f, FieldId::Modsig | FieldId::DModsig))
    }
    /// The name a measurement record carries: the template's name, or its
    /// format string when the template is an unnamed custom format. # C: O(1)
    pub fn record_name(&self) -> &str {
        if self.name.is_empty() { self.fmt } else { self.name }
    }
}
