// Field serialisation. Every byte here lands in the measurement record and in
// the template digest that gets extended into a PCR, so the encodings are
// exact: a string field carries its terminating NUL inside its own length, a
// digest field's algorithm prefix ends with a colon AND a NUL, and a field with
// nothing to say is present with length zero rather than absent.

use alloc::string::String;
use alloc::vec::Vec;

use crate::hash::HashAlgo;
use crate::limits::{IMA_DIGEST_SIZE, IMA_EVENT_NAME_LEN_MAX};
use crate::template::desc::FieldId;
use crate::template::event::Event;
use crate::uapi::XattrType;

/// How a field's bytes are to be rendered in the ASCII list.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DataFmt {
    Digest,
    DigestWithAlgo,
    DigestWithTypeAndAlgo,
    Str,
    Hex,
    Uint,
}

/// One serialised field: its bytes and how to render them.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct FieldData {
    pub bytes: Vec<u8>,
    pub fmt: DataFmt,
}

impl FieldData {
    /// Length as the record's length prefix reports it. # C: O(1)
    pub fn len(&self) -> u32 { self.bytes.len() as u32 }
    /// True when the field carries nothing. # C: O(1)
    pub fn is_empty(&self) -> bool { self.bytes.is_empty() }
}

/// The digest-type prefix a version-2 digest field names.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum DigestType { Ima, Verity }

impl DigestType {
    /// Prefix spelling. # C: O(1)
    pub fn name(self) -> &'static str {
        match self { Self::Ima => "ima", Self::Verity => "verity" }
    }
}

/// Wrap raw field bytes. A string field is stored with a terminating NUL
/// counted in its length, and every space in the text becomes an underscore so
/// the ASCII list stays splittable on spaces. # C: O(n)
pub fn write_field_data(data: &[u8], fmt: DataFmt) -> FieldData {
    if fmt == DataFmt::Str {
        let mut bytes = Vec::with_capacity(data.len() + 1);
        for b in data { bytes.push(if *b == b' ' { b'_' } else { *b }); }
        bytes.push(0);
        FieldData { bytes, fmt }
    } else {
        FieldData { bytes: data.to_vec(), fmt }
    }
}

/// Serialise a digest field. With no algorithm the field is the bare digest;
/// with an algorithm it is `algo:\0digest`; with a type as well it is
/// `type:algo:\0digest`. A violation carries no digest, and the field is then
/// the prefix followed by a run of zero bytes as long as the digest would have
/// been. # C: O(n)
pub fn digest_field(digest: Option<&[u8]>, dtype: Option<DigestType>, algo: Option<HashAlgo>)
    -> FieldData
{
    let mut prefix = String::new();
    let fmt = match (dtype, algo) {
        (Some(t), Some(a)) => {
            prefix.push_str(t.name()); prefix.push(':');
            prefix.push_str(a.name()); prefix.push(':');
            DataFmt::DigestWithTypeAndAlgo
        }
        (None, Some(a)) => {
            prefix.push_str(a.name()); prefix.push(':');
            DataFmt::DigestWithAlgo
        }
        _ => DataFmt::Digest,
    };
    let mut bytes = Vec::new();
    bytes.extend_from_slice(prefix.as_bytes());
    if !prefix.is_empty() { bytes.push(0); }
    match digest {
        Some(d) => bytes.extend_from_slice(d),
        None => {
            let n = algo.map(|a| a.size()).unwrap_or(IMA_DIGEST_SIZE);
            bytes.resize(bytes.len() + n, 0);
        }
    }
    FieldData { bytes, fmt }
}

/// Serialise one field of a template for `event`. # C: O(n)
pub fn init_field(id: FieldId, ev: &Event<'_>) -> FieldData {
    match id {
        FieldId::D => {
            if ev.violation { return digest_field(None, None, None); }
            let d = ev.original_template_digest();
            digest_field(d, None, None)
        }
        FieldId::N => {
            let n = ev.filename.as_bytes();
            let n = if n.len() > IMA_EVENT_NAME_LEN_MAX { &n[..IMA_EVENT_NAME_LEN_MAX] } else { n };
            write_field_data(n, DataFmt::Str)
        }
        FieldId::NNg => write_field_data(ev.filename.as_bytes(), DataFmt::Str),
        FieldId::DNg => {
            if ev.violation { return digest_field(None, None, Some(ev.algo)); }
            digest_field(ev.digest, None, Some(ev.algo))
        }
        FieldId::DNgV2 => {
            let t = if ev.verity { DigestType::Verity } else { DigestType::Ima };
            if ev.violation { return digest_field(None, Some(DigestType::Ima), Some(ev.algo)); }
            digest_field(ev.digest, Some(t), Some(ev.algo))
        }
        FieldId::Sig => {
            match ev.ima_xattr_type() {
                Some(XattrType::EvmImaDigsig) | Some(XattrType::ImaVerityDigsig) =>
                    write_field_data(ev.xattr.unwrap_or(&[]), DataFmt::Hex),
                _ => init_field(FieldId::Evmsig, ev),
            }
        }
        FieldId::Evmsig => {
            match ev.evm_xattr_type() {
                Some(XattrType::EvmPortableDigsig) =>
                    write_field_data(ev.evm_xattr.unwrap_or(&[]), DataFmt::Hex),
                _ => empty(DataFmt::Hex),
            }
        }
        FieldId::Buf => match ev.buf {
            Some(b) if !b.is_empty() => write_field_data(b, DataFmt::Hex),
            _ => empty(DataFmt::Hex),
        },
        FieldId::DModsig => match ev.modsig_digest {
            _ if ev.modsig.is_none() => empty(DataFmt::DigestWithAlgo),
            Some((a, d)) if !ev.violation => digest_field(Some(d), None, Some(a)),
            _ => digest_field(None, None, Some(HashAlgo::Sha1)),
        },
        FieldId::Modsig => match ev.modsig {
            Some(m) => write_field_data(m, DataFmt::Hex),
            None => empty(DataFmt::Hex),
        },
        FieldId::Iuid => match ev.inode {
            Some(i) => write_field_data(&i.uid.to_le_bytes(), DataFmt::Uint),
            None => empty(DataFmt::Uint),
        },
        FieldId::Igid => match ev.inode {
            Some(i) => write_field_data(&i.gid.to_le_bytes(), DataFmt::Uint),
            None => empty(DataFmt::Uint),
        },
        FieldId::Imode => match ev.inode {
            Some(i) => write_field_data(&i.mode.to_le_bytes(), DataFmt::Uint),
            None => empty(DataFmt::Uint),
        },
        FieldId::Xattrnames => bytes_or_empty(ev.xattr_names),
        FieldId::Xattrlengths => bytes_or_empty(ev.xattr_lengths),
        FieldId::Xattrvalues => bytes_or_empty(ev.xattr_values),
    }
}

fn empty(fmt: DataFmt) -> FieldData { FieldData { bytes: Vec::new(), fmt } }

fn bytes_or_empty(b: Option<&[u8]>) -> FieldData {
    match b { Some(v) if !v.is_empty() => write_field_data(v, DataFmt::Hex), _ => empty(DataFmt::Hex) }
}
