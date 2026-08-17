// A measurement record: the fields, the digest computed over them, and the two
// renderings the measurement list exposes.
//
// Record layout (binary): PCR index (u32), template digest (digest-length
// bytes), template-name length (u32), template name, then — for every template
// except the original one — the total template-data length (u32), then the
// fields. Each field is length-prefixed (u32) except the original template's
// fixed-size digest field, which carries no prefix; the original template's
// name field is prefixed with the length of its text, excluding the NUL.
//
// All multi-byte integers are little-endian, which is both the canonical
// measurement-list encoding and the native encoding of this kernel's targets.

use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;

use crate::hash::{hex, HashAlgo};
use crate::limits::IMA_EVENT_NAME_LEN_MAX;
use crate::template::desc::{FieldId, TemplateDesc};
use crate::template::event::Event;
use crate::template::fields::{init_field, DataFmt, FieldData};

/// A built measurement record, before it is appended to the list.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TemplateEntry {
    pub pcr: u32,
    pub desc: TemplateDesc,
    pub ids: Vec<FieldId>,
    pub fields: Vec<FieldData>,
}

impl TemplateEntry {
    /// Serialise every field of `desc` for `ev`. # C: O(total)
    pub fn build(desc: &TemplateDesc, ev: &Event<'_>, pcr: u32) -> Self {
        let ids = desc.fields();
        let fields = ids.iter().map(|id| init_field(*id, ev)).collect();
        Self { pcr, desc: *desc, ids, fields }
    }

    /// Total serialised length of the fields, counting each field's own length
    /// prefix. # C: O(n)
    pub fn data_len(&self) -> u32 {
        self.fields.iter().map(|f| 4 + f.len()).sum()
    }

    /// Digest over the fields, in template order. Every field is hashed with a
    /// leading little-endian length except in the original template, where the
    /// fields are hashed bare and the name field is padded with NULs to its
    /// fixed maximum plus one. `None` when this kernel has no engine for
    /// `algo`. # C: O(total)
    pub fn template_digest(&self, algo: HashAlgo) -> Option<Vec<u8>> {
        let mut buf: Vec<u8> = Vec::new();
        let original = self.desc.is_original();
        for (i, f) in self.fields.iter().enumerate() {
            if !original {
                buf.extend_from_slice(&f.len().to_le_bytes());
                buf.extend_from_slice(&f.bytes);
            } else if self.ids[i] == FieldId::N {
                let mut padded = vec![0u8; IMA_EVENT_NAME_LEN_MAX + 1];
                let n = core::cmp::min(f.bytes.len(), padded.len());
                padded[..n].copy_from_slice(&f.bytes[..n]);
                buf.extend_from_slice(&padded);
            } else {
                buf.extend_from_slice(&f.bytes);
            }
        }
        algo.digest(&[&buf])
    }

    /// The record as `binary_runtime_measurements` emits it. # C: O(total)
    pub fn binary_record(&self, template_digest: &[u8]) -> Vec<u8> {
        let name = self.desc.record_name();
        let mut out = Vec::new();
        out.extend_from_slice(&self.pcr.to_le_bytes());
        out.extend_from_slice(template_digest);
        out.extend_from_slice(&(name.len() as u32).to_le_bytes());
        out.extend_from_slice(name.as_bytes());
        let original = self.desc.is_original();
        if !original { out.extend_from_slice(&self.data_len().to_le_bytes()); }
        for (i, f) in self.fields.iter().enumerate() {
            if original && self.ids[i] == FieldId::D {
                out.extend_from_slice(&f.bytes);
                continue;
            }
            let len = if original && self.ids[i] == FieldId::N {
                // The original template's name field reports the length of its
                // text, stopping at the NUL the field carries.
                f.bytes.iter().position(|b| *b == 0).unwrap_or(f.bytes.len()) as u32
            } else {
                f.len()
            };
            out.extend_from_slice(&len.to_le_bytes());
            if len == 0 { continue; }
            out.extend_from_slice(&f.bytes[..len as usize]);
        }
        out
    }

    /// The record as `ascii_runtime_measurements` renders it. # C: O(total)
    pub fn ascii_record(&self, template_digest: &[u8]) -> String {
        let mut s = String::new();
        // PCR index right-aligned in two columns, as the list has always shown it.
        if self.pcr < 10 { s.push(' '); }
        s.push_str(&int_str(self.pcr as u64));
        s.push(' ');
        s.push_str(&hex(template_digest));
        s.push(' ');
        s.push_str(self.desc.record_name());
        for f in &self.fields {
            s.push(' ');
            if f.is_empty() { continue; }
            s.push_str(&ascii_field(f));
        }
        s.push('\n');
        s
    }
}

/// A field as the ASCII list renders it. # C: O(n)
pub fn ascii_field(f: &FieldData) -> String {
    match f.fmt {
        DataFmt::Digest | DataFmt::Hex => hex(&f.bytes),
        DataFmt::DigestWithAlgo | DataFmt::DigestWithTypeAndAlgo => {
            // The prefix is printed as text up to its NUL; the digest follows
            // the NUL that terminates it.
            match f.bytes.iter().rposition(|b| *b == b':') {
                Some(0) | None => hex(&f.bytes),
                Some(colon) => {
                    let mut s = String::new();
                    let nul = f.bytes.iter().position(|b| *b == 0).unwrap_or(f.bytes.len());
                    s.push_str(&String::from_utf8_lossy(&f.bytes[..nul]));
                    let start = colon + 2;
                    if start < f.bytes.len() { s.push_str(&hex(&f.bytes[start..])); }
                    s
                }
            }
        }
        DataFmt::Str => {
            let nul = f.bytes.iter().position(|b| *b == 0).unwrap_or(f.bytes.len());
            String::from_utf8_lossy(&f.bytes[..nul]).into_owned()
        }
        DataFmt::Uint => {
            let v = match f.bytes.len() {
                1 => f.bytes[0] as u64,
                2 => u16::from_le_bytes([f.bytes[0], f.bytes[1]]) as u64,
                4 => u32::from_le_bytes([f.bytes[0], f.bytes[1], f.bytes[2], f.bytes[3]]) as u64,
                8 => u64::from_le_bytes(f.bytes[..8].try_into().unwrap()),
                _ => return String::new(),
            };
            int_str(v)
        }
    }
}

fn int_str(mut v: u64) -> String {
    if v == 0 { return String::from("0"); }
    let mut d = [0u8; 20];
    let mut i = d.len();
    while v > 0 { i -= 1; d[i] = b'0' + (v % 10) as u8; v /= 10; }
    String::from_utf8_lossy(&d[i..]).into_owned()
}
