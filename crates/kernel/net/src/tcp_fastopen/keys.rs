// The keys a fast-open cookie is minted from, and the text form the sysctl
// leaf shows and accepts.
//
// Two keys, not one: rotating a server's key would otherwise invalidate every
// cookie it has already handed out, so the previous key is kept as a backup
// that still verifies while clients pick the new one up. The active key is the
// only one a fresh cookie is minted from.
//
// The text form is four hexadecimal 32-bit groups per key, dash-separated,
// with a comma between the active key and the backup. Each group is the
// little-endian reading of four key bytes, so the bytes an administrator sees
// in the file are the bytes a `TCP_FASTOPEN_KEY` write would have supplied.

extern crate alloc;
use alloc::vec::Vec;

/// One key. The cookie construction is keyed on exactly this many bytes.
pub const KEY_LEN: usize = 16;

/// An active key plus a backup, as `TCP_FASTOPEN_KEY` carries them.
pub const KEY_BUF_LEN: usize = KEY_LEN * 2;

/// Bytes of one text group, and groups per key.
const GROUP_BYTES: usize = 4;
const GROUPS: usize = KEY_LEN / GROUP_BYTES;
/// Hex digits one group prints as, and the most a write may carry in one.
const GROUP_DIGITS: usize = GROUP_BYTES * 2;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Key([u8; KEY_LEN]);

impl Key {
    /// # C: O(1)
    pub fn new(raw: [u8; KEY_LEN]) -> Self { Self(raw) }

    /// # C: O(1)
    pub fn as_bytes(&self) -> &[u8; KEY_LEN] { &self.0 }
}

/// The keys one owner mints and verifies with.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct KeyCtx {
    /// The key a fresh cookie is minted from.
    pub primary: Key,
    /// The previous key, still accepted while a rotation propagates.
    pub backup: Option<Key>,
}

impl KeyCtx {
    /// # C: O(1)
    pub fn new(primary: Key, backup: Option<Key>) -> Self { Self { primary, backup } }

    /// The keys as `TCP_FASTOPEN_KEY` carries them: the active key, followed
    /// by the backup when there is one. # C: O(KEY_BUF_LEN)
    pub fn bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(KEY_BUF_LEN);
        out.extend_from_slice(&self.primary.0);
        if let Some(backup) = self.backup { out.extend_from_slice(&backup.0); }
        out
    }

    /// Read a `TCP_FASTOPEN_KEY` write: one key, or an active plus a backup.
    /// Any other length names no key pair. # C: O(len)
    pub fn from_bytes(raw: &[u8]) -> Option<Self> {
        let mut primary = [0u8; KEY_LEN];
        match raw.len() {
            KEY_LEN => { primary.copy_from_slice(raw); Some(Self::new(Key(primary), None)) }
            KEY_BUF_LEN => {
                primary.copy_from_slice(&raw[..KEY_LEN]);
                let mut backup = [0u8; KEY_LEN];
                backup.copy_from_slice(&raw[KEY_LEN..]);
                Some(Self::new(Key(primary), Some(Key(backup))))
            }
            _ => None,
        }
    }
}

/// The sysctl's text form. A namespace that has drawn no key yet still reads
/// as one key, all zero — the file names the shape of the value even when
/// nothing has been minted from it. # C: O(KEY_BUF_LEN)
pub fn format_hex(ctx: Option<&KeyCtx>) -> Vec<u8> {
    let mut out = Vec::new();
    match ctx {
        None => write_key(&mut out, &Key([0u8; KEY_LEN])),
        Some(ctx) => {
            write_key(&mut out, &ctx.primary);
            if let Some(backup) = &ctx.backup { out.push(b','); write_key(&mut out, backup); }
        }
    }
    out
}

fn write_key(out: &mut Vec<u8>, key: &Key) {
    for group in 0..GROUPS {
        if group != 0 { out.push(b'-'); }
        let start = group * GROUP_BYTES;
        let mut raw = [0u8; GROUP_BYTES];
        raw.copy_from_slice(&key.0[start..start + GROUP_BYTES]);
        let value = u32::from_le_bytes(raw);
        for digit in (0..GROUP_DIGITS).rev() {
            let nibble = ((value >> (digit * 4)) & 0xf) as u8;
            out.push(if nibble < 10 { b'0' + nibble } else { b'a' + nibble - 10 });
        }
    }
}

/// Read the sysctl's text form. A comma introduces the backup key; text after
/// the fourth group of a key is ignored, which is what lets the value be
/// written back exactly as it was read. # C: O(len)
pub fn parse_hex(text: &[u8]) -> Option<KeyCtx> {
    let text = trim(text);
    let (first, rest) = match text.iter().position(|b| *b == b',') {
        Some(at) => (&text[..at], Some(&text[at + 1..])),
        None => (text, None),
    };
    let primary = parse_key(first)?;
    let backup = match rest { Some(raw) => Some(parse_key(trim(raw))?), None => None };
    Some(KeyCtx::new(primary, backup))
}

fn trim(text: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = text.len();
    while start < end && text[start].is_ascii_whitespace() { start += 1; }
    while end > start && text[end - 1].is_ascii_whitespace() { end -= 1; }
    &text[start..end]
}

fn parse_key(text: &[u8]) -> Option<Key> {
    let mut raw = [0u8; KEY_LEN];
    let mut at = 0;
    for group in 0..GROUPS {
        if group != 0 {
            if text.get(at) != Some(&b'-') { return None; }
            at += 1;
        }
        let (value, len) = parse_group(&text[at..])?;
        at += len;
        raw[group * GROUP_BYTES..(group + 1) * GROUP_BYTES]
            .copy_from_slice(&value.to_le_bytes());
    }
    Some(Key(raw))
}

fn parse_group(text: &[u8]) -> Option<(u32, usize)> {
    let mut value: u32 = 0;
    let mut len = 0;
    // `sscanf("%x")` accepts an arbitrarily long hexadecimal word and stores
    // its low 32 bits in the destination `u32`. Keep consuming rather than
    // treating digit nine as the separator position.
    while len < text.len() {
        let digit = match text[len] {
            b'0'..=b'9' => text[len] - b'0',
            b'a'..=b'f' => text[len] - b'a' + 10,
            b'A'..=b'F' => text[len] - b'A' + 10,
            _ => break,
        };
        value = value.wrapping_shl(4) | digit as u32;
        len += 1;
    }
    if len == 0 { None } else { Some((value, len)) }
}

#[cfg(test)]
#[path = "keys_tests.rs"]
mod tests;
