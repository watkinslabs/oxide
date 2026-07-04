extern crate alloc;

/// Translation output. Holds up to 5 bytes (1 ESC prefix + up to
/// 4 UTF-8 bytes for any Unicode codepoint). `len == 0` ⇒ no mapping.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct Out {
    pub buf: [u8; 5],
    pub len: u8,
}

impl Out {
    /// Empty sentinel — no bytes produced.
    pub const NONE: Self = Self { buf: [0; 5], len: 0 };

    /// Single-byte ASCII shortcut.
    /// # C: O(1)
    pub const fn one(b: u8) -> Self {
        let mut buf = [0u8; 5];
        buf[0] = b;
        Self { buf, len: 1 }
    }

    /// Build from a Unicode codepoint. Encodes to UTF-8 (1..4 bytes).
    /// Returns NONE for codepoint 0.
    /// # C: O(1)
    pub fn from_codepoint(cp: u32) -> Self {
        if cp == 0 {
            return Self::NONE;
        }
        let mut buf = [0u8; 5];
        let n = encode_utf8(cp, &mut buf[..4]);
        Self { buf, len: n as u8 }
    }

    /// Build from a raw byte sequence (≤5 bytes) — for the fixed escape
    /// sequences special keys emit (`ESC [ A`, `ESC [ 5 ~`, `ESC O P`, …).
    /// # C: O(N)
    pub fn seq(bytes: &[u8]) -> Self {
        let mut buf = [0u8; 5];
        let n = if bytes.len() > 5 { 5 } else { bytes.len() };
        let mut i = 0;
        while i < n {
            buf[i] = bytes[i];
            i += 1;
        }
        Self { buf, len: n as u8 }
    }

    /// Prepend ESC (0x1b) for the xterm Meta convention. Caller
    /// ensures `len + 1 <= 5`.
    /// # C: O(1)
    pub fn with_meta(self) -> Self {
        if self.len == 0 || self.len >= 5 {
            return self;
        }
        let mut buf = [0u8; 5];
        buf[0] = 0x1b;
        let mut i = 0;
        while i < self.len as usize {
            buf[i + 1] = self.buf[i];
            i += 1;
        }
        Self {
            buf,
            len: self.len + 1,
        }
    }

    /// Slice of valid bytes — empty for NONE.
    /// # C: O(1)
    pub fn as_bytes(&self) -> &[u8] {
        &self.buf[..self.len as usize]
    }

    /// Iterate produced bytes. Empty for NONE.
    /// # C: O(len)
    pub fn for_each<F: FnMut(u8)>(self, mut f: F) {
        for &b in self.as_bytes() {
            f(b);
        }
    }
}

/// UTF-8-encode `cp` into `out`. Returns the number of bytes written.
/// Replaces invalid codepoints with U+FFFD (3 bytes). `out` must have
/// at least 4 bytes of room.
fn encode_utf8(cp: u32, out: &mut [u8]) -> usize {
    let cp = if cp > 0x10_FFFF || (0xD800..=0xDFFF).contains(&cp) {
        0xFFFD
    } else {
        cp
    };
    if cp < 0x80 {
        out[0] = cp as u8;
        1
    } else if cp < 0x800 {
        out[0] = 0xC0 | (cp >> 6) as u8;
        out[1] = 0x80 | (cp & 0x3F) as u8;
        2
    } else if cp < 0x1_0000 {
        out[0] = 0xE0 | (cp >> 12) as u8;
        out[1] = 0x80 | ((cp >> 6) & 0x3F) as u8;
        out[2] = 0x80 | (cp & 0x3F) as u8;
        3
    } else {
        out[0] = 0xF0 | (cp >> 18) as u8;
        out[1] = 0x80 | ((cp >> 12) & 0x3F) as u8;
        out[2] = 0x80 | ((cp >> 6) & 0x3F) as u8;
        out[3] = 0x80 | (cp & 0x3F) as u8;
        4
    }
}
