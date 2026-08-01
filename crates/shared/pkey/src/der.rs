// DER decoding: definite-length TLV only, which is what every structure here
// is encoded in. A BER indefinite length, a length that runs past the buffer,
// or a non-minimal multi-byte length is rejected — a permissive decoder is how
// two implementations end up disagreeing about what a signed blob said.

/// Universal tag numbers, and the constructed/context-class bits, as they
/// appear in the identifier octet.
pub const TAG_BOOLEAN: u8 = 0x01;
pub const TAG_INTEGER: u8 = 0x02;
pub const TAG_BIT_STRING: u8 = 0x03;
pub const TAG_OCTET_STRING: u8 = 0x04;
pub const TAG_NULL: u8 = 0x05;
pub const TAG_OID: u8 = 0x06;
pub const TAG_UTF8_STRING: u8 = 0x0c;
pub const TAG_SEQUENCE: u8 = 0x30;
pub const TAG_SET: u8 = 0x31;
pub const TAG_PRINTABLE_STRING: u8 = 0x13;
pub const TAG_IA5_STRING: u8 = 0x16;
/// `[n]` explicit context tag, constructed.
pub const TAG_CONTEXT_CONSTRUCTED: u8 = 0xa0;

/// A decoded element: its identifier octet and its contents.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tlv<'a> {
    pub tag: u8,
    pub value: &'a [u8],
}

/// Anything malformed. The caller maps every one of these to the same errno —
/// a blob either decodes or it does not — but keeping them apart makes a
/// parser test say WHICH rule the input broke.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum DerError {
    /// Ran off the end of the buffer.
    Truncated,
    /// Indefinite length, or a length whose encoding is longer than needed.
    BadLength,
    /// The element is not the tag the caller required.
    WrongTag,
    /// Content that the type's own rules forbid (a negative INTEGER where a
    /// modulus is required, an unused-bits count in a BIT STRING, …).
    BadValue,
    /// Bytes left over after the structure the caller asked for.
    Trailing,
}

/// A cursor over a sequence of TLVs.
pub struct Reader<'a> {
    rest: &'a [u8],
}

impl<'a> Reader<'a> {
    /// # C: O(1)
    pub fn new(buf: &'a [u8]) -> Self { Self { rest: buf } }

    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.rest.is_empty() }

    /// Remaining unread bytes. # C: O(1)
    pub fn rest(&self) -> &'a [u8] { self.rest }

    /// Read the next element whatever its tag. # C: O(1)
    pub fn next(&mut self) -> Result<Tlv<'a>, DerError> {
        let (tlv, rest) = parse_one(self.rest)?;
        self.rest = rest;
        Ok(tlv)
    }

    /// Read the next element and its raw encoding INCLUDING the header — what
    /// a certificate's signed region and its DN blobs are identified by.
    /// # C: O(1)
    pub fn next_raw(&mut self) -> Result<(Tlv<'a>, &'a [u8]), DerError> {
        let start = self.rest;
        let (tlv, rest) = parse_one(self.rest)?;
        let consumed = start.len() - rest.len();
        self.rest = rest;
        Ok((tlv, &start[..consumed]))
    }

    /// Read the next element, requiring `tag`. # C: O(1)
    pub fn expect(&mut self, tag: u8) -> Result<&'a [u8], DerError> {
        let tlv = self.next()?;
        if tlv.tag != tag { return Err(DerError::WrongTag); }
        Ok(tlv.value)
    }

    /// Read the next element only if it carries `tag`; leave the cursor
    /// untouched otherwise. # C: O(1)
    pub fn take_if(&mut self, tag: u8) -> Result<Option<&'a [u8]>, DerError> {
        if self.rest.is_empty() { return Ok(None); }
        let (tlv, rest) = parse_one(self.rest)?;
        if tlv.tag != tag { return Ok(None); }
        self.rest = rest;
        Ok(Some(tlv.value))
    }

    /// Peek the next identifier octet. # C: O(1)
    pub fn peek_tag(&self) -> Option<u8> { self.rest.first().copied() }

    /// Require that nothing follows. # C: O(1)
    pub fn end(&self) -> Result<(), DerError> {
        if self.rest.is_empty() { Ok(()) } else { Err(DerError::Trailing) }
    }
}

/// Decode one element, returning it and the bytes after it. # C: O(1)
pub fn parse_one(buf: &[u8]) -> Result<(Tlv<'_>, &[u8]), DerError> {
    if buf.len() < 2 { return Err(DerError::Truncated); }
    let tag = buf[0];
    let first = buf[1];
    let (len, hdr) = if first & 0x80 == 0 {
        (first as usize, 2usize)
    } else {
        let n = (first & 0x7f) as usize;
        // A length of 0x80 is BER's indefinite form, and a length field longer
        // than a pointer cannot address anything this kernel holds.
        if n == 0 || n > 4 { return Err(DerError::BadLength); }
        if buf.len() < 2 + n { return Err(DerError::Truncated); }
        let mut v: usize = 0;
        for &b in &buf[2..2 + n] { v = (v << 8) | b as usize; }
        // DER requires the shortest length encoding.
        if v < 0x80 || (n > 1 && buf[2] == 0) { return Err(DerError::BadLength); }
        (v, 2 + n)
    };
    let end = hdr.checked_add(len).ok_or(DerError::BadLength)?;
    if buf.len() < end { return Err(DerError::Truncated); }
    Ok((Tlv { tag, value: &buf[hdr..end] }, &buf[end..]))
}

/// Decode a single element that must span the WHOLE buffer with the given tag.
/// # C: O(1)
pub fn parse_exact(buf: &[u8], tag: u8) -> Result<&[u8], DerError> {
    let (tlv, rest) = parse_one(buf)?;
    if tlv.tag != tag { return Err(DerError::WrongTag); }
    if !rest.is_empty() { return Err(DerError::Trailing); }
    Ok(tlv.value)
}

/// Contents of a BIT STRING, requiring a whole number of octets. A key or a
/// signature with a partial trailing octet is not something this kernel has a
/// representation for. # C: O(1)
pub fn bit_string_bytes(value: &[u8]) -> Result<&[u8], DerError> {
    match value.split_first() {
        Some((0, rest)) => Ok(rest),
        Some(_) => Err(DerError::BadValue),
        None => Err(DerError::Truncated),
    }
}

/// A non-negative INTEGER's magnitude bytes, with the DER sign byte removed.
/// A negative value is refused: every integer this crate reads is a modulus,
/// an exponent or a serial number. # C: O(1)
pub fn positive_integer(value: &[u8]) -> Result<&[u8], DerError> {
    match value.split_first() {
        None => Err(DerError::Truncated),
        Some((&f, _)) if f & 0x80 != 0 => Err(DerError::BadValue),
        // A leading zero is the sign byte only when the next octet has its
        // high bit set; DER forbids any other leading zero.
        Some((0, rest)) if !rest.is_empty() => Ok(rest),
        _ => Ok(value),
    }
}
