//! ExtTextOutW admission for ScriptStringOut's typed glyph/paired-delta flags.

use syscall::nt_native_gdi as abi;

const RECT_FLAGS: u32 = abi::OPAQUE | abi::CLIPPED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Request {
    pub flags: u32,
    pub rect: Option<u64>,
    pub text: u64,
    pub count: u32,
    pub advances: Option<u64>,
    pub code_page: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Error { InvalidFlags, InvalidCodePage, MissingRect, MissingText, Overflow, TooManyUnits }

/// Preserve ScriptStringOut flags and derive pointer spans without touching user memory.
/// # C: O(1)
pub(crate) fn validate(flags: u32, rect: u64, text: u64, count: u32, advances: u64, code_page: u32) -> Result<Request, Error> {
    const ALL_FLAGS: u32 = RECT_FLAGS | abi::GLYPH_INDEX | abi::IGNORE_LANGUAGE | abi::PDY;
    if flags & !ALL_FLAGS != 0 { return Err(Error::InvalidFlags); }
    if code_page != 0 { return Err(Error::InvalidCodePage); }
    if count > abi::MAX_UNITS { return Err(Error::TooManyUnits); }
    let text_bytes = (count as u64).checked_mul(2).ok_or(Error::Overflow)?;
    if count != 0 && (text == 0 || text.checked_add(text_bytes).is_none()) { return Err(Error::MissingText); }
    let advance_stride = if flags & abi::PDY != 0 { 2 } else { 1 };
    let advance_count = count as u64 * advance_stride;
    if advances != 0 && advances.checked_add(advance_count.checked_mul(4).ok_or(Error::Overflow)?).is_none() { return Err(Error::Overflow); }
    let (flags, rect) = if rect == 0 {
        (flags & !RECT_FLAGS, None)
    } else if rect.checked_add(16).is_none() {
        return Err(Error::MissingRect);
    } else { (flags, Some(rect)) };
    Ok(Request { flags, rect, text, count, advances: (advances != 0).then_some(advances), code_page })
}

#[cfg(test)]
#[path = "tests/text_output.rs"]
mod tests;
