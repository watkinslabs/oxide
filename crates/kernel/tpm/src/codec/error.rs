// Coder failures. Every one of these is a malformed buffer, never a device
// error — a device error arrives as a response code and is decoded by `rc`.

use crate::rc::Rc;

/// Why a buffer could not be built or parsed.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CodecError {
    /// Buffer is shorter than the fixed header.
    ShortHeader { got: usize },
    /// The length field is smaller than the header it sits in.
    LengthUnderHeader { declared: u32 },
    /// The length field disagrees with how many bytes are actually present.
    LengthMismatch { declared: u32, actual: usize },
    /// Structure tag is not one this kernel produces or accepts.
    BadTag(u16),
    /// A field ran past the end of the buffer.
    Truncated { need: usize, have: usize },
    /// Appending would exceed the transport's command buffer.
    Overflow { limit: usize },
    /// The response body was shorter than the command requires.
    ShortBody { need: usize, have: usize },
    /// The device reported a failure.
    Device(Rc),
    /// A caller-supplied value is outside what the command accepts.
    BadArgument(&'static str),
}
