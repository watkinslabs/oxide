// Response-code decode. A response code is a bitfield, not an enum: the
// format selector picks between two layouts, and the per-parameter/handle/
// session number lives in bits that must be masked off before a code can be
// compared against a named constant. Getting that mask wrong turns a failure
// into an unrecognised value — which callers then read as "not the error I
// checked for", i.e. as success. This module is the only decoder.

use crate::uapi::{
    RC_LAYER_SHIFT, TPM2_RC_FMT1, TPM2_RC_SUCCESS, TPM2_RC_VER1, TPM2_RC_WARN,
};

/// Format selector: set in format-one codes, clear in format-zero codes.
const FMT1_BIT: u32 = 0x80;
/// Format-one: set when the number field counts a parameter.
const FMT1_P_BIT: u32 = 0x40;
/// Format-one: error number.
const FMT1_ERROR_MASK: u32 = 0x3F;
/// Format-one: shift of the parameter/handle/session number.
const FMT1_N_SHIFT: u32 = 8;
/// Format-one: width mask of the number field once shifted down.
const FMT1_N_MASK: u32 = 0xF;
/// Format-one: within the number field, marks a session rather than a handle.
const FMT1_N_SESSION_BIT: u32 = 0x8;
/// Mask keeping only the parts of a format-one code that name the error.
const FMT1_VALUE_MASK: u32 = 0xBF;
/// Format-zero: error/warning number.
const FMT0_ERROR_MASK: u32 = 0x7F;
/// Format-zero: marks a TPM 2.0 code.
const FMT0_VER1_BIT: u32 = 0x100;
/// Format-zero: marks a warning rather than an error.
const FMT0_WARN_BIT: u32 = 0x800;
/// Codes are 16 bits; anything above is the software layer that produced it.
const CODE_MASK: u32 = 0xFFFF;

/// What a format-one code's number field is counting.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum Fmt1Subject {
    /// Parameter `n` of the command, one-based.
    Parameter(u8),
    /// Handle `n` of the command, one-based.
    Handle(u8),
    /// Session `n` of the command, one-based.
    Session(u8),
    /// The code names no particular parameter, handle or session.
    None,
}

/// A decoded response code.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Rc(pub u32);

impl Rc {
    /// Wrap a raw response code word. # C: O(1)
    pub fn new(raw: u32) -> Self { Rc(raw) }

    /// Raw word as it appeared on the wire. # C: O(1)
    pub fn raw(self) -> u32 { self.0 }

    /// Software layer that produced the code; zero means the device itself.
    /// # C: O(1)
    pub fn layer(self) -> u32 { self.0 >> RC_LAYER_SHIFT }

    /// The code with any software layer stripped. # C: O(1)
    pub fn code(self) -> u32 { self.0 & CODE_MASK }

    /// Command completed with no error and no warning. A code is a success
    /// only when the entire word is zero. # C: O(1)
    pub fn is_success(self) -> bool { self.0 == TPM2_RC_SUCCESS }

    /// Code uses the format-one layout. # C: O(1)
    pub fn is_fmt1(self) -> bool { self.code() & FMT1_BIT != 0 }

    /// Code is a format-zero warning — the command did not run, and retrying
    /// may succeed. Warnings are never successes. # C: O(1)
    pub fn is_warning(self) -> bool {
        !self.is_fmt1() && self.code() & (FMT0_VER1_BIT | FMT0_WARN_BIT) == (FMT0_VER1_BIT | FMT0_WARN_BIT)
    }

    /// Code is an error: not a success, and not a warning. # C: O(1)
    pub fn is_error(self) -> bool { !self.is_success() && !self.is_warning() }

    /// The code stripped of the parameter/handle/session number, so it can be
    /// compared against a named constant. Format-zero codes carry no such
    /// number and are returned unchanged. # C: O(1)
    pub fn value(self) -> u32 {
        let c = self.code();
        if c & FMT1_BIT != 0 { c & FMT1_VALUE_MASK } else { c }
    }

    /// Error number: bits 0..5 for format one, bits 0..6 for format zero.
    /// # C: O(1)
    pub fn error_number(self) -> u32 {
        let c = self.code();
        if c & FMT1_BIT != 0 { c & FMT1_ERROR_MASK } else { c & FMT0_ERROR_MASK }
    }

    /// Base the code is measured from: format-one, format-zero warning, or
    /// format-zero error. `None` for success and for codes that set neither
    /// version bit. # C: O(1)
    pub fn base(self) -> Option<u32> {
        if self.is_success() { return None; }
        let c = self.code();
        if c & FMT1_BIT != 0 { return Some(TPM2_RC_FMT1); }
        if c & FMT0_VER1_BIT == 0 { return None; }
        Some(if c & FMT0_WARN_BIT != 0 { TPM2_RC_WARN } else { TPM2_RC_VER1 })
    }

    /// What a format-one code blames. Format-zero codes blame nothing.
    /// # C: O(1)
    pub fn subject(self) -> Fmt1Subject {
        let c = self.code();
        if c & FMT1_BIT == 0 { return Fmt1Subject::None; }
        let n = (c >> FMT1_N_SHIFT) & FMT1_N_MASK;
        if c & FMT1_P_BIT != 0 { return Fmt1Subject::Parameter(n as u8); }
        if n == 0 { return Fmt1Subject::None; }
        if n & FMT1_N_SESSION_BIT != 0 { Fmt1Subject::Session((n & !FMT1_N_SESSION_BIT) as u8) }
        else { Fmt1Subject::Handle(n as u8) }
    }
}
