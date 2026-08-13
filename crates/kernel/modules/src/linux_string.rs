// Module manifest: mem owns byte operations, cstr owns C-string operations,
// parse owns kstrto/simple conversions, format owns bounded printf exports,
// bitops owns scan helpers, match_parser owns parser.h helpers, uuid owns UUID ABI objects, unicode owns
// utf8/utf16 conversion, diagnostics owns dump helpers, runtime owns guards.

use core::ffi::VaList;

mod cstr;
mod bitops;
mod diagnostics;
mod format;
mod match_parser;
mod mem;
mod parse;
mod runtime;
mod unicode;
mod uuid;

/// Register Linux string/lib/runtime KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    mem::export_symbols();
    cstr::export_symbols();
    parse::export_symbols();
    bitops::export_symbols();
    match_parser::export_symbols();
    unicode::export_symbols();
    format::export_symbols();
    diagnostics::export_symbols();
    runtime::export_symbols();
    uuid::export_symbols();
}

pub(crate) unsafe fn vscnprintf(buf: *mut u8, size: usize, fmt: *const u8, ap: &mut VaList) -> i32 {
    // SAFETY: caller supplies a printf format and matching varargs.
    unsafe { format::vscnprintf(buf, size, fmt, ap) }
}

#[cfg(test)]
#[path = "linux_string/tests.rs"]
mod tests;
