// Module manifest: mem owns byte operations, cstr owns C-string operations,
// parse owns kstrto/simple conversions, format owns bounded printf exports,
// runtime owns compiler/runtime guard symbols.

use core::ffi::VaList;

mod cstr;
mod format;
mod mem;
mod parse;
mod runtime;

/// Register Linux string/lib/runtime KPI symbols.
/// # C: O(1)
pub fn export_symbols() {
    mem::export_symbols();
    cstr::export_symbols();
    parse::export_symbols();
    format::export_symbols();
    runtime::export_symbols();
}

pub(crate) unsafe fn vscnprintf(buf: *mut u8, size: usize, fmt: *const u8, ap: &mut VaList) -> i32 {
    // SAFETY: caller supplies a printf format and matching varargs.
    unsafe { format::vscnprintf(buf, size, fmt, ap) }
}

#[cfg(test)]
#[path = "linux_string/tests.rs"]
mod tests;
