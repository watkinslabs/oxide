// Module manifest: mem owns byte operations, cstr owns C-string operations,
// parse owns kstrto/simple conversions, format owns bounded printf exports,
// runtime owns compiler/runtime guard symbols.

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

#[cfg(test)]
#[path = "linux_string/tests.rs"]
mod tests;
