use core::ffi::c_void;

pub(crate) fn export_symbols() {
    use crate::symtab::export;
    export("print_hex_dump", print_hex_dump as *const () as usize, false);
}

extern "C" fn print_hex_dump(
    _level: *const u8,
    _prefix: *const u8,
    _prefix_type: i32,
    _rowsize: i32,
    _groupsize: i32,
    _buf: *const c_void,
    _len: usize,
    _ascii: bool,
) {
}
