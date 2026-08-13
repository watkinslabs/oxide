/// Zero UUID and GUID objects use the same fixed 16-byte ABI layout.
#[unsafe(no_mangle)]
pub(super) static guid_null: [u8; 16] = [0; 16];
#[unsafe(no_mangle)]
pub(super) static uuid_null: [u8; 16] = [0; 16];

pub(super) fn export_symbols() {
    crate::symtab::export("guid_null", &guid_null as *const _ as usize, false);
    crate::symtab::export("uuid_null", &uuid_null as *const _ as usize, false);
}
