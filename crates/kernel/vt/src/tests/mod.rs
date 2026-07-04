use crate::emulator::Emulator;
use crate::vc::Vc;

pub(super) fn run(cols: u16, rows: u16, bytes: &[u8]) -> Vc {
    let mut vc = Vc::new(cols, rows);
    let mut em = Emulator::new();
    em.feed_bytes(&mut vc, bytes);
    vc
}

pub(super) fn trimmed(vc: &Vc, row: u16) -> alloc::string::String {
    let s = vc.row_string(row);
    s.trim_end().into()
}

mod attrs;
mod basics;
mod resize;
mod scrollback;
