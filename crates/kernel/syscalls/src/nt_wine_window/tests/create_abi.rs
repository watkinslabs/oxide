use super::*;

#[test]
fn production_raw_reader_normalizes_scalar_widths_without_changing_pointer_slots() {
    let raw = 0x7fa680000000;
    let args = SyscallArgs { a0: raw, a1: raw, a2: raw, a3: raw, a4: raw, a5: raw };
    let expected = [0x80000000, raw, raw, raw, 0x80000000, 0xffffffff80000000];
    for (index, value) in expected.into_iter().enumerate() {
        assert_eq!(raw_arg(args, index), Some(value));
    }
}
