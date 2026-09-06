use super::*;

#[test]
fn selector_comes_from_sixth_argument_and_only_seventh_is_read() {
    for ansi in [0, 1, u64::MAX] {
        let mut reads = alloc::vec::Vec::new();
        assert_eq!(tail(0xffff_ffff_0000_1234, |index| { reads.push(index); (index == 6).then_some(ansi) }), Some((0x1234, ansi != 0)));
        assert_eq!(reads, [6]);
    }
}

#[test]
fn ansi_fault_is_not_silently_unicode() { assert_eq!(tail(0x1234, |_| None), None); }
