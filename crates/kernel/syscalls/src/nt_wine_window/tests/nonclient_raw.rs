use super::*;
#[test]
fn actual_spi_ordinal_action_pointer_and_record_size_are_distinct() {
    for size in [500, 504] {
        assert_eq!(route(0x15cb, &[0x1234567800000029, u64::MAX, 0x1000000040, u64::MAX],
            |pointer| { assert_eq!(pointer, 0x1000000040); Some(size) },
            |pointer, actual| { assert_eq!((pointer, actual), (0x1000000040, size)); 1 }), Some(1));
    }
}
#[test]
fn wrong_action_is_not_a_blanket_spi_success_and_bad_copy_never_enters() {
    for (ordinal, action) in [(0x15cb, 0x2a), (0x15cc, 0x29), (0x4e540000000015cb, 0x29)] {
        assert_eq!(route(ordinal, &[action, 0, 1, 0], |_| panic!("unclaimed copy"), |_, _| panic!("unclaimed native")), None);
    }
    assert_eq!(route(0x15cb, &[0x29, 0, 0, 0], |_| panic!("null copy"), |_, _| panic!("null native")), Some(0));
    assert_eq!(route(0x15cb, &[0x29, 504, 1, 0], |_| None, |_, _| panic!("failed copy native")), Some(0));
    for size in [0, 499, 501, u32::MAX] {
        assert_eq!(route(0x15cb, &[0x29, 504, 1, 0], |_| Some(size), |_, _| panic!("bad size native")), Some(0));
    }
    assert_eq!(route(0x15cb, &[0x29, 504, u64::MAX - 10, 0], |_| Some(504), |_, _| panic!("overflow native")), Some(0));
}
#[test]
fn callback_dispatch_result_is_passthrough_not_bool_normalized() {
    for result in [0, 1, 0x123456789abc] {
        assert_eq!(route(0x15cb, &[0x29, 500, 1, 0], |_| Some(500), |_, _| result), Some(result));
    }
}
