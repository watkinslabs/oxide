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

/// The ordinal must be claimed for every action, because the ordinal falling
/// through is what reported the service as unadmitted while the action was
/// simply one the nonclient redirect does not own.
#[test]
fn the_ordinal_decodes_for_every_action_and_only_for_itself() {
    assert_eq!(decode(0x15cb, &[0x29, 4, 8, 2]), Some(Call { action: 0x29, val: 4, ptr: 8, winini: 2 }));
    assert_eq!(decode(0x15cb, &[0x1022, 0, 0, 0]), Some(Call { action: 0x1022, val: 0, ptr: 0, winini: 0 }));
    assert_eq!(decode(0x15cc, &[0x29, 0, 0, 0]), None);
    assert_eq!(decode(0x15cb, &[0x29, 0, 0]), None);
    // Argument words wider than the action are truncated, never sign-extended.
    assert_eq!(decode(0x15cb, &[0x1234_5678_0000_0029, 0, 0, 0]).map(|call| call.action), Some(0x29));
}

/// A writing action that fetches the wrong shape out of user memory writes the
/// wrong setting; each carrier is the record its action actually carries.
#[test]
fn each_writing_action_names_the_record_it_carries() {
    use ipc::win32_sysparams::action as a;
    assert_eq!(carrier(a::SET_MOUSE), Carrier::Words { count: 3, skip: 0, sized: None });
    assert_eq!(carrier(a::SET_MINIMIZED_METRICS), Carrier::Words { count: 4, skip: 4, sized: Some(MINIMIZED_METRICS_BYTES) });
    assert_eq!(carrier(a::SET_ICON_METRICS), Carrier::IconMetrics);
    assert_eq!(carrier(a::SET_ICON_TITLE_LOGFONT), Carrier::Font);
    assert_eq!(carrier(a::SET_NONCLIENT_METRICS), Carrier::Nonclient);
    assert_eq!(carrier(a::SET_DESK_WALLPAPER), Carrier::Path);
    assert_eq!(carrier(a::SET_WHEEL_SCROLL_LINES), Carrier::None);
    assert_eq!(carrier(a::GET_WHEEL_SCROLL_LINES), Carrier::None);
}

/// A record admitted at a size it cannot have is a usercopy past its end.
#[test]
fn only_the_real_record_sizes_are_admitted() {
    use ipc::win32_sysparams::action as a;
    assert!(record_size_admitted(a::GET_NONCLIENT_METRICS, LEGACY_BYTES));
    assert!(record_size_admitted(a::GET_NONCLIENT_METRICS, MODERN_BYTES));
    assert!(!record_size_admitted(a::GET_NONCLIENT_METRICS, MODERN_BYTES + 1));
    assert!(record_size_admitted(a::GET_ICON_METRICS, ICON_METRICS_BYTES));
    assert!(!record_size_admitted(a::GET_ICON_METRICS, MINIMIZED_METRICS_BYTES));
    assert!(record_size_admitted(a::GET_MINIMIZED_METRICS, MINIMIZED_METRICS_BYTES));
    assert!(!record_size_admitted(a::GET_MINIMIZED_METRICS, 0));
    // An action with no record of its own admits whatever it is asked.
    assert!(record_size_admitted(a::GET_WHEEL_SCROLL_LINES, 0));
}
