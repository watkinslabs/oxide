use super::*;

const CURRENT: u64 = 0x2a;

#[test]
fn the_ordinals_are_the_ones_the_client_library_imports() {
    assert_eq!([ASSOCIATE_ORDINAL, BUILD_HIMC_LIST_ORDINAL, CREATE_ORDINAL, DESTROY_ORDINAL, DISABLE_THREAD_IME_ORDINAL,
        NOTIFY_IME_STATUS_ORDINAL, QUERY_ORDINAL, UPDATE_ORDINAL],
        [0x1321, 0x132c, 0x1364, 0x1381, 0x1389, 0x14be, 0x14dd, 0x15e5]);
}

#[test]
fn every_ordinal_is_admitted_with_its_windows_parameter_count() {
    for (ordinal, count) in [(ASSOCIATE_ORDINAL, 3), (BUILD_HIMC_LIST_ORDINAL, 4), (CREATE_ORDINAL, 1), (DESTROY_ORDINAL, 1),
        (DISABLE_THREAD_IME_ORDINAL, 1), (NOTIFY_IME_STATUS_ORDINAL, 2), (QUERY_ORDINAL, 2), (UPDATE_ORDINAL, 3)] {
        assert_eq!(crate::hosted_contracts::nt_wine_raw_args_contract::argument_count(ordinal), Some(count), "ordinal {ordinal:#x}");
    }
}

#[test]
fn a_zero_handle_is_never_an_object() {
    assert_eq!(handle_index(0), None);
    assert_eq!(handle_index(1), Some(1));
    assert_eq!(handle_index(u64::from(u32::MAX)), Some(u32::MAX));
    assert_eq!(handle_index(0x1_0000_0000), None);
}

#[test]
fn a_list_without_a_named_thread_reads_the_caller() {
    assert_eq!(list_thread(0, CURRENT), CURRENT);
    assert_eq!(list_thread(7, CURRENT), 7);
    // The client passes a DWORD thread id; only its low half is the id.
    assert_eq!(list_thread(0x1_0000_0007, CURRENT), 7);
    assert_eq!(list_thread(0x1_0000_0000, CURRENT), CURRENT);
}

#[test]
fn a_null_list_buffer_is_refused_before_any_write() {
    assert_eq!(list_bounds(0, 4), None);
}

#[test]
fn list_bounds_report_the_element_count_and_refuse_a_wrapping_buffer() {
    assert_eq!(list_bounds(0x1000, 4), Some((0x1000, 4)));
    assert_eq!(list_bounds(0x1000, 0), Some((0x1000, 0)));
    assert_eq!(list_bounds(0x1000, 0x1_0000_0004), Some((0x1000, 4)));
    assert_eq!(list_bounds(u64::MAX - 8, 4), None);
}

#[test]
fn a_himc_element_is_one_machine_word() {
    assert_eq!(HIMC_BYTES, 8);
}
