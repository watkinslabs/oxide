use super::*;

#[test]
fn a_thread_receiving_nothing_reports_no_send() {
    assert_eq!(receive_flags(None), ISMEX_NOSEND);
    assert_eq!(ISMEX_NOSEND, 0);
}

#[test]
fn a_thread_running_its_own_send_receives_nothing() {
    assert_eq!(receive_flags(Some(ReceivedSend { inter_thread: false, replied: false })), ISMEX_NOSEND);
    assert_eq!(receive_flags(Some(ReceivedSend { inter_thread: false, replied: true })), ISMEX_NOSEND);
}

#[test]
fn an_unanswered_inter_thread_send_reports_the_send_bit_alone() {
    assert_eq!(receive_flags(Some(ReceivedSend { inter_thread: true, replied: false })), ISMEX_SEND);
}

#[test]
fn a_replied_inter_thread_send_keeps_the_send_bit_and_adds_the_replied_bit() {
    assert_eq!(receive_flags(Some(ReceivedSend { inter_thread: true, replied: true })), ISMEX_SEND | ISMEX_REPLIED);
}

#[test]
fn the_flag_values_are_the_distinct_bits_the_class_reports() {
    assert_eq!([ISMEX_SEND, ISMEX_NOTIFY, ISMEX_CALLBACK, ISMEX_REPLIED], [1, 2, 4, 8]);
}
