//! Status translation contracts: the pass-through classes, the severity
//! normalization, the Win32-carrying facilities, and the mapped statuses.

use super::nt_status_to_dos_error;

#[test]
fn success_and_customer_statuses_pass_through() {
    assert_eq!(nt_status_to_dos_error(0), 0);
    assert_eq!(nt_status_to_dos_error(0x2000_1234), 0x2000_1234);
    assert_eq!(nt_status_to_dos_error(0xe000_0001), 0xe000_0001);
}

#[test]
fn the_alternate_severity_normalizes_onto_the_error_severity() {
    assert_eq!(nt_status_to_dos_error(0xd000_000d), nt_status_to_dos_error(0xc000_000d));
    assert_eq!(nt_status_to_dos_error(0xd000_000d), 87);
}

#[test]
fn the_win32_carrying_facilities_answer_with_their_low_word() {
    assert_eq!(nt_status_to_dos_error(0xc001_0032), 0x32);
    assert_eq!(nt_status_to_dos_error(0x8007_0005), 5);
    assert_eq!(nt_status_to_dos_error(0xc007_007b), 0x7b);
    assert_eq!(nt_status_to_dos_error(0xd007_0005), 5);
}

#[test]
fn the_mapped_statuses_answer_their_win32_errors() {
    assert_eq!(nt_status_to_dos_error(0x0000_0102), 1460);
    assert_eq!(nt_status_to_dos_error(0x0000_0103), 997);
    assert_eq!(nt_status_to_dos_error(0x8000_0005), 234);
    assert_eq!(nt_status_to_dos_error(0x8000_001a), 259);
    assert_eq!(nt_status_to_dos_error(0xc000_0002), 1);
    assert_eq!(nt_status_to_dos_error(0xc000_0005), 998);
    assert_eq!(nt_status_to_dos_error(0xc000_0008), 6);
    assert_eq!(nt_status_to_dos_error(0xc000_000f), 2);
    assert_eq!(nt_status_to_dos_error(0xc000_0011), 38);
    assert_eq!(nt_status_to_dos_error(0xc000_0017), 8);
    assert_eq!(nt_status_to_dos_error(0xc000_0022), 5);
    assert_eq!(nt_status_to_dos_error(0xc000_0023), 122);
    assert_eq!(nt_status_to_dos_error(0xc000_0033), 123);
    assert_eq!(nt_status_to_dos_error(0xc000_0034), 2);
    assert_eq!(nt_status_to_dos_error(0xc000_0035), 183);
    assert_eq!(nt_status_to_dos_error(0xc000_003a), 3);
    assert_eq!(nt_status_to_dos_error(0xc000_0043), 32);
    assert_eq!(nt_status_to_dos_error(0xc000_0054), 33);
    assert_eq!(nt_status_to_dos_error(0xc000_007b), 193);
    assert_eq!(nt_status_to_dos_error(0xc000_009a), 1450);
    assert_eq!(nt_status_to_dos_error(0xc000_00b5), 121);
    assert_eq!(nt_status_to_dos_error(0xc000_00bb), 50);
    assert_eq!(nt_status_to_dos_error(0xc000_0102), 1392);
    assert_eq!(nt_status_to_dos_error(0xc000_0103), 267);
    assert_eq!(nt_status_to_dos_error(0xc000_0106), 206);
    assert_eq!(nt_status_to_dos_error(0xc000_0109), 317);
    assert_eq!(nt_status_to_dos_error(0xc000_0120), 995);
    assert_eq!(nt_status_to_dos_error(0xc000_0121), 5);
    assert_eq!(nt_status_to_dos_error(0xc000_0141), 59);
    assert_eq!(nt_status_to_dos_error(0xc000_0275), 4390);
}

#[test]
fn an_unmapped_status_answers_the_message_not_found_error() {
    assert_eq!(nt_status_to_dos_error(0xc000_0999), 317);
    assert_eq!(nt_status_to_dos_error(0xc000_ffff), 317);
}
