use crate::token::*;

#[test]
fn exact_parameter_uses_last_complete_token() {
    let line = b"not.zram.num_devices=9 zram.num_devices=0 zram.num_devices=3";
    assert_eq!(value(line, b"zram.num_devices"), Some(&b"3"[..]));
}

#[test]
fn parameter_does_not_match_prefix_or_flag() {
    let line = b"zram.num_devices_extra=4 zram.num_devices";
    assert_eq!(value(line, b"zram.num_devices"), None);
}

#[test]
fn value_may_contain_further_equals_signs() {
    assert_eq!(value(b"systemd.setenv=A=B", b"systemd.setenv"), Some(&b"A=B"[..]));
}

#[test]
fn bare_flag_and_valued_form_are_distinguished() {
    assert!(bare_flag(b"quiet earlycon root=/dev/oxide0", b"earlycon"));
    assert!(!bare_flag(b"earlycon=uart8250,io,0x3f8", b"earlycon"));
    assert!(present(b"earlycon=uart8250,io,0x3f8", b"earlycon"));
    assert!(present(b"quiet earlycon", b"earlycon"));
}

#[test]
fn trailing_newline_terminates_the_last_token() {
    // The installed line ends with '\n' per the /proc/cmdline convention; the
    // final parameter must not absorb it into its value.
    assert_eq!(value(b"root=/dev/oxide0 loglevel=7\n", b"loglevel"), Some(&b"7"[..]));
    assert_eq!(uint_value(b"root=/dev/oxide0 loglevel=7\n", b"loglevel"), Some(7));
}

#[test]
fn uint_parse_honours_hex_prefix_and_stops_at_separator() {
    assert_eq!(parse_uint(b"0x3f8,115200"), (0x3f8, 5));
    assert_eq!(parse_uint(b"115200n8"), (115200, 6));
    assert_eq!(parse_uint(b"0X9000000"), (0x9000000, 9));
    assert_eq!(parse_uint(b"nodigits"), (0, 0));
}

#[test]
fn full_uint_rejects_trailing_garbage() {
    assert_eq!(full_uint(b"7"), Some(7));
    assert_eq!(full_uint(b"7x"), None);
    assert_eq!(full_uint(b""), None);
}

#[test]
fn full_int_accepts_a_negative() {
    assert_eq!(full_int(b"-1"), Some(-1));
    assert_eq!(full_int(b"+5"), Some(5));
    assert_eq!(full_int(b"30"), Some(30));
    assert_eq!(full_int(b"-"), None);
}

#[test]
fn split_comma_separates_head_from_the_rest() {
    assert_eq!(split_comma(b"uart8250,io,0x3f8"), (&b"uart8250"[..], Some(&b"io,0x3f8"[..])));
    assert_eq!(split_comma(b"pl011"), (&b"pl011"[..], None));
}
