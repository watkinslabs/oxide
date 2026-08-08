use crate::console::*;

#[test]
fn both_classes_from_the_default_line() {
    let (s, v) = console_classes_in(b"root=/dev/oxide0 console=ttyS0,115200 console=tty0");
    assert!(s && v, "default cmdline registers serial + vt");
}

#[test]
fn last_entry_backs_dev_console() {
    assert_eq!(preferred_console_in(b"console=ttyS0 console=tty0"), ConsoleKind::Vt(0));
    assert_eq!(preferred_console_in(b"console=tty0 console=ttyS0"), ConsoleKind::Serial);
    assert_eq!(preferred_console_in(b"console=tty1 console=tty2"), ConsoleKind::Vt(2));
}

#[test]
fn serial_only_and_vt_only() {
    let (s, v) = console_classes_in(b"console=ttyS0,115200");
    assert!(s && !v, "console=ttyS0 only -> serial printk, no VT");
    let (s, v) = console_classes_in(b"console=tty0");
    assert!(!s && v, "console=tty0 only -> VT printk, no serial");
}

#[test]
fn no_entry_keeps_both_sinks() {
    let (s, v) = console_classes_in(b"root=/dev/oxide0 ro");
    assert!(s && v);
}

#[test]
fn a_device_name_this_kernel_drives_no_console_for_is_not_classified() {
    assert_eq!(classify(b"ttynull"), None);
    assert_eq!(classify(b"hvc0"), None);
    assert_eq!(classify(b""), None);
}

#[test]
fn pl011_counts_as_serial() {
    let (s, v) = console_classes_in(b"console=ttyAMA0,115200 console=tty0");
    assert!(s && v);
}

#[test]
fn options_decode_baud_parity_bits_and_flow() {
    let o = parse_options(b"115200n8r");
    assert_eq!(o.baud, 115_200);
    assert_eq!(o.parity, Parity::None);
    assert_eq!(o.bits, 8);
    assert!(o.flow);
    let o = parse_options(b"9600e7");
    assert_eq!((o.baud, o.parity, o.bits, o.flow), (9600, Parity::Even, 7, false));
    let o = parse_options(b"38400o8");
    assert_eq!((o.baud, o.parity), (38400, Parity::Odd));
}

#[test]
fn bare_baud_keeps_the_8n1_defaults() {
    let o = parse_options(b"9600");
    assert_eq!((o.baud, o.parity, o.bits, o.flow), (9600, Parity::None, 8, false));
}

#[test]
fn missing_options_are_the_8n1_defaults() {
    let o = serial_options_in(b"console=ttyS0 console=tty0").expect("serial entry present");
    assert_eq!(o, ConsoleOptions::default_8n1());
}

#[test]
fn last_serial_entry_supplies_the_line_settings() {
    let o = serial_options_in(b"console=ttyS0,9600 console=ttyS1,57600n8").expect("serial entry");
    assert_eq!(o.baud, 57_600);
    assert_eq!(serial_options_in(b"console=tty0"), None);
}

#[test]
fn entries_are_yielded_in_command_line_order() {
    let mut got = [ConsoleKind::Vt(9); 3];
    let mut n = 0;
    for (k, _) in entries(b"console=tty0 console=ttyS0 console=tty2") { got[n] = k; n += 1; }
    assert_eq!(n, 3);
    assert_eq!(got, [ConsoleKind::Vt(0), ConsoleKind::Serial, ConsoleKind::Vt(2)]);
}
