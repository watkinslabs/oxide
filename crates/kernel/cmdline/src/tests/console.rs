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

/// The property `systemd-getty-generator` acts on: with the boot line this
/// image ships, the serial line IS reported, so a serial login prompt is
/// generated. Reporting the VT alone is what left the serial line with no
/// getty and a debug shell standing in for it.
#[test]
fn the_boot_line_reports_the_serial_console_so_a_getty_is_generated() {
    for line in [&b"root=/dev/vda rw console=ttyS0,115200 console=tty0"[..],
                 &b"root=/dev/vda rw console=ttyAMA0,115200 console=tty0"[..]] {
        let a = active_consoles_in(line);
        assert_eq!(a.as_slice(), &[ConsoleKind::Serial, ConsoleKind::Vt(0)], "{:?}", a);
    }
}

/// Print order is the console LIST walked backwards: the preferred console
/// (last `console=`) prints last, the rest in reverse command-line order.
/// A consumer reading the first word (dracut's plymouth hook) depends on it.
#[test]
fn the_preferred_console_prints_last_and_the_rest_reversed() {
    let a = active_consoles_in(b"console=tty0 console=ttyS0");
    assert_eq!(a.as_slice(), &[ConsoleKind::Vt(0), ConsoleKind::Serial]);
    let a = active_consoles_in(b"console=tty1 console=ttyS0 console=tty0");
    assert_eq!(a.as_slice(), &[ConsoleKind::Serial, ConsoleKind::Vt(1), ConsoleKind::Vt(0)]);
}

/// A class named twice registered ONE console, so it is reported once.
#[test]
fn a_repeated_entry_is_reported_once() {
    let a = active_consoles_in(b"console=ttyS0,115200 console=ttyS0 console=tty0");
    assert_eq!(a.as_slice(), &[ConsoleKind::Serial, ConsoleKind::Vt(0)]);
}

/// A single entry is both the only console and the preferred one.
#[test]
fn a_single_entry_is_reported_alone() {
    assert_eq!(active_consoles_in(b"console=ttyS0").as_slice(), &[ConsoleKind::Serial]);
    assert_eq!(active_consoles_in(b"console=tty0").as_slice(), &[ConsoleKind::Vt(0)]);
}

/// No `console=` registers the arch default pair — the same answer
/// `console_classes_in` gives, from the same line.
#[test]
fn no_entry_reports_the_arch_default_pair() {
    let a = active_consoles_in(b"root=/dev/vda ro");
    assert_eq!(a.as_slice(), &[ConsoleKind::Serial, ConsoleKind::Vt(0)]);
    assert_eq!(console_classes_in(b"root=/dev/vda ro"), (true, true));
}

/// A name no console is driven for takes no slot, and cannot displace one.
#[test]
fn an_undriven_name_is_not_reported() {
    let a = active_consoles_in(b"console=ttynull console=ttyS0 console=tty0");
    assert_eq!(a.as_slice(), &[ConsoleKind::Serial, ConsoleKind::Vt(0)]);
}

/// The reported set is exactly the classes that register printk consoles —
/// two answers derived from one line must not disagree.
#[test]
fn the_reported_set_matches_the_registered_classes() {
    for line in [&b"console=ttyS0 console=tty0"[..], &b"console=ttyS0"[..],
                 &b"console=tty0"[..], &b"root=/dev/vda"[..], &b"console=tty1 console=ttyAMA0"[..]] {
        let (serial, vt) = console_classes_in(line);
        let a = active_consoles_in(line);
        assert_eq!(a.as_slice().iter().any(|k| *k == ConsoleKind::Serial), serial, "{line:?}");
        assert_eq!(a.as_slice().iter().any(|k| matches!(k, ConsoleKind::Vt(_))), vt, "{line:?}");
    }
}

#[test]
fn entries_are_yielded_in_command_line_order() {
    let mut got = [ConsoleKind::Vt(9); 3];
    let mut n = 0;
    for (k, _) in entries(b"console=tty0 console=ttyS0 console=tty2") { got[n] = k; n += 1; }
    assert_eq!(n, 3);
    assert_eq!(got, [ConsoleKind::Vt(0), ConsoleKind::Serial, ConsoleKind::Vt(2)]);
}
