use crate::earlycon::*;

/// x86-shaped platform: 8250 behind port I/O at COM1.
const X86: ArchDefaults = ArchDefaults { driver: Driver::Uart8250, iotype: IoType::Port, addr: 0x3f8 };
/// arm-shaped platform: PL011 in MMIO at the virt machine's UART base.
const ARM: ArchDefaults = ArchDefaults { driver: Driver::Pl011, iotype: IoType::Mem32, addr: 0x0900_0000 };

fn spec(d: Driver, io: IoType, addr: u64, baud: u32) -> EarlyconSpec { EarlyconSpec { driver: d, iotype: io, addr, baud } }

#[test]
fn bare_earlycon_resolves_to_the_platform_uart() {
    assert_eq!(earlycon_request(b"root=/dev/oxide0 earlycon", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
    assert_eq!(earlycon_request(b"root=/dev/oxide0 earlycon", ARM), Some(spec(Driver::Pl011, IoType::Mem32, 0x0900_0000, 115_200)));
}

#[test]
fn no_parameter_means_no_boot_console() {
    assert_eq!(earlycon_request(b"root=/dev/oxide0 ro console=tty0", X86), None);
}

#[test]
fn explicit_port_io_form() {
    assert_eq!(parse_earlycon(b"uart8250,io,0x3f8", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
    assert_eq!(parse_earlycon(b"uart8250,io,0x2f8,9600", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x2f8, 9600)));
}

#[test]
fn explicit_mmio_forms_carry_their_stride() {
    assert_eq!(parse_earlycon(b"uart,mmio,0x9000000", ARM), Some(spec(Driver::Uart8250, IoType::Mem, 0x9000000, 115_200)));
    assert_eq!(parse_earlycon(b"uart,mmio32,0x9000000", ARM), Some(spec(Driver::Uart8250, IoType::Mem32, 0x9000000, 115_200)));
    assert_eq!(parse_earlycon(b"uart,mmio16,0x9000000", ARM), Some(spec(Driver::Uart8250, IoType::Mem16, 0x9000000, 115_200)));
    assert_eq!(parse_earlycon(b"uart,mmio32be,0x9000000", ARM), Some(spec(Driver::Uart8250, IoType::Mem32Be, 0x9000000, 115_200)));
    assert_eq!(IoType::Mem.stride(), 1);
    assert_eq!(IoType::Mem16.stride(), 2);
    assert_eq!(IoType::Mem32.stride(), 4);
    assert_eq!(IoType::Port.stride(), 1);
}

#[test]
fn mmio32native_follows_the_target_endianness() {
    assert_eq!(parse_earlycon(b"uart,mmio32native,0x9000000", ARM), Some(spec(Driver::Uart8250, IoType::Mem32, 0x9000000, 115_200)));
}

#[test]
fn bare_hex_address_means_memory_mapped() {
    assert_eq!(parse_earlycon(b"pl011,0x9000000", ARM), Some(spec(Driver::Pl011, IoType::Mem, 0x9000000, 115_200)));
    assert_eq!(parse_earlycon(b"pl011,0x9000000,115200", ARM), Some(spec(Driver::Pl011, IoType::Mem, 0x9000000, 115_200)));
}

#[test]
fn name_only_inherits_the_platform_address_for_the_platform_driver() {
    assert_eq!(parse_earlycon(b"pl011", ARM), Some(spec(Driver::Pl011, IoType::Mem32, 0x0900_0000, 115_200)));
    assert_eq!(parse_earlycon(b"uart8250", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
}

#[test]
fn name_with_only_options_keeps_the_platform_address() {
    assert_eq!(parse_earlycon(b"uart8250,9600", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 9600)));
}

#[test]
fn every_accepted_driver_alias_maps_to_a_programming_model() {
    for n in [&b"uart"[..], b"uart8250", b"ns16550", b"ns16550a", b"8250"] {
        assert_eq!(driver_for_name(n), Some(Driver::Uart8250), "alias must resolve");
    }
    assert_eq!(driver_for_name(b"pl011"), Some(Driver::Pl011));
}

#[test]
fn an_unknown_device_name_is_not_silently_driven() {
    assert_eq!(parse_earlycon(b"efifb", X86), None);
    assert_eq!(earlycon_request(b"earlycon=efifb", X86), None);
    assert_eq!(earlycon_request(b"console=tty0", X86), None, "a VT is not an earlycon");
}

#[test]
fn console_alias_registers_a_boot_console() {
    assert_eq!(earlycon_request(b"console=uart8250,io,0x3f8", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
    assert_eq!(earlycon_request(b"console=ttyS0,115200", X86), None, "a tty class name is not an earlycon request");
}

#[test]
fn earlyprintk_serial_spellings() {
    assert_eq!(parse_earlyprintk(b"serial", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
    assert_eq!(parse_earlyprintk(b"serial,ttyS0,115200", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
    assert_eq!(parse_earlyprintk(b"serial,ttyS1,9600", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x2f8, 9600)));
    assert_eq!(parse_earlyprintk(b"ttyS0,57600", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 57_600)));
    assert_eq!(parse_earlyprintk(b"serial,0x2f8,9600", X86), Some(spec(Driver::Uart8250, IoType::Port, 0x2f8, 9600)));
    assert_eq!(parse_earlyprintk(b"mmio32,0x9000000,115200", ARM), Some(spec(Driver::Uart8250, IoType::Mem32, 0x9000000, 115_200)));
}

#[test]
fn earlyprintk_hardware_we_do_not_drive_is_refused() {
    assert_eq!(parse_earlyprintk(b"vga", X86), None);
    assert_eq!(parse_earlyprintk(b"dbgp", X86), None);
    assert_eq!(parse_earlyprintk(b"xen", X86), None);
}

#[test]
fn earlycon_takes_precedence_over_earlyprintk() {
    let line = b"earlyprintk=serial,ttyS1,9600 earlycon=uart8250,io,0x3f8";
    assert_eq!(earlycon_request(line, X86), Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
}

#[test]
fn keep_bootcon_is_requested_by_either_spelling() {
    assert!(keep_bootcon(b"earlycon keep_bootcon"));
    assert!(keep_bootcon(b"earlyprintk=serial,ttyS0,115200,keep"));
    assert!(!keep_bootcon(b"earlycon"));
    assert!(!keep_bootcon(b"earlyprintk=serial,ttyS0,115200"));
}

#[test]
fn a_trailing_newline_does_not_leak_into_the_address() {
    assert_eq!(earlycon_request(b"root=/dev/oxide0 earlycon=uart8250,io,0x3f8\n", X86),
               Some(spec(Driver::Uart8250, IoType::Port, 0x3f8, 115_200)));
}

#[test]
fn a_missing_address_after_an_iotype_keyword_is_refused() {
    assert_eq!(parse_earlycon(b"uart8250,io,", X86), None);
    assert_eq!(parse_earlycon(b"uart8250,mmio32,zzz", X86), None);
}
