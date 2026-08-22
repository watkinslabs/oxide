// Runtime serial-console line state derived from the canonical cmdline parser.
//
// This module is ungated so hosted tests exercise the exact value handed to
// both the tty's termios image and the hardware driver. Parsing remains owned
// by `cmdline::console`; this is only the boundary translation.

use tty::pty::{default_termios, TERMIOS_BYTES, TERMIOS_OFF_CFLAG,
               TERMIOS_OFF_ISPEED, TERMIOS_OFF_OSPEED};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub(crate) struct RuntimeLine {
    pub baud: u32,
    pub parity: u8,
    pub bits: u8,
    pub flow: bool,
}

/// Translate the one parsed owner into the primitive UART contract. # C: O(1)
pub(crate) const fn from_options(options: cmdline::console::ConsoleOptions) -> RuntimeLine {
    let parity = match options.parity {
        cmdline::console::Parity::None => b'n',
        cmdline::console::Parity::Odd => b'o',
        cmdline::console::Parity::Even => b'e',
    };
    RuntimeLine { baud: options.baud, parity, bits: options.bits, flow: options.flow }
}

/// Termios image userspace reads back for the runtime console. # C: O(1)
pub(crate) fn termios(line: RuntimeLine) -> [u8; TERMIOS_BYTES] {
    const CS5: u32 = 0;
    const CS6: u32 = 0x10;
    const CS7: u32 = 0x20;
    const CS8: u32 = 0x30;
    const CREAD: u32 = 0x80;
    const PARENB: u32 = 0x100;
    const PARODD: u32 = 0x200;
    const CLOCAL: u32 = 0x800;
    const CRTSCTS: u32 = 0x8000_0000;

    let width = match line.bits { 5 => CS5, 6 => CS6, 7 => CS7, _ => CS8 };
    let parity = match line.parity {
        b'o' => PARENB | PARODD,
        b'e' => PARENB,
        _ => 0,
    };
    let mut cflag = width | CREAD | CLOCAL | parity;
    if line.flow { cflag |= CRTSCTS; }
    let mut image = default_termios();
    image[TERMIOS_OFF_CFLAG..TERMIOS_OFF_CFLAG + 4].copy_from_slice(&cflag.to_le_bytes());
    image[TERMIOS_OFF_ISPEED..TERMIOS_OFF_ISPEED + 4].copy_from_slice(&line.baud.to_le_bytes());
    image[TERMIOS_OFF_OSPEED..TERMIOS_OFF_OSPEED + 4].copy_from_slice(&line.baud.to_le_bytes());
    image
}

#[cfg(test)]
mod tests {
    use super::*;

    fn u32_at(image: &[u8; TERMIOS_BYTES], at: usize) -> u32 {
        u32::from_le_bytes(image[at..at + 4].try_into().unwrap())
    }

    #[test]
    fn parsed_console_options_drive_the_runtime_line_and_termios() {
        let options = cmdline::console::serial_options_in(
            b"console=ttyS0,115200 console=tty0 console=ttyS1,9600e7r",
        ).unwrap();
        let line = from_options(options);
        assert_eq!(line, RuntimeLine { baud: 9600, parity: b'e', bits: 7, flow: true });
        let image = termios(line);
        assert_eq!(u32_at(&image, TERMIOS_OFF_ISPEED), 9600);
        assert_eq!(u32_at(&image, TERMIOS_OFF_OSPEED), 9600);
        assert_eq!(u32_at(&image, TERMIOS_OFF_CFLAG), 0x8000_09a0);
    }

    #[test]
    fn default_console_line_is_115200_8n1_without_flow() {
        let line = from_options(cmdline::console::ConsoleOptions::default_8n1());
        assert_eq!(line, RuntimeLine { baud: 115_200, parity: b'n', bits: 8, flow: false });
        assert_eq!(u32_at(&termios(line), TERMIOS_OFF_CFLAG), 0x8b0);
    }
}
