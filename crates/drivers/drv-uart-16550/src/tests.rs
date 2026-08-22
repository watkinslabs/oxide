// Host-testable FIFO-mode encoding.

use super::imp::fifo_mode;
use super::{line_control_bits, modem_control_bits};

#[test]
fn console_line_options_encode_data_bits_and_parity() {
    assert_eq!(line_control_bits(b'n', 8), 0x03);
    assert_eq!(line_control_bits(b'o', 7), 0x0a);
    assert_eq!(line_control_bits(b'e', 7), 0x1a);
}

#[test]
fn console_hardware_flow_uses_auto_cts_rts() {
    assert_eq!(modem_control_bits(false), 0);
    assert_eq!(modem_control_bits(true), 0x20);
}

#[test]
fn steady_fifo_mode_keeps_fifo_enabled_with_eight_byte_rx_trigger() {
    assert_eq!(fifo_mode(), 0x81);
}
