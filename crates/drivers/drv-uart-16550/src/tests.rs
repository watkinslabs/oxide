// Host-testable FIFO-mode encoding.

use super::imp::fifo_mode;

#[test]
fn steady_fifo_mode_keeps_fifo_enabled_with_eight_byte_rx_trigger() {
    assert_eq!(fifo_mode(), 0x81);
}
