use super::*;

#[test]
fn cooked_icrnl_translates_carriage_return_to_newline() {
    // Default iflag has ICRNL. Terminal Enter sends \r; ldisc converts
    // it to \n so cooked-mode slave_read can complete a line.
    let mut p = cooked(0);
    p.master_write(b"hello\r");
    let mut buf = [0u8; 16];
    // ICRNL turned \r into \n → line is complete.
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 6);
    assert_eq!(&buf[..6], b"hello\n");
}

#[test]
fn cooked_igncr_drops_carriage_return() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    let new_iflag = (iflag & !iflag::ICRNL) | iflag::IGNCR;
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&new_iflag.to_le_bytes());
    p.master_write(b"a\rb\n");
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ab\n");
}

#[test]
fn cooked_inlcr_translates_newline_to_cr() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    let new_iflag = (iflag & !iflag::ICRNL) | iflag::INLCR;
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&new_iflag.to_le_bytes());
    // \n becomes \r — no longer a line terminator under ICANON.
    p.master_write(b"hi\n");
    let mut buf = [0u8; 16];
    // No newline in m_to_s after INLCR translation → slave_read = 0.
    assert_eq!(p.slave_read(&mut buf), 0);
}

#[test]
fn cooked_onlcr_expands_newline_on_slave_write() {
    // Default oflag = OPOST | ONLCR. Slave writes "ok\n" → master sees "ok\r\n".
    let mut p = cooked(0);
    p.slave_write(b"ok\n");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"ok\r\n");
}

#[test]
fn raw_slave_write_skips_oflag_transformations() {
    // Pair::new starts raw (oflag = 0); slave_write is verbatim.
    let mut p = Pair::new(0);
    p.slave_write(b"raw\n");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 4);
    assert_eq!(&buf[..4], b"raw\n");
}

#[test]
fn cooked_opost_off_disables_onlcr() {
    let mut p = cooked(0);
    let oflag = read_oflag(&p.termios);
    let new_oflag = oflag & !oflag::OPOST;
    p.termios[TERMIOS_OFF_OFLAG..TERMIOS_OFF_OFLAG + 4]
        .copy_from_slice(&new_oflag.to_le_bytes());
    p.slave_write(b"x\n");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 2, "OPOST off → no expansion");
    assert_eq!(&buf[..2], b"x\n");
}

#[test]
fn master_readable_tracks_s_to_m() {
    let mut p = Pair::new(0);
    assert!(!p.master_readable());
    p.slave_write(b"x");
    assert!(p.master_readable());
    let mut buf = [0u8; 4];
    p.master_read(&mut buf);
    assert!(!p.master_readable());
}

#[test]
fn slave_readable_raw_mode_any_byte() {
    let mut p = Pair::new(0); // raw
    assert!(!p.slave_readable());
    p.master_write(b"x");
    assert!(p.slave_readable());
}

#[test]
fn slave_readable_cooked_requires_newline() {
    let mut p = cooked(0);
    p.master_write(b"hi");
    assert!(!p.slave_readable(), "ICANON needs \\n");
    p.master_write(b"\n");
    assert!(p.slave_readable());
    let mut buf = [0u8; 8];
    p.slave_read(&mut buf);
    assert!(!p.slave_readable());
}

#[test]
fn default_termios_populates_full_c_cc_set() {
    let t = default_termios();
    assert_eq!(t[TERMIOS_OFF_CC + cc::VINTR],  DEFAULT_VINTR);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VQUIT],  DEFAULT_VQUIT);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VERASE], DEFAULT_VERASE);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VKILL],  DEFAULT_VKILL);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VEOF],   DEFAULT_VEOF);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VSUSP],  DEFAULT_VSUSP);
    // Remaining slots stay zero.
    assert_eq!(t[TERMIOS_OFF_CC + cc::VTIME],  0);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VMIN],   0);
    assert_eq!(t[TERMIOS_OFF_CC + cc::VEOL],   0);
}

#[test]
fn cooked_veof_on_empty_line_terminates_with_zero_bytes() {
    let mut p = cooked(0);
    p.master_write(b"\x04"); // ^D on empty line
    assert!(p.pending_eof);
    let mut buf = [0u8; 16];
    // slave_read returns 0 (EOF), clears the flag.
    assert_eq!(p.slave_read(&mut buf), 0);
    assert!(!p.pending_eof, "EOF flag cleared after delivery");
}

#[test]
fn cooked_veof_after_partial_line_drains_buffer() {
    let mut p = cooked(0);
    p.master_write(b"hi");        // partial line, no \n yet
    p.master_write(b"\x04");      // ^D — terminates without \n
    assert!(p.pending_eof);
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"hi");
    // Next read sees the empty queue + cleared flag → 0 (EOF still).
    assert!(!p.pending_eof);
}

#[test]
fn cooked_veof_zero_disables_eof_path() {
    let mut p = cooked(0);
    p.termios[TERMIOS_OFF_CC + cc::VEOF] = 0;
    p.master_write(b"\x04");
    assert!(!p.pending_eof, "VEOF=0 disables");
    // Byte passes through as data.
    let mut buf = [0u8; 4];
    p.master_write(b"\n");
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"\x04\n");
}

#[test]
fn cooked_veof_does_not_fire_in_raw_mode() {
    let mut p = Pair::new(0); // raw
    p.termios[TERMIOS_OFF_CC + cc::VEOF] = 0x04;
    p.master_write(b"\x04");
    assert!(!p.pending_eof, "raw mode skips ICANON-only EOF path");
}

#[test]
fn cooked_verase_backspaces_unfinished_line() {
    let mut p = cooked(0);
    p.master_write(b"abc");
    p.master_write(b"\x7f");  // DEL = default VERASE
    p.master_write(b"\n");
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ab\n");
}

#[test]
fn cooked_verase_does_not_eat_past_newline() {
    let mut p = cooked(0);
    p.master_write(b"first\n");
    p.master_write(b"\x7f"); // backspace: should NOT touch "first\n"
    p.master_write(b"x\n");
    let mut buf = [0u8; 32];
    let n1 = p.slave_read(&mut buf);
    assert_eq!(n1, 6);
    assert_eq!(&buf[..6], b"first\n");
    let n2 = p.slave_read(&mut buf);
    assert_eq!(n2, 2);
    assert_eq!(&buf[..2], b"x\n");
}

#[test]
fn cooked_vkill_clears_unfinished_line() {
    let mut p = cooked(0);
    p.master_write(b"oops");
    p.master_write(b"\x15"); // ^U = default VKILL
    p.master_write(b"ok\n");
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ok\n");
}

#[test]
fn cooked_verase_echoes_destructive_backspace() {
    let mut p = cooked(0);
    p.master_write(b"x");
    let mut echo = [0u8; 8];
    let _ = p.master_read(&mut echo); // drain echo of 'x'
    p.master_write(b"\x7f");
    let n = p.master_read(&mut echo);
    // Linux ldisc echoes "\b \b" — destructive backspace.
    assert_eq!(n, 3);
    assert_eq!(&echo[..3], b"\x08 \x08");
}

#[test]
fn ixon_vstop_pauses_slave_writes() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&(iflag | iflag::IXON).to_le_bytes());
    // ^S on master pauses output.
    p.master_write(b"\x13");
    assert!(p.output_stopped);
    // slave_write under output_stopped is WITHHELD (consumed from src,
    // buffered in out_hold) — not dropped, not yet visible to master.
    let n = p.slave_write(b"hello");
    assert_eq!(n, 5);
    let mut buf = [0u8; 16];
    assert_eq!(p.master_read(&mut buf), 0, "no bytes reach master while paused");
}

#[test]
fn ixon_vstart_resumes_slave_writes() {
    let mut p = cooked(0);
    let iflag = read_iflag(&p.termios);
    p.termios[TERMIOS_OFF_IFLAG..TERMIOS_OFF_IFLAG + 4]
        .copy_from_slice(&(iflag | iflag::IXON).to_le_bytes());
    p.master_write(b"\x13");                  // ^S
    p.slave_write(b"held");                   // WITHHELD while paused (not dropped)
    let mut buf = [0u8; 16];
    assert_eq!(p.master_read(&mut buf), 0, "withheld while stopped");
    p.master_write(b"\x11");                  // ^Q → flush held bytes
    assert!(!p.output_stopped);
    p.slave_write(b"ok\n");
    let n = p.master_read(&mut buf);
    // Held "held" flushes first, then "ok\r\n" (ONLCR \n → \r\n).
    assert_eq!(n, 8);
    assert_eq!(&buf[..8], b"heldok\r\n");
}

#[test]
fn ixon_off_passes_ctrl_chars_through() {
    // IXON is OFF in cooked default — the master_write should let ^S/^Q
    // through to the slave as data.
    let mut p = cooked(0);
    p.master_write(b"\x13\n");
    let mut buf = [0u8; 8];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"\x13\n");
    assert!(!p.output_stopped, "no IXON → no flow control");
}

#[test]
fn cooked_vsusp_records_pending_sigtstp() {
    let mut p = cooked(0);
    p.master_write(b"a\x1ab\n"); // ^Z mid-line
    assert!(p.pending_sigtstp);
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(n, 3);
    assert_eq!(&buf[..3], b"ab\n");
}

#[test]
fn cooked_vquit_records_pending_sigquit() {
    let mut p = cooked(0);
    p.master_write(b"\x1c"); // ^\ alone
    assert!(p.pending_sigquit);
}

#[test]
fn cooked_vsusp_echoes_caret_z() {
    let mut p = cooked(0);
    p.master_write(b"\x1a");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"^Z");
}

#[test]
fn cooked_vquit_echoes_caret_backslash() {
    let mut p = cooked(0);
    p.master_write(b"\x1c");
    let mut buf = [0u8; 16];
    let n = p.master_read(&mut buf);
    assert_eq!(n, 2);
    assert_eq!(&buf[..2], b"^\\");
}

#[test]
fn raw_mode_passes_vsusp_through() {
    let mut p = Pair::new(0); // raw
    p.termios[TERMIOS_OFF_CC + cc::VSUSP] = 0x1A;
    p.master_write(b"\x1a");
    assert!(!p.pending_sigtstp, "raw mode skips ISIG");
}

// ---------------------------------------------------------------------------
// PTY hangup edge cases (console-plan B5 c): master close → slave EOF + EIO.
// ---------------------------------------------------------------------------

#[test]
fn master_hangup_makes_slave_read_eof() {
    let mut p = cooked(0);
    // A partial line with no newline would normally block under ICANON.
    p.master_write(b"partial");
    p.master_hangup();
    assert!(p.hung_up && p.pending_sighup);
    assert!(p.slave_readable(), "hung-up slave is readable (EOF-ready)");
    // Residual bytes drain, then EOF — bypassing the ICANON \n rule.
    let mut buf = [0u8; 16];
    let n = p.slave_read(&mut buf);
    assert_eq!(&buf[..n], b"partial");
    assert_eq!(p.slave_read(&mut buf), 0, "then EOF");
}

#[test]
fn master_hangup_makes_slave_write_hung() {
    let mut p = cooked(0);
    p.master_hangup();
    // The adapter maps slave_hung_up() → EIO; the predicate is the gate.
    assert!(p.slave_hung_up(), "slave writes should fail EIO after master close");
}

#[test]
fn slave_hangup_makes_master_read_eof() {
    let mut p = cooked(0);
    p.slave_write(b"out");
    p.hangup(); // generic (slave close) — master sees EOF after drain
    assert!(p.master_readable());
    let mut buf = [0u8; 8];
    assert_eq!(p.master_read(&mut buf), 3);
    assert_eq!(&buf[..3], b"out");
    assert_eq!(p.master_read(&mut buf), 0, "EOF after drain");
    // Slave close does NOT owe the slave a SIGHUP / EIO-on-write.
    assert!(!p.slave_hung_up());
}
