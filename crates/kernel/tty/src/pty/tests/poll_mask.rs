// `n_tty_poll` readiness for both halves of a pty pair.
//
// These are the assertions the devpts `FileOps::poll` shims delegate to. They
// live here because `crates/kernel/devpts/src/lib.rs` is
// `#![cfg(target_os = "oxide-kernel")]` — a `#[cfg(test)]` block in that crate
// compiles out silently and reports "ok" having built nothing.

use super::*;

/// Fill `m_to_s` (what the MASTER writes into) to capacity with raw bytes.
fn fill_master_to_slave(p: &mut Pair) {
    let chunk = [b'x'; 256];
    while p.master_write_room() > 0 { p.master_write(&chunk); }
}

/// Fill `s_to_m` (what the SLAVE writes into) to capacity.
fn fill_slave_to_master(p: &mut Pair) {
    let chunk = [b'y'; 256];
    while p.slave_write_room() > 0 { p.slave_write(&chunk); }
}

#[test]
fn fresh_pair_is_writable_on_both_halves_and_readable_on_neither() {
    let p = Pair::new(0);
    assert_eq!(p.master_poll_mask(), vfs::POLL_OUT | vfs::POLL_WRNORM);
    assert_eq!(p.slave_poll_mask(), vfs::POLL_OUT | vfs::POLL_WRNORM);
}

#[test]
fn master_write_makes_the_slave_readable() {
    let mut p = Pair::new(0);
    p.master_write(b"hello");
    assert_ne!(p.slave_poll_mask() & vfs::POLL_IN, 0);
    assert_eq!(p.master_poll_mask() & vfs::POLL_IN, 0);
}

#[test]
fn slave_write_makes_the_master_readable() {
    let mut p = Pair::new(0);
    p.slave_write(b"output");
    assert_ne!(p.master_poll_mask() & vfs::POLL_IN, 0);
    assert_eq!(p.slave_poll_mask() & vfs::POLL_IN, 0);
}

#[test]
fn full_peer_buffer_clears_master_pollout() {
    // The state a poll-driven writer reaches with a slave that never reads.
    // POLLOUT must go away, or `write` keeps returning a short/zero count and
    // the writer spins.
    let mut p = Pair::new(0);
    fill_master_to_slave(&mut p);
    assert_eq!(p.master_write_room(), 0);
    assert_eq!(p.master_poll_mask() & vfs::POLL_OUT, 0);
    assert_eq!(p.master_write(b"more"), 0);
}

#[test]
fn slave_read_restores_master_pollout() {
    let mut p = Pair::new(0);
    fill_master_to_slave(&mut p);
    assert_eq!(p.master_poll_mask() & vfs::POLL_OUT, 0);
    let mut sink = [0u8; 512];
    assert!(p.slave_read(&mut sink) > 0);
    assert_ne!(p.master_poll_mask() & vfs::POLL_OUT, 0);
}

#[test]
fn full_peer_buffer_clears_slave_pollout() {
    let mut p = Pair::new(0);
    fill_slave_to_master(&mut p);
    assert_eq!(p.slave_poll_mask() & vfs::POLL_OUT, 0);
    assert_eq!(p.slave_write(b"more"), 0);
}

#[test]
fn master_read_restores_slave_pollout() {
    let mut p = Pair::new(0);
    fill_slave_to_master(&mut p);
    assert_eq!(p.slave_poll_mask() & vfs::POLL_OUT, 0);
    let mut sink = [0u8; 512];
    assert!(p.master_read(&mut sink) > 0);
    assert_ne!(p.slave_poll_mask() & vfs::POLL_OUT, 0);
}

#[test]
fn output_stopped_withholds_slave_pollout() {
    // Linux `pty_write_room` returns 0 outright while `tty->flow.stopped`
    // (^S / TCOOFF), so the program sleeps until ^Q instead of spinning.
    let mut p = cooked(0);
    assert_ne!(p.slave_poll_mask() & vfs::POLL_OUT, 0);
    p.flow_output(true);
    assert_eq!(p.slave_poll_mask() & vfs::POLL_OUT, 0);
    p.flow_output(false);
    assert_ne!(p.slave_poll_mask() & vfs::POLL_OUT, 0);
}

#[test]
fn master_hangup_reports_hup_and_eof_on_the_slave() {
    // `pty_close` on the last master fd sets TTY_OTHER_CLOSED on the link;
    // `n_tty_poll` then reports EPOLLHUP, and the read side reports EOF.
    let mut p = Pair::new(0);
    assert_eq!(p.slave_poll_mask() & vfs::POLL_HUP, 0);
    p.master_hangup();
    assert_ne!(p.slave_poll_mask() & vfs::POLL_HUP, 0);
    assert_ne!(p.slave_poll_mask() & vfs::POLL_IN, 0);
}

#[test]
fn canonical_mode_withholds_pollin_until_a_full_line() {
    // `input_available_p` under ICANON is `canon_head != read_tail`, i.e. a
    // completed line — a partial line must NOT report readable.
    let mut p = cooked(0);
    p.master_write(b"par");
    assert_eq!(p.slave_poll_mask() & vfs::POLL_IN, 0);
    p.master_write(b"tial\n");
    assert_ne!(p.slave_poll_mask() & vfs::POLL_IN, 0);
}
