// Byte-exactness of the ECHO stream across the whole RX path: the flip ring
// (device-interrupt half), `flush_to_ldisc` (workqueue half) and N_TTY's echo.
//
// The defect this pins down is a serial console that echoed ONE EXTRA COPY of
// a character roughly every ~40 bytes of typed input (`grep -E` echoed as
// `grep --E`, `env` as `ennv`) while the bytes DELIVERED to the shell stayed
// correct — so the extra copy entered somewhere between the ldisc's read queue
// and the wire. These tests hold the software half of that path to "one input
// byte in, exactly one echoed byte out", including across the staging-ring and
// flush-chunk boundaries and with a concurrent writer on the same tty.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::vec::Vec;

use super::RecordingDriver;
use crate::core::flip::{FLIP_CAPACITY, FLUSH_CHUNK};
use crate::pty::default_termios;
use crate::wait::host::HostWait;
use crate::TtyStruct;

type Tty = TtyStruct<RecordingDriver, HostWait>;

fn cooked_tty() -> Tty {
    // default_termios: ICANON | ECHO | ISIG, OPOST | ONLCR — a login line.
    TtyStruct::with_termios(RecordingDriver::default(), HostWait::new(), default_termios())
}

/// Everything the driver has been handed so far.
fn emitted(tty: &Tty) -> Vec<u8> {
    tty.with_driver(|d| d.out.clone())
}

/// Type `input` the way the UART does: stage in ISR-sized bursts, then run the
/// flush worker. `burst` is the number of bytes one interrupt delivers.
fn type_bytes(tty: &Tty, input: &[u8], burst: usize) {
    for chunk in input.chunks(burst) {
        assert_eq!(tty.insert_flip(chunk), chunk.len(), "staging must not drop");
        tty.flush_to_ldisc();
    }
}

/// A long line of printable input, echoed verbatim, must come back out with
/// the same length and the same bytes — no insertion, no duplication.
#[test]
fn echo_of_a_long_typed_stream_is_byte_exact() {
    let tty = cooked_tty();
    // Long enough to cross the ~40-byte period at which the reported duplicate
    // appeared many times over, and to wrap the flush chunk repeatedly.
    let mut input = Vec::new();
    for i in 0..4000u32 {
        input.push(b'a' + (i % 26) as u8);
    }
    type_bytes(&tty, &input, 8);
    assert_eq!(emitted(&tty), input, "echo must reproduce the typed bytes exactly");
}

/// The staging ring hands the ldisc `FLUSH_CHUNK` bytes at a time. A stream
/// that straddles that boundary must not re-echo the byte at the seam.
#[test]
fn echo_across_the_flush_chunk_boundary_is_byte_exact() {
    for len in [FLUSH_CHUNK - 1, FLUSH_CHUNK, FLUSH_CHUNK + 1, 2 * FLUSH_CHUNK + 3] {
        let tty = cooked_tty();
        let input: Vec<u8> = (0..len).map(|i| b'A' + (i % 26) as u8).collect();
        // One interrupt stages the whole burst; one flush drains it in chunks.
        assert_eq!(tty.insert_flip(&input), input.len());
        tty.flush_to_ldisc();
        assert_eq!(emitted(&tty), input, "len {len} must echo once per byte");
    }
}

/// Bytes staged while the previous flush is mid-drain must be echoed once, in
/// order — the interleaving the ISR/kworker split makes possible.
#[test]
fn echo_of_interleaved_staging_and_flushing_is_byte_exact() {
    let tty = cooked_tty();
    let mut expect = Vec::new();
    for round in 0..200u32 {
        let a = [b'0' + (round % 10) as u8; 3];
        let b = [b'a' + (round % 26) as u8; 5];
        tty.insert_flip(&a);
        tty.insert_flip(&b);
        tty.flush_to_ldisc();
        expect.extend_from_slice(&a);
        expect.extend_from_slice(&b);
    }
    assert_eq!(emitted(&tty), expect);
}

/// Whole typed lines reach the reader byte-for-byte; the terminal echo carries
/// the same stream after its default ONLCR rendering.
#[test]
fn echoed_bytes_and_delivered_bytes_agree_line_by_line() {
    let tty = cooked_tty();
    let lines: [&[u8]; 4] = [
        b"grep -E 'x' /run/user\n",
        b"timeout 60 env\n",
        b"/usr/bin/gnome-control-center\n",
        b"echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n",
    ];
    let mut typed = Vec::new();
    let mut delivered = Vec::new();
    for line in lines {
        typed.extend_from_slice(line);
        type_bytes(&tty, line, 1);
        let mut buf = [0u8; 256];
        let n = tty.read_nonblock(&mut buf);
        delivered.extend_from_slice(&buf[..n]);
    }
    let mut rendered = Vec::new();
    for b in &typed {
        if *b == b'\n' { rendered.extend_from_slice(b"\r\n"); }
        else { rendered.push(*b); }
    }
    assert_eq!(emitted(&tty), rendered, "echo stream");
    assert_eq!(delivered, typed, "bytes handed to the reader");
}

/// A full staging ring drops the overflow rather than re-echoing what it
/// already holds: a short `insert_flip` is a FIFO overrun, never a duplicate.
#[test]
fn a_saturated_staging_ring_drops_rather_than_duplicates() {
    let tty = cooked_tty();
    let input: Vec<u8> = (0..FLIP_CAPACITY + 64).map(|i| b'a' + (i % 26) as u8).collect();
    let taken = tty.insert_flip(&input);
    assert_eq!(taken, FLIP_CAPACITY, "the ring accepts exactly its capacity");
    tty.flush_to_ldisc();
    assert_eq!(emitted(&tty), input[..taken].to_vec());
    assert_eq!(tty.flip_dropped(), 64, "the refusal is counted, not hidden");
}

/// A program writing to the tty while input is being cooked must not make the
/// echo gain or lose a byte. The two paths take the port lock independently
/// (the echo from the flush worker, the write from the task), so this is the
/// concurrency causality test for the "one extra copy" symptom: the two
/// streams use disjoint byte classes, so any duplication shows up as a count
/// mismatch regardless of how the streams interleave.
#[test]
fn a_concurrent_writer_does_not_perturb_the_echo_count() {
    const TYPED: usize = 2000;
    const WRITTEN: usize = 2000;
    let tty = Arc::new(cooked_tty());
    let done = Arc::new(AtomicBool::new(false));

    let w_tty = Arc::clone(&tty);
    let w_done = Arc::clone(&done);
    let writer = std::thread::spawn(move || {
        for _ in 0..WRITTEN {
            // Digits: disjoint from the typed letters below.
            w_tty.write(b"7");
        }
        w_done.store(true, Ordering::Release);
    });

    for i in 0..TYPED {
        let b = [b'a' + (i % 26) as u8];
        w_reader_stage(&tty, &b);
    }
    writer.join().expect("writer thread");
    assert!(done.load(Ordering::Acquire));

    let out = emitted(&tty);
    let letters = out.iter().filter(|b| b.is_ascii_lowercase()).count();
    let digits = out.iter().filter(|b| **b == b'7').count();
    assert_eq!(letters, TYPED, "one echoed byte per typed byte");
    assert_eq!(digits, WRITTEN, "one written byte per write");
    assert_eq!(out.len(), TYPED + WRITTEN, "nothing else reached the driver");
}

fn w_reader_stage(tty: &Tty, bytes: &[u8]) {
    assert_eq!(tty.insert_flip(bytes), bytes.len());
    tty.flush_to_ldisc();
}
