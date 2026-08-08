// One audit record: a type and the text a consumer parses.
//
// Every record opens with `audit(SECONDS.MILLIS:SERIAL): `. The (timestamp,
// serial) pair is the record's identity — a single event may be split across
// several records, and userspace re-joins them by that pair, so the serial is
// allocated once per record and never reused.

extern crate alloc;

use alloc::vec::Vec;
use core::sync::atomic::{AtomicU32, Ordering};

use crate::fmt;

/// A queued record. `text` already carries the stamp prefix.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Record {
    pub ty: u16,
    pub text: Vec<u8>,
}

impl Record {
    /// # C: O(1)
    pub fn len(&self) -> usize { self.text.len() }
    /// # C: O(1)
    pub fn is_empty(&self) -> bool { self.text.is_empty() }
}

static SERIAL: AtomicU32 = AtomicU32::new(0);

/// Allocate the next record serial. Wrapping is harmless: userspace pairs the
/// serial with the timestamp, and the counter cannot wrap within one second's
/// worth of records.
/// # C: O(1)
pub fn next_serial() -> u32 { SERIAL.fetch_add(1, Ordering::Relaxed).wrapping_add(1) }

/// Build the `audit(SECS.MMM:SERIAL): ` prefix.
/// # C: O(digits)
pub fn stamp(out: &mut Vec<u8>, secs: u64, millis: u64, serial: u32) {
    const MILLIS_WIDTH: usize = 3;
    out.extend_from_slice(b"audit(");
    fmt::dec(out, secs);
    out.push(b'.');
    fmt::dec_pad(out, millis, MILLIS_WIDTH);
    out.push(b':');
    fmt::dec(out, serial as u64);
    out.extend_from_slice(b"): ");
}

/// Assemble a record from a body, stamping it at `realtime_ns`.
/// # C: O(body len)
pub fn build(ty: u16, realtime_ns: u64, serial: u32, body: &[u8]) -> Record {
    const NS_PER_SEC: u64 = 1_000_000_000;
    const NS_PER_MS:  u64 = 1_000_000;
    let mut text = Vec::with_capacity(body.len() + 32);
    stamp(&mut text, realtime_ns / NS_PER_SEC, (realtime_ns % NS_PER_SEC) / NS_PER_MS, serial);
    text.extend_from_slice(body);
    Record { ty, text }
}

#[cfg(test)]
#[path = "tests/record.rs"]
mod tests;
