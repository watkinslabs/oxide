// Record marking (RFC 1831 §10) — the framing a stream transport needs.
//
// A byte stream has no message boundaries, so RPC-over-TCP prefixes each record
// with a four-byte header whose top bit says "last fragment of this record" and
// whose low 31 bits give the fragment's payload length. A record is one or more
// fragments; the reassembler here concatenates them until the last-fragment bit
// arrives.
//
// This kernel SENDS single-fragment records, which is what makes the send side
// one function. It must still RECEIVE multi-fragment ones: nothing stops a
// server from splitting a large READ reply, and a receiver that assumed one
// fragment per record would treat the second fragment's header as reply data.

extern crate alloc;
use alloc::vec::Vec;

use crate::err::{RpcError, RpcResult};
use crate::uapi::frag;

/// The fragment header for a final fragment of `len` bytes. # C: O(1)
pub fn last_marker(len: usize) -> RpcResult<[u8; frag::HDR_LEN]> {
    if len > frag::MAX_FRAGMENT_SIZE as usize { return Err(RpcError::MsgTooLarge); }
    Ok(((len as u32) | frag::LAST_FRAGMENT).to_be_bytes())
}

/// Prefix `body` with a single last-fragment marker, producing the bytes to
/// write to a stream. # C: O(len)
pub fn frame(body: &[u8]) -> RpcResult<Vec<u8>> {
    let mut out = Vec::with_capacity(frag::HDR_LEN + body.len());
    out.extend_from_slice(&last_marker(body.len())?);
    out.extend_from_slice(body);
    Ok(out)
}

/// Reassembles records from a stream of bytes.
///
/// Feed it whatever arrived; take whole records out. It never assumes a read
/// ends on a fragment boundary — a stream splits wherever the network did, and
/// a header arriving two bytes at a time is ordinary.
pub struct Reassembler {
    /// Bytes of the current record accumulated so far, fragment headers
    /// stripped.
    record: Vec<u8>,
    /// Bytes of the current fragment's header seen so far.
    hdr: [u8; frag::HDR_LEN],
    hdr_len: usize,
    /// Payload bytes still owed for the current fragment, once its header is
    /// complete.
    want: usize,
    /// Whether the current fragment ends the record.
    last: bool,
    /// Whether a fragment header is being accumulated (as opposed to payload).
    in_hdr: bool,
    /// Largest record accepted before the stream is declared unusable.
    max_record: usize,
}

impl Reassembler {
    /// A reassembler that refuses any record larger than `max_record`.
    ///
    /// The cap is what stops a corrupt or hostile length word from making the
    /// client buffer unboundedly while it waits for bytes that will never come.
    /// # C: O(1)
    pub fn new(max_record: usize) -> Self {
        Self {
            record: Vec::new(),
            hdr: [0; frag::HDR_LEN],
            hdr_len: 0,
            want: 0,
            last: false,
            in_hdr: true,
            max_record,
        }
    }

    /// Discard partial state after a transport reset. # C: O(1)
    pub fn reset(&mut self) {
        self.record.clear();
        self.hdr_len = 0;
        self.want = 0;
        self.last = false;
        self.in_hdr = true;
    }

    /// Bytes of a partially received record. # C: O(1)
    pub fn pending(&self) -> usize { self.record.len() }

    /// Consume `input`, returning every complete record it finished.
    ///
    /// A record is returned only when its LAST fragment has arrived; a caller
    /// that acted on a non-final fragment would decode a reply body that stops
    /// mid-field. # C: O(len(input))
    pub fn feed(&mut self, mut input: &[u8]) -> RpcResult<Vec<Vec<u8>>> {
        let mut done = Vec::new();
        while !input.is_empty() {
            if self.in_hdr {
                let need = frag::HDR_LEN - self.hdr_len;
                let n = core::cmp::min(need, input.len());
                self.hdr[self.hdr_len..self.hdr_len + n].copy_from_slice(&input[..n]);
                self.hdr_len += n;
                input = &input[n..];
                if self.hdr_len < frag::HDR_LEN { break; }
                let h = u32::from_be_bytes(self.hdr);
                self.last = h & frag::LAST_FRAGMENT != 0;
                self.want = (h & frag::SIZE_MASK) as usize;
                self.hdr_len = 0;
                self.in_hdr = false;
                if self.record.len() + self.want > self.max_record {
                    self.reset();
                    return Err(RpcError::MsgTooLarge);
                }
                // A zero-length final fragment legitimately terminates a record
                // whose payload arrived in earlier fragments, so the
                // end-of-fragment check has to run even with no payload to
                // copy.
                if self.want == 0 && self.last {
                    done.push(core::mem::take(&mut self.record));
                    self.in_hdr = true;
                    self.last = false;
                }
                continue;
            }
            let n = core::cmp::min(self.want, input.len());
            self.record.extend_from_slice(&input[..n]);
            input = &input[n..];
            self.want -= n;
            if self.want == 0 {
                self.in_hdr = true;
                if self.last {
                    done.push(core::mem::take(&mut self.record));
                    self.last = false;
                }
            }
        }
        Ok(done)
    }
}
