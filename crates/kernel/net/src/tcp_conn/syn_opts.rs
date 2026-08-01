// Handshake option assembly: which options a SYN or SYN-ACK carries and the
// exact bytes they occupy.
//
// Module manifest:
// - this file: the option descriptor, its encoded length, and the writer.
// - `tests`: the wire layout every combination produces.
//
// The option area is variable: a handshake segment carries only the options
// that are actually being offered or echoed, packed the way the reference
// packs them. A fixed-length area cannot express that — it forces every SYN
// and SYN-ACK to carry the same three options whether or not they were
// negotiated, which is how this connection came to offer window scaling to
// peers that never asked for it.
//
// Padding is not free-form. Options are aligned by inserting no-ops ahead of
// them, and two options that would each need a pair of no-ops are packed into
// one word instead — timestamps and SACK-permitted share a word, which is why
// a SYN carrying both spends 16 option bytes rather than 20.
//
// No target gate: the layout is the observable contract, so it is decided here
// where `cargo test` compiles it (`docs/53§4`).

#[cfg(test)]
#[path = "syn_opts_tests.rs"]
mod tests;

use crate::tcp_conn::fastopen::Cookie;
use crate::tcp_hdr::{opt, FASTOPEN_MAGIC, TCP_HDR_MIN_LEN};

/// Largest option area a TCP header can address: the 4-bit data offset counts
/// 4-byte words, so the header is at most 60 bytes.
pub const MAX_OPTION_BYTES: usize = 40;

/// Option lengths as they appear in each option's own length byte.
pub const LEN_MSS: u8 = 4;
pub const LEN_WSCALE: u8 = 3;
pub const LEN_SACK_PERM: u8 = 2;
pub const LEN_TIMESTAMP: u8 = 10;

/// Bytes each option occupies once padded into the area.
const SPACE_MSS: usize = 4;
const SPACE_TIMESTAMP: usize = 12;
const SPACE_SACK_PERM: usize = 4;
const SPACE_WSCALE: usize = 4;

/// Bytes a fast-open option spends before its cookie: the kind and length
/// under the assigned number, and a further two for the experiment identifier
/// under the shared experimental number.
pub const LEN_FASTOPEN_BASE: usize = 2;
pub const LEN_EXP_FASTOPEN_BASE: usize = 4;

/// Bytes a fast-open option occupies, cookie included, rounded up to the word
/// the option area is measured in. # C: O(1)
fn space_fastopen(cookie: &Cookie) -> usize {
    let base = if cookie.exp { LEN_EXP_FASTOPEN_BASE } else { LEN_FASTOPEN_BASE };
    (base + cookie.len() + 3) & !3
}

/// What one handshake segment offers or echoes. Every field is `None`/`false`
/// unless this segment genuinely carries that option: a SYN-ACK echoes only
/// what the peer's SYN offered, so an absent field is how "the peer did not
/// ask for this" is represented.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct SynOptions {
    /// Largest segment this side will accept.
    pub mss: Option<u16>,
    /// `(TSval, TSecr)`. An opening SYN has nothing to echo, so its `TSecr` is
    /// zero.
    pub timestamp: Option<(u32, u32)>,
    /// This side accepts selective acknowledgements.
    pub sack_perm: bool,
    /// Window scale this side will apply to the windows it advertises.
    pub wscale: Option<u8>,
    /// A fast-open cookie to present, or an empty cookie asking for one.
    pub fastopen: Option<Cookie>,
}

impl SynOptions {
    /// Bytes the encoded area occupies. Always a multiple of four: every
    /// option in a handshake segment either fills its word or is packed
    /// against the no-ops of the one before it. # C: O(1)
    pub fn encoded_len(&self) -> usize {
        let mut len = 0;
        if self.mss.is_some() { len += SPACE_MSS; }
        if self.timestamp.is_some() { len += SPACE_TIMESTAMP; }
        // Timestamps carry SACK-permitted in the no-op pair they would
        // otherwise waste, so the pair costs nothing extra alongside them.
        if self.sack_perm && self.timestamp.is_none() { len += SPACE_SACK_PERM; }
        if self.wscale.is_some() { len += SPACE_WSCALE; }
        if let Some(c) = self.fastopen.as_ref() { len += space_fastopen(c); }
        len
    }

    /// Value of the header's data-offset field for a segment carrying these
    /// options and no payload-bearing extension. # C: O(1)
    pub fn data_offset(&self) -> u8 { ((TCP_HDR_MIN_LEN + self.encoded_len()) / 4) as u8 }

    /// Write the option area into `out`, returning the bytes written. `out`
    /// must hold [`Self::encoded_len`]; a shorter buffer writes nothing, since
    /// a partially written option area would be read as a different option.
    /// # C: O(1)
    pub fn encode(&self, out: &mut [u8]) -> usize {
        let len = self.encoded_len();
        if out.len() < len { return 0; }
        let mut i = 0;
        if let Some(mss) = self.mss {
            out[i] = opt::MSS;
            out[i + 1] = LEN_MSS;
            out[i + 2..i + 4].copy_from_slice(&mss.to_be_bytes());
            i += SPACE_MSS;
        }
        if let Some((tsval, tsecr)) = self.timestamp {
            // The two bytes ahead of the timestamp are padding either way, so
            // SACK-permitted is written into them rather than spending a word
            // of its own.
            if self.sack_perm {
                out[i] = opt::SACK_PERMIT;
                out[i + 1] = LEN_SACK_PERM;
            } else {
                out[i] = opt::NOP;
                out[i + 1] = opt::NOP;
            }
            out[i + 2] = opt::TIMESTAMP;
            out[i + 3] = LEN_TIMESTAMP;
            out[i + 4..i + 8].copy_from_slice(&tsval.to_be_bytes());
            out[i + 8..i + 12].copy_from_slice(&tsecr.to_be_bytes());
            i += SPACE_TIMESTAMP;
        } else if self.sack_perm {
            out[i] = opt::NOP;
            out[i + 1] = opt::NOP;
            out[i + 2] = opt::SACK_PERMIT;
            out[i + 3] = LEN_SACK_PERM;
            i += SPACE_SACK_PERM;
        }
        if let Some(ws) = self.wscale {
            out[i] = opt::NOP;
            out[i + 1] = opt::WSCALE;
            out[i + 2] = LEN_WSCALE;
            out[i + 3] = ws;
            i += SPACE_WSCALE;
        }
        if let Some(c) = self.fastopen.as_ref() {
            // The experimental form spends two extra bytes naming the
            // experiment; a peer that only speaks that form would not
            // recognise the assigned kind, so the reply keeps the kind the
            // exchange started under.
            let base = if c.exp { LEN_EXP_FASTOPEN_BASE } else { LEN_FASTOPEN_BASE };
            let opt_len = base + c.len();
            if c.exp {
                out[i] = opt::EXP;
                out[i + 1] = opt_len as u8;
                out[i + 2..i + 4].copy_from_slice(&FASTOPEN_MAGIC.to_be_bytes());
            } else {
                out[i] = opt::FASTOPEN;
                out[i + 1] = opt_len as u8;
            }
            out[i + base..i + base + c.len()].copy_from_slice(c.as_bytes());
            // The option is the last one written, so a length that does not
            // fill its final word is padded with no-ops rather than leaving
            // bytes a peer would walk into as another option.
            for pad in &mut out[i + opt_len..i + space_fastopen(c)] { *pad = opt::NOP; }
            i += space_fastopen(c);
        }
        i
    }
}
