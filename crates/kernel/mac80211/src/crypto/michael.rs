// The message integrity code the temporal-key cipher adds on top of its
// per-frame check value.
//
// It is computed over a PSEUDO header — destination, source, priority and
// three zero bytes — that is never transmitted. A receiver that recomputed it
// over the real header would fail every frame, and one that omitted the
// priority byte would accept a frame whose traffic identifier an attacker had
// rewritten, which is the substitution this code exists to catch.

use wireless::ieee80211::{fctl, hdr::MacHeader, MacAddr};

use crate::uapi::cipher_len;

/// Width of the code.
pub const MIC_LEN: usize = cipher_len::MICHAEL_MIC;
/// Padding byte that terminates the message before the final zero block.
const PAD: u32 = 0x5a;

struct Ctx { l: u32, r: u32 }

impl Ctx {
    fn block(&mut self, val: u32) {
        self.l ^= val;
        self.r ^= self.l.rotate_left(17);
        self.l = self.l.wrapping_add(self.r);
        self.r ^= ((self.l & 0xff00_ff00) >> 8) | ((self.l & 0x00ff_00ff) << 8);
        self.l = self.l.wrapping_add(self.r);
        self.r ^= self.l.rotate_left(3);
        self.l = self.l.wrapping_add(self.r);
        self.r ^= self.l.rotate_right(2);
        self.l = self.l.wrapping_add(self.r);
    }
}

fn le32(b: &[u8]) -> u32 { u32::from_le_bytes([b[0], b[1], b[2], b[3]]) }
fn le16(b: &[u8]) -> u32 { u16::from_le_bytes([b[0], b[1]]) as u32 }

/// The bare algorithm over a byte string, with no pseudo header. Exposed on
/// its own because the published test vectors are stated in this form, and a
/// vector that can only be applied through the frame wrapper pins the wrapper
/// rather than the algorithm. # C: O(len)
pub fn mic_over(key: &[u8], data: &[u8]) -> [u8; MIC_LEN] {
    let mut ctx = Ctx { l: le32(&key[0..4]), r: le32(&key[4..8]) };
    finish(&mut ctx, data)
}

/// Compute the code over a frame's addresses, priority and payload. The key
/// is the eight-byte directional integrity key — the transmit half on send
/// and the receive half on receive, and swapping them yields a link that
/// fails in one direction only. # C: O(len)
pub fn michael_mic(key: &[u8], da: MacAddr, sa: MacAddr, tid: u8, data: &[u8])
    -> [u8; MIC_LEN]
{
    let mut ctx = Ctx { l: le32(&key[0..4]), r: le32(&key[4..8]) };
    // A pseudo header of destination, source, priority and three zero bytes
    // is folded in first. It is never transmitted; it is what binds the code
    // to the addresses and the traffic identifier.
    ctx.block(le32(&da.0[0..4]));
    ctx.block(le16(&da.0[4..6]) | (le16(&sa.0[0..2]) << 16));
    ctx.block(le32(&sa.0[2..6]));
    ctx.block(tid as u32);
    finish(&mut ctx, data)
}

fn finish(ctx: &mut Ctx, data: &[u8]) -> [u8; MIC_LEN] {
    let blocks = data.len() / 4;
    for b in 0..blocks { ctx.block(le32(&data[b * 4..b * 4 + 4])); }

    // Partial block: the padding byte, then the 0 to 3 remaining bytes fed in
    // from the top down, then a whole zero block.
    let mut left = data.len() % 4;
    let mut val = PAD;
    while left > 0 {
        val <<= 8;
        left -= 1;
        val |= data[blocks * 4 + left] as u32;
    }
    ctx.block(val);
    ctx.block(0);

    let mut out = [0u8; MIC_LEN];
    out[0..4].copy_from_slice(&ctx.l.to_le_bytes());
    out[4..8].copy_from_slice(&ctx.r.to_le_bytes());
    out
}

/// The same code, taking the addresses and priority from a parsed header.
/// A frame with no quality-of-service control field is priority zero.
/// # C: O(len)
pub fn michael_mic_hdr(key: &[u8], header: &MacHeader, data: &[u8]) -> Option<[u8; MIC_LEN]> {
    if key.len() < MIC_LEN { return None; }
    let da = header.destination()?;
    let sa = header.source()?;
    let tid = if fctl::is_data_qos(header.frame_control) { header.tid() } else { 0 };
    Some(michael_mic(key, da, sa, tid, data))
}
