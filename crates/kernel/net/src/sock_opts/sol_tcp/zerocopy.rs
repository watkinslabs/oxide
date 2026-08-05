// `TCP_ZEROCOPY_RECEIVE` ABI layout and decision logic.
//
// Module manifest:
// - this file: the optlen-versioned struct layout, the caller's length
//   admission, input validation, the map/copy plan, and the finish rules.
// - `tests`: hosted coverage for the layout, the errno ordering, and every
//   field-update rule.
//
// No target gate: `055_getsockopt/tcp_zerocopy.rs` is the byte-moving shim and
// carries no decisions, so everything decidable lives here where `cargo test`
// compiles it (`docs/53§4`).

#[cfg(test)]
mod tests;

use syscall::errno::Errno;

/// Field offsets of the option's operand struct. The struct grew field by
/// field, so an offset is ABI forever once published.
pub const OFF_ADDRESS: usize = 0;
pub const OFF_LENGTH: usize = 8;
pub const OFF_RECV_SKIP_HINT: usize = 12;
pub const OFF_INQ: usize = 16;
pub const OFF_ERR: usize = 20;
pub const OFF_COPYBUF_ADDRESS: usize = 24;
pub const OFF_COPYBUF_LEN: usize = 32;
pub const OFF_FLAGS: usize = 36;
pub const OFF_MSG_CONTROL: usize = 40;
pub const OFF_MSG_CONTROLLEN: usize = 48;
pub const OFF_MSG_FLAGS: usize = 56;
pub const OFF_RESERVED: usize = 60;

/// One-past-the-end of each field: the caller's `optlen` is compared against
/// these, so each names the struct version that first carried the field.
pub const END_ADDRESS: usize = OFF_ADDRESS + 8;
pub const END_LENGTH: usize = OFF_LENGTH + 4;
pub const END_RECV_SKIP_HINT: usize = OFF_RECV_SKIP_HINT + 4;
pub const END_INQ: usize = OFF_INQ + 4;
pub const END_ERR: usize = OFF_ERR + 4;
pub const END_COPYBUF_ADDRESS: usize = OFF_COPYBUF_ADDRESS + 8;
pub const END_COPYBUF_LEN: usize = OFF_COPYBUF_LEN + 4;
pub const END_FLAGS: usize = OFF_FLAGS + 4;
pub const END_MSG_CONTROL: usize = OFF_MSG_CONTROL + 8;
pub const END_MSG_CONTROLLEN: usize = OFF_MSG_CONTROLLEN + 8;
pub const END_MSG_FLAGS: usize = OFF_MSG_FLAGS + 4;
pub const ZC_SIZE: usize = OFF_RESERVED + 4;

/// `flags` input bit: the caller promises the window carries no live
/// translations, so the kernel may skip the pre-insert unmap.
pub const ZEROCOPY_FLAG_TLB_CLEAN_HINT: u32 = 0x1;

/// `msg_flags` bit reporting that a receive timestamp was published through
/// `msg_control`. The only bit the option accepts on input.
pub const CMSG_TS: u32 = 2;
pub const VALID_ZC_MSG_FLAGS: u32 = CMSG_TS;

/// The operand struct, zero-extended from whatever prefix the caller passed.
#[derive(Copy, Clone, Debug, Default, Eq, PartialEq)]
pub struct Zc {
    pub address: u64,
    pub length: u32,
    pub recv_skip_hint: u32,
    pub inq: u32,
    pub err: i32,
    pub copybuf_address: u64,
    pub copybuf_len: i32,
    pub flags: u32,
    pub msg_control: u64,
    pub msg_controllen: u64,
    pub msg_flags: u32,
    pub reserved: u32,
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    let mut w = [0u8; 4];
    for (i, slot) in w.iter_mut().enumerate() { if let Some(v) = b.get(off + i) { *slot = *v; } }
    u32::from_ne_bytes(w)
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    let mut w = [0u8; 8];
    for (i, slot) in w.iter_mut().enumerate() { if let Some(v) = b.get(off + i) { *slot = *v; } }
    u64::from_ne_bytes(w)
}

impl Zc {
    /// Parse the caller's prefix; every field past `bytes` reads as zero, which
    /// is what makes a short operand mean "the fields that version did not
    /// have are unset". # C: O(1)
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self {
            address: u64_at(bytes, OFF_ADDRESS),
            length: u32_at(bytes, OFF_LENGTH),
            recv_skip_hint: u32_at(bytes, OFF_RECV_SKIP_HINT),
            inq: u32_at(bytes, OFF_INQ),
            err: u32_at(bytes, OFF_ERR) as i32,
            copybuf_address: u64_at(bytes, OFF_COPYBUF_ADDRESS),
            copybuf_len: u32_at(bytes, OFF_COPYBUF_LEN) as i32,
            flags: u32_at(bytes, OFF_FLAGS),
            msg_control: u64_at(bytes, OFF_MSG_CONTROL),
            msg_controllen: u64_at(bytes, OFF_MSG_CONTROLLEN),
            msg_flags: u32_at(bytes, OFF_MSG_FLAGS),
            reserved: u32_at(bytes, OFF_RESERVED),
        }
    }

    /// Render the whole struct; the caller publishes only its own prefix.
    /// # C: O(1)
    pub fn to_bytes(&self) -> [u8; ZC_SIZE] {
        let mut b = [0u8; ZC_SIZE];
        b[OFF_ADDRESS..END_ADDRESS].copy_from_slice(&self.address.to_ne_bytes());
        b[OFF_LENGTH..END_LENGTH].copy_from_slice(&self.length.to_ne_bytes());
        b[OFF_RECV_SKIP_HINT..END_RECV_SKIP_HINT].copy_from_slice(&self.recv_skip_hint.to_ne_bytes());
        b[OFF_INQ..END_INQ].copy_from_slice(&self.inq.to_ne_bytes());
        b[OFF_ERR..END_ERR].copy_from_slice(&self.err.to_ne_bytes());
        b[OFF_COPYBUF_ADDRESS..END_COPYBUF_ADDRESS].copy_from_slice(&self.copybuf_address.to_ne_bytes());
        b[OFF_COPYBUF_LEN..END_COPYBUF_LEN].copy_from_slice(&self.copybuf_len.to_ne_bytes());
        b[OFF_FLAGS..END_FLAGS].copy_from_slice(&self.flags.to_ne_bytes());
        b[OFF_MSG_CONTROL..END_MSG_CONTROL].copy_from_slice(&self.msg_control.to_ne_bytes());
        b[OFF_MSG_CONTROLLEN..END_MSG_CONTROLLEN].copy_from_slice(&self.msg_controllen.to_ne_bytes());
        b[OFF_MSG_FLAGS..END_MSG_FLAGS].copy_from_slice(&self.msg_flags.to_ne_bytes());
        b[OFF_RESERVED..ZC_SIZE].copy_from_slice(&self.reserved.to_ne_bytes());
        b
    }
}

/// What the caller's declared `optlen` admits.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum LenPlan {
    /// Read and publish exactly this many bytes.
    Use(usize),
    /// The caller declared a struct longer than this kernel knows. The excess
    /// must read as all-zero (otherwise the caller is asking for a field this
    /// kernel cannot answer), after which the operand is clamped and the
    /// clamped length published back through `optlen`.
    Clamp { tail_off: usize, tail_len: usize },
}

/// Admit the caller's declared length. A length that cannot even carry
/// `length` is rejected, because `length` is the field the option's contract
/// is built on. # C: O(1)
pub fn admit_optlen(len: i32) -> Result<LenPlan, Errno> {
    if len < 0 { return Err(Errno::Einval); }
    let len = len as usize;
    if len < END_LENGTH { return Err(Errno::Einval); }
    if len > ZC_SIZE { return Ok(LenPlan::Clamp { tail_off: ZC_SIZE, tail_len: len - ZC_SIZE }); }
    Ok(LenPlan::Use(len))
}

/// Screen the operand's input-only fields. # C: O(1)
pub fn validate_input(zc: &Zc) -> Result<(), Errno> {
    if zc.reserved != 0 { return Err(Errno::Einval); }
    if zc.msg_flags & !VALID_ZC_MSG_FLAGS != 0 { return Err(Errno::Einval); }
    Ok(())
}

/// Which output fields a given operand version gets refreshed. Ordered: each
/// stage also performs every stage below it.
#[derive(Copy, Clone, Debug, Eq, PartialEq, PartialOrd, Ord)]
pub enum Stage {
    /// Only `length` and `recv_skip_hint` are published.
    Out = 0,
    /// …plus `inq`.
    Inq = 1,
    /// …plus the socket's pending error in `err`.
    SkErr = 2,
    /// …plus the ancillary-data report in `msg_flags` / `msg_control`.
    Cmsg = 3,
}

/// Map an admitted operand length onto its output stage. Only the exact
/// end-of-field lengths select the intermediate stages: a length that lands
/// mid-field carries no complete field to publish, so it falls to `Out`.
/// # C: O(1)
pub fn output_stage(len: usize) -> Stage {
    if len >= END_MSG_FLAGS { return Stage::Cmsg; }
    match len {
        END_MSG_CONTROLLEN | END_MSG_CONTROL | END_FLAGS
            | END_COPYBUF_LEN | END_COPYBUF_ADDRESS | END_ERR => Stage::SkErr,
        END_INQ => Stage::Inq,
        _ => Stage::Out,
    }
}

/// The live state one call is planned against.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZcQuery {
    pub address: u64,
    /// Bytes the caller offers to have mapped.
    pub length: u32,
    pub copybuf_len: i32,
    pub flags: u32,
    /// Bytes queued for the reader.
    pub inq: u32,
    pub listening: bool,
    /// The stream has ended and nothing further can arrive.
    pub done: bool,
    /// Exclusive end of the receive window the caller's address falls in, or
    /// `None` when no window covers it.
    pub window_end: Option<u64>,
    pub page: u64,
}

/// What one call must do.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ZcAction {
    /// Everything queued fits the copy buffer, so a plain non-blocking receive
    /// of `bytes` into `copybuf_address` beats mapping pages.
    Fallback { bytes: u32 },
    /// Less than a page is queued: nothing is mappable, and `recv_skip_hint`
    /// tells the caller how much it must receive the ordinary way.
    Short { recv_skip_hint: u32 },
    /// Remap `map_bytes` of receive-queue pages at `address`, after dropping
    /// `zap_bytes` of stale translations there.
    Map { zap_bytes: u32, map_bytes: u32, length: u32, recv_skip_hint: u32 },
}

/// Plan one call. The order of the tests is the errno contract: a misaligned
/// address is rejected before the socket's state is consulted, and the window
/// is only looked for once a page-sized remap is actually possible.
/// # C: O(1)
pub fn plan(q: &ZcQuery) -> Result<ZcAction, Errno> {
    if q.address & (q.page - 1) != 0 { return Err(Errno::Einval); }
    if q.listening { return Err(Errno::Enotconn); }
    if q.inq != 0 && q.copybuf_len > 0 && q.inq <= q.copybuf_len as u32 {
        return Ok(ZcAction::Fallback { bytes: q.inq });
    }
    if (q.inq as u64) < q.page {
        if q.inq == 0 && q.done { return Err(Errno::Eio); }
        return Ok(ZcAction::Short { recv_skip_hint: q.inq });
    }
    let end = match q.window_end { Some(end) if end > q.address => end, _ => return Err(Errno::Einval) };
    let window = (end - q.address).min(q.length as u64) as u32;
    let avail = window.min(q.inq);
    let total = avail & !((q.page - 1) as u32);
    if total != 0 {
        // The clean-TLB hint only lets Linux DEFER the unmap to the retry that
        // a live translation forces; the caller cannot observe the difference,
        // and an unmapped-first window is the only shape that can never publish
        // a stale page. So the window is always dropped first.
        Ok(ZcAction::Map { zap_bytes: total, map_bytes: total, length: total, recv_skip_hint: 0 })
    } else {
        Ok(ZcAction::Map { zap_bytes: 0, map_bytes: 0, length: avail, recv_skip_hint: avail })
    }
}

/// Bytes the copy buffer takes from what could not be mapped. # C: O(1)
pub fn straggler_bytes(copybuf_len: i32, recv_skip_hint: u32) -> u32 {
    if copybuf_len <= 0 { return 0; }
    (copybuf_len as u32).min(recv_skip_hint)
}

/// Transfer complete receive pages into a receive window. A failed install
/// consumes and releases its page, then leaves later queue pages untouched.
/// # C: O(page count)
pub fn donate_pages(bytes: u32, page: u32, mut take: impl FnMut() -> Option<u64>,
                    mut install: impl FnMut(u64, u64) -> bool,
                    mut release: impl FnMut(u64)) -> u32 {
    let mut done = 0;
    while done < bytes {
        let Some(pa) = take() else { break; };
        if !install(done as u64, pa) {
            release(pa);
            break;
        }
        done += page;
    }
    done
}

/// The operand's output fields after the mapping and the straggler copy.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct ZcFinish {
    pub length: u32,
    pub recv_skip_hint: u32,
    pub copybuf_len: i32,
}

/// Close out one call. `target` is the byte count the plan asked for, `mapped`
/// what the remap achieved, and `copied` what the copy buffer took.
///
/// Mapping the whole target retires the hint: there is nothing the caller must
/// receive the ordinary way before its next call. A call that moved no bytes at
/// all over an ended stream is the end-of-stream report. # C: O(1)
pub fn finish(target: u32, mapped: u32, recv_skip_hint: u32, copied: u32, done: bool)
    -> Result<ZcFinish, Errno>
{
    let hint = recv_skip_hint.saturating_sub(copied);
    if mapped == 0 && copied == 0 {
        if hint == 0 && done { return Err(Errno::Eio); }
        return Ok(ZcFinish { length: 0, recv_skip_hint: hint, copybuf_len: copied as i32 });
    }
    let hint = if mapped == target { 0 } else { hint };
    Ok(ZcFinish { length: mapped, recv_skip_hint: hint, copybuf_len: copied as i32 })
}
