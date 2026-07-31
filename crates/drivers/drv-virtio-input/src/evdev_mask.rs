// Per-client evdev event masks: the decision logic behind EVIOCGMASK and
// EVIOCSMASK, and the delivery-time filter they drive. Ungated on purpose —
// the ioctl slot is a copy shim, every rule below is hosted-testable.

use alloc::vec;
use alloc::vec::Vec;

use input::{
    ABS_CNT, EV_ABS, EV_CNT, EV_FF, EV_KEY, EV_LED, EV_MSC, EV_REL, EV_SND, EV_SW, EV_SYN,
    FF_CNT, KEY_CNT, LED_CNT, MSC_CNT, REL_CNT, SND_CNT, SW_CNT,
};

/// Bit width of the mask word the ABI transfers masks in.
pub const MASK_WORD_BITS: usize = u64::BITS as usize;
/// Byte width of that word; every transfer length is a multiple of it.
pub const MASK_WORD_BYTES: usize = core::mem::size_of::<u64>();
/// Largest mask storage any event type needs, so a transfer needs no allocation.
pub const MASK_MAX_BYTES: usize = bits_to_words(KEY_CNT) * MASK_WORD_BYTES;
/// Byte written for every code of a type whose client mask is unset.
pub const MASK_UNSET_FILL: u8 = 0xff;

/// Words needed to hold `bits` bits.
/// # C: O(1)
pub const fn bits_to_words(bits: usize) -> usize {
    bits.div_ceil(MASK_WORD_BITS)
}

/// Code count of one type's mask, or zero when the type carries no mask.
/// Type zero masks event TYPES, so its count is the type count.
/// # C: O(1)
pub fn mask_cnt(ev_type: u32) -> usize {
    match u16::try_from(ev_type) {
        Ok(t) if t == EV_SYN => EV_CNT,
        Ok(t) if t == EV_KEY => KEY_CNT,
        Ok(t) if t == EV_REL => REL_CNT,
        Ok(t) if t == EV_ABS => ABS_CNT,
        Ok(t) if t == EV_MSC => MSC_CNT,
        Ok(t) if t == EV_SW => SW_CNT,
        Ok(t) if t == EV_LED => LED_CNT,
        Ok(t) if t == EV_SND => SND_CNT,
        Ok(t) if t == EV_FF => FF_CNT,
        _ => 0,
    }
}

/// Stored size of one type's mask.
/// # C: O(1)
pub fn mask_storage_bytes(cnt: usize) -> usize {
    bits_to_words(cnt) * MASK_WORD_BYTES
}

/// Transferable size of one type's mask. Derived from the highest code rather
/// than the count, so a count landing one bit past a word boundary transfers
/// one word less than it stores.
/// # C: O(1)
pub fn mask_transfer_bytes(cnt: usize) -> usize {
    if cnt == 0 { 0 } else { bits_to_words(cnt - 1) * MASK_WORD_BYTES }
}

/// `struct input_mask` as it crosses the ABI.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct InputMask {
    pub ev_type: u32,
    pub codes_size: u32,
    pub codes_ptr: u64,
}

/// ABI size of `struct input_mask`.
pub const INPUT_MASK_BYTES: usize = 16;
const INPUT_MASK_TYPE_OFF: usize = 0;
const INPUT_MASK_CODES_SIZE_OFF: usize = 4;
const INPUT_MASK_CODES_PTR_OFF: usize = 8;

/// Decode the fixed-length descriptor both mask commands carry.
/// # C: O(1)
pub fn parse_input_mask(raw: &[u8; INPUT_MASK_BYTES]) -> InputMask {
    let mut t = [0u8; 4];
    t.copy_from_slice(&raw[INPUT_MASK_TYPE_OFF..INPUT_MASK_CODES_SIZE_OFF]);
    let mut s = [0u8; 4];
    s.copy_from_slice(&raw[INPUT_MASK_CODES_SIZE_OFF..INPUT_MASK_CODES_PTR_OFF]);
    let mut p = [0u8; 8];
    p.copy_from_slice(&raw[INPUT_MASK_CODES_PTR_OFF..INPUT_MASK_BYTES]);
    InputMask {
        ev_type: u32::from_le_bytes(t),
        codes_size: u32::from_le_bytes(s),
        codes_ptr: u64::from_le_bytes(p),
    }
}

/// What the read direction owes the caller's buffer. Unknown types are not an
/// error — they transfer nothing and leave the whole buffer zeroed, which is
/// how a caller learns the type carries no mask.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct GetMaskPlan {
    /// Bytes of mask content the buffer receives, from offset zero.
    pub payload: usize,
    /// First byte past the transfer; everything from here to `codes_size` zeroes.
    pub tail_off: usize,
    /// Bytes zeroed after the payload.
    pub tail_len: usize,
}

/// Split the caller's buffer into the mask transfer and the zero-filled tail.
/// # C: O(1)
pub fn plan_get(cnt: usize, codes_size: u32) -> GetMaskPlan {
    let codes_size = codes_size as usize;
    let xfer = codes_size.min(mask_storage_bytes(cnt));
    GetMaskPlan {
        payload: xfer,
        tail_off: xfer,
        tail_len: codes_size - xfer,
    }
}

/// Bytes of a present mask the read direction copies. Short buffers truncate;
/// they are not an error in this direction.
/// # C: O(1)
pub fn get_copy_len(cnt: usize, plan: GetMaskPlan) -> usize {
    mask_transfer_bytes(cnt).min(plan.payload)
}

/// Why the write direction refused, or how much of the caller's buffer it reads.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum SetMaskPlan {
    /// Type carries no mask: accepted and ignored, so masks stay forward-compatible.
    Ignore,
    /// Buffer length is not a whole number of mask words.
    Misaligned,
    /// Read this many bytes; codes past them keep their zeroed state.
    Copy(usize),
}

/// Decide the write direction before any of the caller's buffer is touched.
/// # C: O(1)
pub fn plan_set(cnt: usize, codes_size: u32) -> SetMaskPlan {
    if cnt == 0 { return SetMaskPlan::Ignore; }
    let codes_size = codes_size as usize;
    if codes_size % MASK_WORD_BYTES != 0 { return SetMaskPlan::Misaligned; }
    SetMaskPlan::Copy(mask_transfer_bytes(cnt).min(codes_size))
}

/// One client's per-type masks. An unset type admits every code.
pub struct EvdevMasks {
    masks: [Option<Vec<u8>>; EV_CNT],
}

impl Default for EvdevMasks {
    fn default() -> Self { Self::new() }
}

impl EvdevMasks {
    /// # C: O(EV_CNT)
    pub fn new() -> Self {
        Self { masks: [const { None }; EV_CNT] }
    }

    /// Borrow the stored mask of one type.
    /// # C: O(1)
    pub fn get(&self, ev_type: u32) -> Option<&[u8]> {
        let idx = usize::try_from(ev_type).ok()?;
        self.masks.get(idx)?.as_deref()
    }

    /// Install one type's mask from `bytes`; codes past `bytes` are cleared.
    /// Rejected for a type that carries no mask.
    /// # C: O(mask bytes)
    pub fn set(&mut self, ev_type: u32, bytes: &[u8]) -> bool {
        let cnt = mask_cnt(ev_type);
        if cnt == 0 { return false; }
        let Ok(idx) = usize::try_from(ev_type) else { return false; };
        let Some(slot) = self.masks.get_mut(idx) else { return false; };
        let mut stored = vec![0u8; mask_storage_bytes(cnt)];
        let n = bytes.len().min(stored.len());
        stored[..n].copy_from_slice(&bytes[..n]);
        *slot = Some(stored);
        true
    }

    /// Does any type currently carry a mask?
    /// # C: O(EV_CNT)
    pub fn any(&self) -> bool {
        self.masks.iter().any(Option::is_some)
    }

    /// Is this value withheld from the client by its masks? Synchronization
    /// events and codes past a mask's width are always delivered.
    /// # C: O(1)
    pub fn is_filtered(&self, ev_type: u16, code: u16) -> bool {
        if ev_type == EV_SYN || usize::from(ev_type) >= EV_CNT { return false; }
        if let Some(types) = self.get(u32::from(EV_SYN)) {
            if !bit_set(types, usize::from(ev_type)) { return true; }
        }
        let cnt = mask_cnt(u32::from(ev_type));
        if cnt == 0 || usize::from(code) >= cnt { return false; }
        match self.get(u32::from(ev_type)) {
            Some(mask) => !bit_set(mask, usize::from(code)),
            None => false,
        }
    }
}

/// Values of one packet this client's masks admit. A report whose values were
/// all withheld is withheld with them, so masking never delivers empty packets.
/// # C: O(packet values)
pub fn admit_values(masks: &EvdevMasks, values: &[input::InputValue]) -> Vec<input::InputValue> {
    let mut out = Vec::with_capacity(values.len());
    let mut since_report = 0usize;
    for value in values {
        if masks.is_filtered(value.ev_type, value.code) { continue; }
        if value.ev_type == EV_SYN && value.code == input::SYN_REPORT {
            if since_report == 0 { continue; }
            since_report = 0;
        } else {
            since_report += 1;
        }
        out.push(*value);
    }
    out
}

/// Test one bit of a little-endian mask buffer.
/// # C: O(1)
pub fn bit_set(mask: &[u8], bit: usize) -> bool {
    let byte = bit / u8::BITS as usize;
    match mask.get(byte) {
        Some(b) => b & (1u8 << (bit % u8::BITS as usize)) != 0,
        None => false,
    }
}

#[cfg(test)]
mod tests;
