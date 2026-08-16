// Card identity reported through SNDRV_CTL_IOCTL_CARD_INFO and
// SNDRV_PCM_IOCTL_INFO. The sound core owns the ABI field widths; the card
// driver owns the strings, so no transport name is hard-coded here.

use crate::uapi::*;

/// Fixed-width, NUL-padded identity fields in ALSA's own field widths.
#[derive(Clone)]
pub struct CardIdentity {
    pub id: [u8; ID_WIDTH],
    pub driver: [u8; ID_WIDTH],
    pub name: [u8; NAME_WIDTH],
    pub longname: [u8; LONG_WIDTH],
    pub mixername: [u8; LONG_WIDTH],
    pub components: [u8; COMPONENTS_WIDTH],
    /// `snd_pcm_info.name` stem; the stream direction is appended by the core.
    pub pcm_name: [u8; NAME_WIDTH],
}

pub const ID_WIDTH: usize = 16;
pub const NAME_WIDTH: usize = 32;
pub const LONG_WIDTH: usize = 80;
pub const COMPONENTS_WIDTH: usize = 128;

fn pad<const N: usize>(src: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    let n = if src.len() < N { src.len() } else { N };
    out[..n].copy_from_slice(&src[..n]);
    out
}

impl CardIdentity {
    /// Build an identity, truncating each field to its ALSA width. # C: O(field widths)
    pub fn new(id: &[u8], driver: &[u8], name: &[u8], longname: &[u8], mixername: &[u8],
               components: &[u8], pcm_name: &[u8]) -> Self {
        Self {
            id: pad(id), driver: pad(driver), name: pad(name), longname: pad(longname),
            mixername: pad(mixername), components: pad(components), pcm_name: pad(pcm_name),
        }
    }
}

/// Copy the identity into a `snd_ctl_card_info` at `card`. # C: O(struct size)
pub(crate) fn write_card_info(b: &UserBuf, card: u32, ident: &CardIdentity) {
    b.zero(0, CARD_INFO_SIZE);
    b.w32(CI_CARD, card);
    b.wstr(CI_ID, &ident.id, ID_WIDTH);
    b.wstr(CI_DRIVER, &ident.driver, ID_WIDTH);
    b.wstr(CI_NAME, &ident.name, NAME_WIDTH);
    b.wstr(CI_LONGNAME, &ident.longname, LONG_WIDTH);
    b.wstr(CI_MIXERNAME, &ident.mixername, LONG_WIDTH);
    b.wstr(CI_COMPONENTS, &ident.components, COMPONENTS_WIDTH);
}

/// Trim trailing NULs so the stem can be concatenated. # C: O(len)
pub(crate) fn trim(field: &[u8]) -> &[u8] {
    let mut end = field.len();
    while end > 0 && field[end - 1] == 0 { end -= 1; }
    &field[..end]
}

/// `"<pcm_name> <direction>"` for `snd_pcm_info.name`. # C: O(NAME_WIDTH)
pub(crate) fn pcm_stream_name(ident: &CardIdentity, capture: bool) -> [u8; LONG_WIDTH] {
    let stem = trim(&ident.pcm_name);
    let suffix: &[u8] = if capture { b" Capture" } else { b" Playback" };
    let mut out = [0u8; LONG_WIDTH];
    let mut n = 0;
    for &byte in stem.iter().chain(suffix.iter()) {
        if n == LONG_WIDTH { break; }
        out[n] = byte;
        n += 1;
    }
    out
}

#[cfg(test)]
#[path = "tests/identity_fields.rs"]
mod tests;
