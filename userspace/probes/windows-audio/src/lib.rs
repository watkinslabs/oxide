//! Strict Windows PCM format boundary for the native sound service.
//!
//! This is the format half of the future XAudio2/DirectSound adapter.  The
//! kernel sound core remains the owner of device negotiation and buffer
//! lifetime; this crate only validates the Windows ABI and produces a stable
//! descriptor for that owner.  The layout follows Wine's WAVEFORMATEX use and
//! the Windows multimedia contract.

/// `WAVEFORMATEX` for the 64-bit Windows ABI.  It contains no pointers.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaveFormatEx {
    pub format_tag: u16,
    pub channels: u16,
    pub samples_per_sec: u32,
    pub avg_bytes_per_sec: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
    pub cb_size: u16,
}

/// `WAVEFORMATEXTENSIBLE` with its fixed 22-byte extension.
#[repr(C)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaveFormatExtensible {
    pub format: WaveFormatEx,
    pub valid_bits_per_sample: u16,
    pub channel_mask: u32,
    pub sub_format: [u8; 16],
}

pub const WAVE_FORMAT_PCM: u16 = 1;
pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
pub const WAVE_FORMAT_EXTENSIBLE: u16 = 0xfffe;
pub const EXTENSIBLE_CB_SIZE: u16 = 22;
pub const SUBFORMAT_PCM: [u8; 16] = [1, 0, 0, 0, 0, 0, 16, 0, 128, 0, 0, 170, 0, 56, 155, 113];
pub const SUBFORMAT_IEEE_FLOAT: [u8; 16] = [3, 0, 0, 0, 0, 0, 16, 0, 128, 0, 0, 170, 0, 56, 155, 113];
pub const MAX_CHANNELS: u16 = 8;
pub const MIN_RATE: u32 = 8_000;
pub const MAX_RATE: u32 = 192_000;

/// Native format accepted by the current kernel PCM core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSampleFormat { U8, S16Le, S24Le, S32Le, F32Le }

impl NativeSampleFormat {
    pub const fn bytes(self) -> u32 {
        match self { Self::U8 => 1, Self::S16Le => 2, Self::S24Le => 3, Self::S32Le | Self::F32Le => 4 }
    }
}

/// Validated, overflow-free descriptor consumed by a sound backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativePcmFormat {
    pub format: NativeSampleFormat,
    pub channels: u16,
    pub rate: u32,
    pub frame_bytes: u32,
    pub byte_rate: u32,
    pub valid_bits_per_sample: u16,
    pub channel_mask: u32,
}

mod stream;
pub use stream::{AudioDirection, AudioStream, StreamError, StreamGeometry, StreamState, HNS_PER_SEC};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    UnsupportedTag,
    InvalidChannels,
    InvalidRate,
    UnsupportedBits,
    InvalidBlockAlign,
    InvalidByteRate,
    UnsupportedExtension,
    InvalidValidBits,
    InvalidChannelMask,
    UnsupportedSubtype,
}

/// Validate a Windows PCM format and normalize it for the native sound core.
/// # C: O(1)
pub fn normalize_pcm(wave: &WaveFormatEx) -> Result<NativePcmFormat, FormatError> {
    if wave.format_tag != WAVE_FORMAT_PCM && wave.format_tag != WAVE_FORMAT_IEEE_FLOAT { return Err(FormatError::UnsupportedTag); }
    if wave.cb_size != 0 { return Err(FormatError::UnsupportedExtension); }
    let subtype = if wave.format_tag == WAVE_FORMAT_PCM { SUBFORMAT_PCM } else { SUBFORMAT_IEEE_FLOAT };
    normalize_parts(wave, wave.bits_per_sample, channel_mask_for(wave.channels), subtype)
}

/// Validate the fixed extensible audio descriptor used by WASAPI and winmm.
/// # C: O(1)
pub fn normalize_extensible(wave: &WaveFormatExtensible) -> Result<NativePcmFormat, FormatError> {
    if wave.format.format_tag != WAVE_FORMAT_EXTENSIBLE { return Err(FormatError::UnsupportedTag); }
    if wave.format.cb_size < EXTENSIBLE_CB_SIZE { return Err(FormatError::UnsupportedExtension); }
    normalize_parts(format_ref(wave), wave.valid_bits_per_sample, wave.channel_mask, wave.sub_format)
}

fn format_ref(wave: &WaveFormatExtensible) -> &WaveFormatEx { &wave.format }

fn channel_mask_for(channels: u16) -> u32 { (1u32 << u32::from(channels)) - 1 }

fn normalize_parts(wave: &WaveFormatEx, valid_bits: u16, channel_mask: u32, subtype: [u8; 16]) -> Result<NativePcmFormat, FormatError> {
    if wave.channels == 0 || wave.channels > MAX_CHANNELS { return Err(FormatError::InvalidChannels); }
    if !(MIN_RATE..=MAX_RATE).contains(&wave.samples_per_sec) { return Err(FormatError::InvalidRate); }
    if valid_bits == 0 || valid_bits > wave.bits_per_sample { return Err(FormatError::InvalidValidBits); }
    if channel_mask != 0 && channel_mask.count_ones() != u32::from(wave.channels) { return Err(FormatError::InvalidChannelMask); }
    let format = if subtype == SUBFORMAT_IEEE_FLOAT {
        if wave.bits_per_sample != 32 { return Err(FormatError::UnsupportedBits); }
        if valid_bits != wave.bits_per_sample { return Err(FormatError::UnsupportedBits); }
        NativeSampleFormat::F32Le
    } else if subtype == SUBFORMAT_PCM { match wave.bits_per_sample {
        8 => NativeSampleFormat::U8,
        16 => NativeSampleFormat::S16Le,
        24 => NativeSampleFormat::S24Le,
        32 => NativeSampleFormat::S32Le,
        _ => return Err(FormatError::UnsupportedBits),
    } } else { return Err(FormatError::UnsupportedSubtype); };
    let frame_bytes = format.bytes().checked_mul(u32::from(wave.channels)).ok_or(FormatError::InvalidBlockAlign)?;
    if u32::from(wave.block_align) != frame_bytes { return Err(FormatError::InvalidBlockAlign); }
    let byte_rate = wave.samples_per_sec.checked_mul(frame_bytes).ok_or(FormatError::InvalidByteRate)?;
    if wave.avg_bytes_per_sec != byte_rate { return Err(FormatError::InvalidByteRate); }
    Ok(NativePcmFormat { format, channels: wave.channels, rate: wave.samples_per_sec, frame_bytes, byte_rate, valid_bits_per_sample: valid_bits, channel_mask })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pcm(bits: u16, channels: u16, rate: u32) -> WaveFormatEx {
        let bytes = u32::from(bits / 8) * u32::from(channels);
        WaveFormatEx { format_tag: WAVE_FORMAT_PCM, channels, samples_per_sec: rate,
            avg_bytes_per_sec: rate * bytes, block_align: bytes as u16,
            bits_per_sample: bits, cb_size: 0 }
    }

    #[test]
    fn normalizes_wine_style_pcm_formats() {
        let value = normalize_pcm(&pcm(16, 2, 44_100)).unwrap();
        assert_eq!(value, NativePcmFormat { format: NativeSampleFormat::S16Le,
            channels: 2, rate: 44_100, frame_bytes: 4, byte_rate: 176_400,
            valid_bits_per_sample: 16, channel_mask: 3 });
        assert_eq!(normalize_pcm(&pcm(8, 1, 8_000)).unwrap().format, NativeSampleFormat::U8);
        assert_eq!(normalize_pcm(&pcm(32, 2, 192_000)).unwrap().format, NativeSampleFormat::S32Le);
        let float = WaveFormatEx { format_tag: WAVE_FORMAT_IEEE_FLOAT, bits_per_sample: 32, ..pcm(32, 2, 48_000) };
        assert_eq!(normalize_pcm(&float).unwrap().format, NativeSampleFormat::F32Le);
    }

    #[test]
    fn rejects_non_pcm_and_nonzero_extensions() {
        let mut value = pcm(16, 2, 48_000);
        value.format_tag = WAVE_FORMAT_IEEE_FLOAT;
        value.bits_per_sample = 16;
        assert_eq!(normalize_pcm(&value), Err(FormatError::UnsupportedBits));
        value.format_tag = WAVE_FORMAT_PCM;
        value.cb_size = 22;
        assert_eq!(normalize_pcm(&value), Err(FormatError::UnsupportedExtension));
    }

    #[test]
    fn rejects_inconsistent_and_unsafe_descriptors() {
        let mut value = pcm(16, 2, 44_100);
        value.block_align = 2;
        assert_eq!(normalize_pcm(&value), Err(FormatError::InvalidBlockAlign));
        value = pcm(16, 2, 44_100);
        value.avg_bytes_per_sec -= 1;
        assert_eq!(normalize_pcm(&value), Err(FormatError::InvalidByteRate));
        assert_eq!(normalize_pcm(&pcm(24, 2, 44_100)).unwrap().format, NativeSampleFormat::S24Le);
        assert_eq!(normalize_pcm(&pcm(16, 0, 44_100)), Err(FormatError::InvalidChannels));
    }

    fn extensible(bits: u16, channels: u16, rate: u32, subtype: [u8; 16]) -> WaveFormatExtensible {
        let bytes = u32::from(bits / 8) * u32::from(channels);
        WaveFormatExtensible { format: WaveFormatEx { format_tag: WAVE_FORMAT_EXTENSIBLE,
            channels, samples_per_sec: rate, avg_bytes_per_sec: rate * bytes,
            block_align: bytes as u16, bits_per_sample: bits, cb_size: EXTENSIBLE_CB_SIZE },
            valid_bits_per_sample: bits, channel_mask: channel_mask_for(channels), sub_format: subtype }
    }

    #[test]
    fn accepts_wasapi_extensible_pcm_and_float() {
        let pcm = normalize_extensible(&extensible(16, 2, 48_000, SUBFORMAT_PCM)).unwrap();
        assert_eq!(pcm.format, NativeSampleFormat::S16Le);
        assert_eq!(pcm.valid_bits_per_sample, 16);
        assert_eq!(pcm.channel_mask, 3);
        let float = normalize_extensible(&extensible(32, 2, 48_000, SUBFORMAT_IEEE_FLOAT)).unwrap();
        assert_eq!(float.format, NativeSampleFormat::F32Le);
    }

    #[test]
    fn rejects_malformed_extensible_contracts() {
        let mut value = extensible(32, 2, 48_000, SUBFORMAT_PCM);
        value.valid_bits_per_sample = 33;
        assert_eq!(normalize_extensible(&value), Err(FormatError::InvalidValidBits));
        value = extensible(16, 2, 48_000, SUBFORMAT_PCM);
        value.channel_mask = 1;
        assert_eq!(normalize_extensible(&value), Err(FormatError::InvalidChannelMask));
        value = extensible(16, 2, 48_000, [0; 16]);
        assert_eq!(normalize_extensible(&value), Err(FormatError::UnsupportedSubtype));
        value = extensible(16, 2, 48_000, SUBFORMAT_PCM);
        value.format.cb_size = EXTENSIBLE_CB_SIZE - 1;
        assert_eq!(normalize_extensible(&value), Err(FormatError::UnsupportedExtension));
    }

    #[test]
    fn extensible_abi_is_pointer_free_and_fixed_size() {
        assert_eq!(core::mem::size_of::<WaveFormatEx>(), 20);
        assert_eq!(core::mem::size_of::<WaveFormatExtensible>(), 44);
        assert_eq!(core::mem::offset_of!(WaveFormatExtensible, valid_bits_per_sample), 20);
        assert_eq!(core::mem::offset_of!(WaveFormatExtensible, channel_mask), 24);
        assert_eq!(core::mem::offset_of!(WaveFormatExtensible, sub_format), 28);
    }
}
