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

pub const WAVE_FORMAT_PCM: u16 = 1;
pub const WAVE_FORMAT_IEEE_FLOAT: u16 = 3;
pub const MAX_CHANNELS: u16 = 8;
pub const MIN_RATE: u32 = 8_000;
pub const MAX_RATE: u32 = 192_000;

/// Native format accepted by the current kernel PCM core.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeSampleFormat { U8, S16Le, S32Le }

impl NativeSampleFormat {
    pub const fn bytes(self) -> u32 {
        match self { Self::U8 => 1, Self::S16Le => 2, Self::S32Le => 4 }
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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError {
    UnsupportedTag,
    InvalidChannels,
    InvalidRate,
    UnsupportedBits,
    InvalidBlockAlign,
    InvalidByteRate,
    UnsupportedExtension,
}

/// Validate a Windows PCM format and normalize it for the native sound core.
/// # C: O(1)
pub fn normalize_pcm(wave: &WaveFormatEx) -> Result<NativePcmFormat, FormatError> {
    if wave.format_tag != WAVE_FORMAT_PCM { return Err(FormatError::UnsupportedTag); }
    if wave.cb_size != 0 { return Err(FormatError::UnsupportedExtension); }
    if wave.channels == 0 || wave.channels > MAX_CHANNELS { return Err(FormatError::InvalidChannels); }
    if !(MIN_RATE..=MAX_RATE).contains(&wave.samples_per_sec) { return Err(FormatError::InvalidRate); }
    let format = match wave.bits_per_sample {
        8 => NativeSampleFormat::U8,
        16 => NativeSampleFormat::S16Le,
        32 => NativeSampleFormat::S32Le,
        _ => return Err(FormatError::UnsupportedBits),
    };
    let frame_bytes = format.bytes().checked_mul(u32::from(wave.channels)).ok_or(FormatError::InvalidBlockAlign)?;
    if u32::from(wave.block_align) != frame_bytes { return Err(FormatError::InvalidBlockAlign); }
    let byte_rate = wave.samples_per_sec.checked_mul(frame_bytes).ok_or(FormatError::InvalidByteRate)?;
    if wave.avg_bytes_per_sec != byte_rate { return Err(FormatError::InvalidByteRate); }
    Ok(NativePcmFormat { format, channels: wave.channels, rate: wave.samples_per_sec, frame_bytes, byte_rate })
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
            channels: 2, rate: 44_100, frame_bytes: 4, byte_rate: 176_400 });
        assert_eq!(normalize_pcm(&pcm(8, 1, 8_000)).unwrap().format, NativeSampleFormat::U8);
        assert_eq!(normalize_pcm(&pcm(32, 2, 192_000)).unwrap().format, NativeSampleFormat::S32Le);
    }

    #[test]
    fn rejects_non_pcm_and_nonzero_extensions() {
        let mut value = pcm(16, 2, 48_000);
        value.format_tag = WAVE_FORMAT_IEEE_FLOAT;
        assert_eq!(normalize_pcm(&value), Err(FormatError::UnsupportedTag));
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
        assert_eq!(normalize_pcm(&pcm(24, 2, 44_100)), Err(FormatError::UnsupportedBits));
        assert_eq!(normalize_pcm(&pcm(16, 0, 44_100)), Err(FormatError::InvalidChannels));
    }
}
