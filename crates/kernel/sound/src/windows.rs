//! Bounded Windows endpoint contract owned by the native sound core.

use crate::format;

pub const HNS_PER_SEC: u64 = 10_000_000;
pub const MAX_BUFFER_FRAMES: u64 = 1_048_576;
pub const MAX_CHANNELS: u32 = 64;
pub const MIN_RATE_HZ: u32 = 1_000;
pub const MAX_RATE_HZ: u32 = 200_000;
pub const WAVE_FORMAT_EXTENSIBLE: u16 = 0xfffe;
pub const WAVE_FORMAT_EXTENSIBLE_SIZE: u16 = 22;
pub const SPEAKER_RESERVED: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcmFormat { alsa_format: u32, channels: u32, rate_hz: u32, frame_bytes: u32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError { UnsupportedFormat, InvalidChannels, InvalidRate, InvalidFrameBytes, InvalidWaveFormat }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WaveSubFormat { Pcm, IeeeFloat }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WaveFormatExtensible {
    pub format_tag: u16,
    pub channels: u16,
    pub rate_hz: u32,
    pub avg_bytes_per_sec: u32,
    pub block_align: u16,
    pub bits_per_sample: u16,
    pub cb_size: u16,
    pub valid_bits_per_sample: u16,
    pub channel_mask: u32,
    pub sub_format: WaveSubFormat,
}

impl WaveFormatExtensible {
    /// Validate the Windows extensible descriptor before native negotiation.
    /// # C: O(1)
    pub fn validate(self) -> Result<(), FormatError> {
        if self.format_tag != WAVE_FORMAT_EXTENSIBLE || self.cb_size < WAVE_FORMAT_EXTENSIBLE_SIZE { return Err(FormatError::InvalidWaveFormat); }
        let channels = u32::from(self.channels);
        let bits = u32::from(self.bits_per_sample);
        if channels == 0 || channels > MAX_CHANNELS { return Err(FormatError::InvalidChannels); }
        if !(MIN_RATE_HZ..=MAX_RATE_HZ).contains(&self.rate_hz) { return Err(FormatError::InvalidRate); }
        if bits == 0 || bits % 8 != 0 || u32::from(self.block_align) != channels * bits / 8 || self.avg_bytes_per_sec != u32::from(self.block_align) * self.rate_hz { return Err(FormatError::InvalidWaveFormat); }
        let valid = u32::from(self.valid_bits_per_sample);
        if valid == 0 || valid > bits { return Err(FormatError::InvalidWaveFormat); }
        if self.channel_mask & SPEAKER_RESERVED != 0 || (self.channel_mask != 0 && self.channel_mask.count_ones() != channels) { return Err(FormatError::InvalidWaveFormat); }
        match self.sub_format {
            WaveSubFormat::Pcm if matches!(bits, 8 | 16 | 24 | 32) && (valid == bits || (bits == 32 && valid == 24)) => Ok(()),
            WaveSubFormat::IeeeFloat if bits == 32 && valid == bits => Ok(()),
            _ => Err(FormatError::UnsupportedFormat),
        }
    }

    /// Convert an accepted PCM descriptor into the existing native format.
    /// # C: O(1)
    pub fn to_pcm_format(self) -> Result<PcmFormat, FormatError> {
        self.validate()?;
        let alsa = match (self.sub_format, self.bits_per_sample) {
            (WaveSubFormat::Pcm, 8) => crate::uapi::FMT_U8,
            (WaveSubFormat::Pcm, 16) => crate::uapi::FMT_S16_LE,
            (WaveSubFormat::Pcm, 24) => crate::uapi::FMT_S24_LE,
            (WaveSubFormat::Pcm, 32) => crate::uapi::FMT_S32_LE,
            _ => return Err(FormatError::UnsupportedFormat),
        };
        let format = PcmFormat::from_alsa(alsa, u32::from(self.channels), self.rate_hz)?;
        if format.frame_bytes() != u32::from(self.block_align) { return Err(FormatError::InvalidWaveFormat); }
        Ok(format)
    }
}

impl PcmFormat {
    /// Build adapter geometry from an already-negotiated native format.
    /// # C: O(1)
    pub fn from_alsa(alsa_format: u32, channels: u32, rate_hz: u32) -> Result<Self, FormatError> {
        if !matches!(alsa_format, crate::uapi::FMT_U8 | crate::uapi::FMT_S16_LE |
                     crate::uapi::FMT_S24_LE | crate::uapi::FMT_S32_LE) { return Err(FormatError::UnsupportedFormat); }
        if channels == 0 || channels > MAX_CHANNELS { return Err(FormatError::InvalidChannels); }
        if !(MIN_RATE_HZ..=MAX_RATE_HZ).contains(&rate_hz) { return Err(FormatError::InvalidRate); }
        let frame_bytes = format::frame_bytes(alsa_format, channels);
        Ok(Self { alsa_format, channels, rate_hz, frame_bytes })
    }

    /// Validate the complete negotiated tuple, including its derived storage width.
    /// # C: O(1)
    pub fn validate(self) -> Result<(), FormatError> {
        if self.frame_bytes != format::frame_bytes(self.alsa_format, self.channels) {
            return Err(FormatError::InvalidFrameBytes);
        }
        Ok(())
    }
    /// ALSA sample format selected by negotiation. # C: O(1)
    pub const fn alsa_format(self) -> u32 { self.alsa_format }
    /// Channel count selected by negotiation. # C: O(1)
    pub const fn channels(self) -> u32 { self.channels }
    /// Sample rate selected by negotiation. # C: O(1)
    pub const fn rate_hz(self) -> u32 { self.rate_hz }
    /// Bytes in one interleaved frame. # C: O(1)
    pub const fn frame_bytes(self) -> u32 { self.frame_bytes }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioDirection { Render, Capture }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError { ZeroDuration, ZeroFrames, PeriodExceedsBuffer, BufferTooLarge, InvalidFrameCount, InvalidFormat, WouldBlock, BufferOperationPending, OutOfOrder, InvalidBufferSize, WrongDirection, AlreadyStarted, NotStopped, Invalidated, Closed }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamState { Initialized, Running, Stopped, Invalidated, Closed }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamGeometry { pub buffer_frames: u32, pub period_frames: u32, pub buffer_bytes: u32, pub period_bytes: u32 }

impl StreamGeometry {
    /// Convert WASAPI 100-ns duration requests into bounded PCM geometry.
    /// # C: O(1)
    pub fn from_durations(format: PcmFormat, buffer_hns: u64, period_hns: u64) -> Result<Self, StreamError> {
        if buffer_hns == 0 || period_hns == 0 { return Err(StreamError::ZeroDuration); }
        Self::from_frames(format, frames_for_duration(format.rate_hz, buffer_hns)?, frames_for_duration(format.rate_hz, period_hns)?)
    }

    /// Validate geometry allocated by the native PCM backend.
    /// # C: O(1)
    pub fn from_frames(format: PcmFormat, buffer_frames: u64, period_frames: u64) -> Result<Self, StreamError> {
        if format.validate().is_err() { return Err(StreamError::InvalidFormat); }
        if buffer_frames == 0 || period_frames == 0 { return Err(StreamError::ZeroFrames); }
        if buffer_frames > MAX_BUFFER_FRAMES { return Err(StreamError::BufferTooLarge); }
        if period_frames > buffer_frames { return Err(StreamError::PeriodExceedsBuffer); }
        let buffer_bytes = buffer_frames.checked_mul(u64::from(format.frame_bytes)).ok_or(StreamError::InvalidFrameCount)?;
        let period_bytes = period_frames.checked_mul(u64::from(format.frame_bytes)).ok_or(StreamError::InvalidFrameCount)?;
        if buffer_bytes > u64::from(u32::MAX) || period_bytes > u64::from(u32::MAX) { return Err(StreamError::InvalidFrameCount); }
        Ok(Self { buffer_frames: buffer_frames as u32, period_frames: period_frames as u32, buffer_bytes: buffer_bytes as u32, period_bytes: period_bytes as u32 })
    }

    /// Return the duration represented by the allocated buffer.
    /// # C: O(1)
    pub fn duration_hns(self, rate_hz: u32) -> Result<u64, StreamError> {
        if rate_hz == 0 { return Err(StreamError::InvalidFrameCount); }
        u64::from(self.buffer_frames).checked_mul(HNS_PER_SEC).and_then(|n| n.checked_add(u64::from(rate_hz) - 1))
            .map(|n| n / u64::from(rate_hz)).ok_or(StreamError::InvalidFrameCount)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AudioStream { format: Option<PcmFormat>, geometry: StreamGeometry, direction: AudioDirection, state: StreamState, queued_frames: u32, render_loan: Option<u32> }

impl AudioStream {
    /// Create an endpoint queue starting with no padded frames.
    /// # C: O(1)
    pub const fn new(geometry: StreamGeometry, direction: AudioDirection) -> Self {
        Self { format: None, geometry, direction, state: StreamState::Initialized, queued_frames: 0, render_loan: None }
    }
    /// Create a stream while retaining the negotiated format for endpoint queries.
    /// # C: O(1)
    pub const fn with_format(format: PcmFormat, geometry: StreamGeometry, direction: AudioDirection) -> Self {
        Self { format: Some(format), geometry, direction, state: StreamState::Initialized, queued_frames: 0, render_loan: None }
    }
    /// Return the immutable format committed at stream creation. # C: O(1)
    pub const fn format(self) -> Option<PcmFormat> { self.format }
    /// Return the negotiated ALSA format. # C: O(1)
    pub const fn negotiated_format(self) -> Option<u32> { match self.format { Some(format) => Some(format.alsa_format), None => None } }
    pub const fn state(self) -> StreamState { self.state }
    pub const fn current_padding(self) -> u32 { self.queued_frames }
    pub const fn available_frames(self) -> u32 { self.geometry.buffer_frames - self.queued_frames }

    /// Transition an initialized or stopped endpoint into active playback/capture.
    /// # C: O(1)
    pub fn start(&mut self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Invalidated => Err(StreamError::Invalidated),
            StreamState::Closed => Err(StreamError::Closed),
            StreamState::Running => Err(StreamError::AlreadyStarted),
            StreamState::Initialized | StreamState::Stopped => { self.state = StreamState::Running; Ok(()) }
        }
    }

    /// Stop an endpoint; stopping an already stopped endpoint is idempotent.
    /// # C: O(1)
    pub fn stop(&mut self) -> Result<(), StreamError> {
        if self.state == StreamState::Invalidated { return Err(StreamError::Invalidated); }
        if self.state == StreamState::Closed { return Err(StreamError::Closed); }
        self.state = StreamState::Stopped;
        self.render_loan = None;
        Ok(())
    }

    /// Reset a stopped endpoint's client-visible padding and pointers.
    /// # C: O(1)
    pub fn reset(&mut self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Invalidated => Err(StreamError::Invalidated),
            StreamState::Closed => Err(StreamError::Closed),
            StreamState::Running => Err(StreamError::NotStopped),
            StreamState::Initialized | StreamState::Stopped => {
                self.queued_frames = 0;
                self.render_loan = None;
                Ok(())
            }
        }
    }

    /// Permanently invalidate an endpoint after native device removal.
    /// # C: O(1)
    pub fn invalidate(&mut self) {
        if self.state == StreamState::Closed { return; }
        self.state = StreamState::Invalidated;
        self.queued_frames = 0;
        self.render_loan = None;
    }

    /// Release the endpoint; close is terminal and rejects all later operations.
    /// # C: O(1)
    pub fn close(&mut self) {
        self.state = StreamState::Closed;
        self.queued_frames = 0;
        self.render_loan = None;
    }

    /// Submit render frames or make capture frames available to the client.
    /// # C: O(1)
    pub fn client_write(&mut self, frames: u32) -> Result<(), StreamError> {
        if self.state == StreamState::Invalidated { return Err(StreamError::Invalidated); }
        if self.state == StreamState::Closed { return Err(StreamError::Closed); }
        if self.render_loan.is_some() { return Err(StreamError::BufferOperationPending); }
        if frames > self.available_frames() { return Err(StreamError::WouldBlock); }
        self.queued_frames += frames; Ok(())
    }

    /// Consume render frames or read capture frames from the client queue.
    /// # C: O(1)
    pub fn client_read(&mut self, frames: u32) -> Result<(), StreamError> {
        if self.state == StreamState::Invalidated { return Err(StreamError::Invalidated); }
        if self.state == StreamState::Closed { return Err(StreamError::Closed); }
        if self.render_loan.is_some() { return Err(StreamError::BufferOperationPending); }
        if frames > self.queued_frames { return Err(StreamError::WouldBlock); }
        self.queued_frames -= frames; Ok(())
    }

    /// Reserve one render buffer; its frames do not affect padding until release.
    /// # C: O(1)
    pub fn render_get_buffer(&mut self, frames: u32) -> Result<(), StreamError> {
        if self.state == StreamState::Invalidated { return Err(StreamError::Invalidated); }
        if self.state == StreamState::Closed { return Err(StreamError::Closed); }
        if self.direction != AudioDirection::Render { return Err(StreamError::WrongDirection); }
        if self.render_loan.is_some() { return Err(StreamError::OutOfOrder); }
        if frames > self.available_frames() { return Err(StreamError::BufferTooLarge); }
        self.render_loan = Some(frames);
        Ok(())
    }

    /// Commit the valid portion of the outstanding render buffer reservation.
    /// # C: O(1)
    pub fn render_release_buffer(&mut self, written_frames: u32) -> Result<(), StreamError> {
        if self.state == StreamState::Invalidated { return Err(StreamError::Invalidated); }
        if self.state == StreamState::Closed { return Err(StreamError::Closed); }
        let Some(reserved) = self.render_loan else { return Err(StreamError::OutOfOrder); };
        if written_frames > reserved { return Err(StreamError::InvalidBufferSize); }
        self.render_loan = None;
        self.queued_frames += written_frames;
        Ok(())
    }

    /// Advance the device while preserving the endpoint padding bound.
    /// # C: O(1)
    pub fn device_advance(&mut self, frames: u32) -> Result<(), StreamError> {
        match self.direction { AudioDirection::Render => self.client_read(frames), AudioDirection::Capture => self.client_write(frames) }
    }
}

fn frames_for_duration(rate_hz: u32, duration_hns: u64) -> Result<u64, StreamError> {
    if rate_hz == 0 { return Err(StreamError::InvalidFrameCount); }
    duration_hns.checked_mul(u64::from(rate_hz)).and_then(|n| n.checked_add(HNS_PER_SEC - 1)).map(|n| n / HNS_PER_SEC)
        .filter(|frames| *frames != 0).ok_or(StreamError::ZeroFrames)
}

#[cfg(test)]
#[path = "tests/windows.rs"]
mod tests;
