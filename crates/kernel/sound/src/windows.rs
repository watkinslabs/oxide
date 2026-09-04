//! Bounded Windows endpoint contract owned by the native sound core.

use crate::format;

pub const HNS_PER_SEC: u64 = 10_000_000;
pub const MAX_BUFFER_FRAMES: u64 = 1_048_576;
pub const MAX_CHANNELS: u32 = 64;
pub const MIN_RATE_HZ: u32 = 1_000;
pub const MAX_RATE_HZ: u32 = 200_000;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PcmFormat { pub alsa_format: u32, pub channels: u32, pub rate_hz: u32, pub frame_bytes: u32 }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatError { UnsupportedFormat, InvalidChannels, InvalidRate }

impl PcmFormat {
    /// Build adapter geometry from an already-negotiated native format.
    /// # C: O(1)
    pub fn from_alsa(alsa_format: u32, channels: u32, rate_hz: u32) -> Result<Self, FormatError> {
        if !matches!(alsa_format, crate::uapi::FMT_U8 | crate::uapi::FMT_S16_LE |
                     crate::uapi::FMT_S24_LE | crate::uapi::FMT_S32_LE) { return Err(FormatError::UnsupportedFormat); }
        if channels == 0 || channels > MAX_CHANNELS { return Err(FormatError::InvalidChannels); }
        if !(MIN_RATE_HZ..=MAX_RATE_HZ).contains(&rate_hz) { return Err(FormatError::InvalidRate); }
        Ok(Self { alsa_format, channels, rate_hz, frame_bytes: format::frame_bytes(alsa_format, channels) })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioDirection { Render, Capture }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError { ZeroDuration, ZeroFrames, PeriodExceedsBuffer, BufferTooLarge, InvalidFrameCount, WouldBlock }

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
pub struct AudioStream { geometry: StreamGeometry, direction: AudioDirection, queued_frames: u32 }

impl AudioStream {
    /// Create an endpoint queue starting with no padded frames.
    /// # C: O(1)
    pub const fn new(geometry: StreamGeometry, direction: AudioDirection) -> Self { Self { geometry, direction, queued_frames: 0 } }
    pub const fn current_padding(self) -> u32 { self.queued_frames }
    pub const fn available_frames(self) -> u32 { self.geometry.buffer_frames - self.queued_frames }

    /// Submit render frames or make capture frames available to the client.
    /// # C: O(1)
    pub fn client_write(&mut self, frames: u32) -> Result<(), StreamError> {
        if frames > self.available_frames() { return Err(StreamError::WouldBlock); }
        self.queued_frames += frames; Ok(())
    }

    /// Consume render frames or read capture frames from the client queue.
    /// # C: O(1)
    pub fn client_read(&mut self, frames: u32) -> Result<(), StreamError> {
        if frames > self.queued_frames { return Err(StreamError::WouldBlock); }
        self.queued_frames -= frames; Ok(())
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
