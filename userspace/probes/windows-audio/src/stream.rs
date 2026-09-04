use crate::NativePcmFormat;

/// Windows reference-time units used by WASAPI buffer durations.
pub const HNS_PER_SEC: u64 = 10_000_000;
const MAX_BUFFER_FRAMES: u64 = 1_048_576;

/// Direction changes which side owns the next movement of the bounded queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AudioDirection { Render, Capture }

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamError {
    ZeroDuration,
    ZeroFrames,
    PeriodExceedsBuffer,
    BufferTooLarge,
    InvalidFrameCount,
    WouldBlock,
}

/// Actual frame geometry returned after a duration-based stream request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamGeometry {
    pub buffer_frames: u32,
    pub period_frames: u32,
    pub buffer_bytes: u32,
    pub period_bytes: u32,
}

impl StreamGeometry {
    /// Convert WASAPI 100-nanosecond durations into bounded native PCM geometry.
    /// # C: O(1)
    pub fn from_durations(format: NativePcmFormat, buffer_hns: u64, period_hns: u64)
        -> Result<Self, StreamError> {
        if buffer_hns == 0 || period_hns == 0 { return Err(StreamError::ZeroDuration); }
        let buffer_frames = frames_for_duration(format.rate, buffer_hns)?;
        let period_frames = frames_for_duration(format.rate, period_hns)?;
        Self::from_frames(format, buffer_frames, period_frames)
    }

    /// Validate geometry supplied by a native PCM backend.
    /// # C: O(1)
    pub fn from_frames(format: NativePcmFormat, buffer_frames: u64, period_frames: u64)
        -> Result<Self, StreamError> {
        if buffer_frames == 0 || period_frames == 0 { return Err(StreamError::ZeroFrames); }
        if buffer_frames > MAX_BUFFER_FRAMES { return Err(StreamError::BufferTooLarge); }
        if period_frames > buffer_frames { return Err(StreamError::PeriodExceedsBuffer); }
        let buffer_bytes = buffer_frames.checked_mul(u64::from(format.frame_bytes))
            .ok_or(StreamError::InvalidFrameCount)?;
        let period_bytes = period_frames.checked_mul(u64::from(format.frame_bytes))
            .ok_or(StreamError::InvalidFrameCount)?;
        if buffer_bytes > u64::from(u32::MAX) || period_bytes > u64::from(u32::MAX) {
            return Err(StreamError::InvalidFrameCount);
        }
        Ok(Self { buffer_frames: buffer_frames as u32, period_frames: period_frames as u32,
            buffer_bytes: buffer_bytes as u32, period_bytes: period_bytes as u32 })
    }

    /// Report the requested duration represented by the actual allocated frames.
    /// # C: O(1)
    pub fn duration_hns(self, rate: u32) -> Result<u64, StreamError> {
        duration_for_frames(rate, u64::from(self.buffer_frames))
    }
}

/// Bounded endpoint queue matching WASAPI padding/available-frame semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AudioStream {
    geometry: StreamGeometry,
    direction: AudioDirection,
    queued_frames: u32,
}

impl AudioStream {
    /// Create an empty render or capture endpoint queue.
    /// # C: O(1)
    pub const fn new(geometry: StreamGeometry, direction: AudioDirection) -> Self {
        Self { geometry, direction, queued_frames: 0 }
    }

    pub const fn geometry(self) -> StreamGeometry { self.geometry }
    pub const fn direction(self) -> AudioDirection { self.direction }

    /// Frames currently padded in the endpoint buffer.
    /// # C: O(1)
    pub const fn current_padding(self) -> u32 { self.queued_frames }

    /// Frames that can be submitted without overwriting queued audio.
    /// # C: O(1)
    pub const fn available_frames(self) -> u32 { self.geometry.buffer_frames - self.queued_frames }

    /// Queue render frames or make capture frames available to the client.
    /// # C: O(1)
    pub fn client_write(&mut self, frames: u32) -> Result<(), StreamError> {
        if frames > self.available_frames() { return Err(StreamError::WouldBlock); }
        self.queued_frames += frames;
        Ok(())
    }

    /// Consume render frames or remove capture frames from the client queue.
    /// # C: O(1)
    pub fn client_read(&mut self, frames: u32) -> Result<(), StreamError> {
        if frames > self.queued_frames { return Err(StreamError::WouldBlock); }
        self.queued_frames -= frames;
        Ok(())
    }

    /// Advance the native device clock, preserving the bounded queue invariant.
    /// # C: O(1)
    pub fn device_advance(&mut self, frames: u32) -> Result<(), StreamError> {
        match self.direction {
            AudioDirection::Render => self.client_read(frames),
            AudioDirection::Capture => self.client_write(frames),
        }
    }
}

fn frames_for_duration(rate: u32, duration_hns: u64) -> Result<u64, StreamError> {
    let scaled = duration_hns.checked_mul(u64::from(rate)).ok_or(StreamError::BufferTooLarge)?;
    let frames = scaled.checked_add(HNS_PER_SEC - 1).ok_or(StreamError::BufferTooLarge)? / HNS_PER_SEC;
    if frames == 0 { return Err(StreamError::ZeroFrames); }
    Ok(frames)
}

fn duration_for_frames(rate: u32, frames: u64) -> Result<u64, StreamError> {
    if rate == 0 || frames == 0 { return Err(StreamError::InvalidFrameCount); }
    frames.checked_mul(HNS_PER_SEC).and_then(|n| n.checked_add(u64::from(rate) - 1))
        .map(|n| n / u64::from(rate)).ok_or(StreamError::InvalidFrameCount)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{NativeSampleFormat, NativePcmFormat};

    fn format() -> NativePcmFormat {
        NativePcmFormat { format: NativeSampleFormat::S16Le, channels: 2, rate: 48_000,
            frame_bytes: 4, byte_rate: 192_000, valid_bits_per_sample: 16, channel_mask: 3 }
    }

    #[test]
    fn duration_request_rounds_up_to_actual_frames() {
        let g = StreamGeometry::from_durations(format(), 10_000_000, 1_000_000).unwrap();
        assert_eq!(g.buffer_frames, 48_000);
        assert_eq!(g.period_frames, 4_800);
        assert_eq!(g.buffer_bytes, 192_000);
        assert_eq!(g.duration_hns(format().rate).unwrap(), 10_000_000);
    }

    #[test]
    fn rejects_unbounded_or_invalid_geometry() {
        assert_eq!(StreamGeometry::from_durations(format(), 0, 1), Err(StreamError::ZeroDuration));
        assert_eq!(StreamGeometry::from_frames(format(), 8, 9), Err(StreamError::PeriodExceedsBuffer));
        assert_eq!(StreamGeometry::from_frames(format(), 1_048_577, 1), Err(StreamError::BufferTooLarge));
    }

    #[test]
    fn render_and_capture_never_cross_the_buffer_boundary() {
        let geometry = StreamGeometry::from_frames(format(), 8, 4).unwrap();
        let mut render = AudioStream::new(geometry, AudioDirection::Render);
        assert!(render.client_write(8).is_ok());
        assert_eq!(render.current_padding(), 8);
        assert_eq!(render.client_write(1), Err(StreamError::WouldBlock));
        assert!(render.device_advance(4).is_ok());
        assert_eq!(render.available_frames(), 4);

        let mut capture = AudioStream::new(geometry, AudioDirection::Capture);
        assert!(capture.device_advance(8).is_ok());
        assert_eq!(capture.device_advance(1), Err(StreamError::WouldBlock));
        assert!(capture.client_read(4).is_ok());
        assert_eq!(capture.current_padding(), 4);
    }
}
