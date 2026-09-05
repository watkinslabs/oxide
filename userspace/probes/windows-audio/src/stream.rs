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
    BufferOperationPending,
    OutOfOrder,
    InvalidBufferSize,
    WrongDirection,
    NotRunning,
    AlreadyStarted,
    NotStopped,
    Invalidated,
    Closed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StreamState { Initialized, Running, Stopped, Invalidated, Closed }

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
    format: Option<NativePcmFormat>,
    geometry: StreamGeometry,
    direction: AudioDirection,
    queued_frames: u32,
    state: StreamState,
    render_loan: Option<u32>,
}

impl AudioStream {
    /// Create an empty render or capture endpoint queue.
    /// # C: O(1)
    pub const fn new(geometry: StreamGeometry, direction: AudioDirection) -> Self {
        Self { format: None, geometry, direction, queued_frames: 0, state: StreamState::Initialized, render_loan: None }
    }

    /// Create an endpoint while retaining its negotiated native format.
    /// # C: O(1)
    pub const fn with_format(format: NativePcmFormat, geometry: StreamGeometry, direction: AudioDirection) -> Self {
        Self { format: Some(format), geometry, direction, queued_frames: 0, state: StreamState::Initialized, render_loan: None }
    }

    pub const fn geometry(self) -> StreamGeometry { self.geometry }
    pub const fn direction(self) -> AudioDirection { self.direction }
    pub const fn format(self) -> Option<NativePcmFormat> { self.format }
    pub const fn state(self) -> StreamState { self.state }

    /// Frames currently padded in the endpoint buffer.
    /// # C: O(1)
    pub const fn current_padding(self) -> u32 { self.queued_frames }

    /// Frames that can be submitted without overwriting queued audio.
    /// # C: O(1)
    pub const fn available_frames(self) -> u32 { self.geometry.buffer_frames - self.queued_frames }

    /// Queue render frames or make capture frames available to the client.
    /// # C: O(1)
    pub fn client_write(&mut self, frames: u32) -> Result<(), StreamError> {
        self.ensure_open()?;
        if self.render_loan.is_some() { return Err(StreamError::BufferOperationPending); }
        if frames > self.available_frames() { return Err(StreamError::WouldBlock); }
        self.queued_frames += frames;
        Ok(())
    }

    /// Consume render frames or remove capture frames from the client queue.
    /// # C: O(1)
    pub fn client_read(&mut self, frames: u32) -> Result<(), StreamError> {
        self.ensure_open()?;
        if self.render_loan.is_some() { return Err(StreamError::BufferOperationPending); }
        if frames > self.queued_frames { return Err(StreamError::WouldBlock); }
        self.queued_frames -= frames;
        Ok(())
    }

    /// Advance the native device clock, preserving the bounded queue invariant.
    /// # C: O(1)
    pub fn device_advance(&mut self, frames: u32) -> Result<(), StreamError> {
        if self.state != StreamState::Running { return Err(StreamError::NotRunning); }
        match self.direction {
            AudioDirection::Render => self.client_read(frames),
            AudioDirection::Capture => self.client_write(frames),
        }
    }

    /// Start the endpoint; a running endpoint cannot be started twice.
    /// # C: O(1)
    pub fn start(&mut self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Invalidated => Err(StreamError::Invalidated),
            StreamState::Closed => Err(StreamError::Closed),
            StreamState::Running => Err(StreamError::AlreadyStarted),
            StreamState::Initialized | StreamState::Stopped => { self.state = StreamState::Running; Ok(()) }
        }
    }

    /// Stop the endpoint and cancel an outstanding render reservation.
    /// # C: O(1)
    pub fn stop(&mut self) -> Result<(), StreamError> {
        self.ensure_open()?;
        self.state = StreamState::Stopped;
        self.render_loan = None;
        Ok(())
    }

    /// Reset a stopped endpoint and clear client-visible padding.
    /// # C: O(1)
    pub fn reset(&mut self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Invalidated => Err(StreamError::Invalidated),
            StreamState::Closed => Err(StreamError::Closed),
            StreamState::Running => Err(StreamError::NotStopped),
            StreamState::Initialized | StreamState::Stopped => { self.queued_frames = 0; self.render_loan = None; Ok(()) }
        }
    }

    /// Permanently reject operations after native endpoint removal.
    /// # C: O(1)
    pub fn invalidate(&mut self) {
        if self.state == StreamState::Closed { return; }
        self.state = StreamState::Invalidated;
        self.queued_frames = 0;
        self.render_loan = None;
    }

    /// Release the endpoint; no operation can revive a closed stream.
    /// # C: O(1)
    pub fn close(&mut self) {
        self.state = StreamState::Closed;
        self.queued_frames = 0;
        self.render_loan = None;
    }

    /// Reserve a render region before submitting its written portion.
    /// # C: O(1)
    pub fn render_get_buffer(&mut self, frames: u32) -> Result<(), StreamError> {
        self.ensure_open()?;
        if self.direction != AudioDirection::Render { return Err(StreamError::WrongDirection); }
        if self.render_loan.is_some() { return Err(StreamError::OutOfOrder); }
        if frames > self.available_frames() { return Err(StreamError::BufferTooLarge); }
        self.render_loan = Some(frames);
        Ok(())
    }

    /// Commit only the valid portion of the outstanding render region.
    /// # C: O(1)
    pub fn render_release_buffer(&mut self, written_frames: u32) -> Result<(), StreamError> {
        self.ensure_open()?;
        let Some(reserved) = self.render_loan else { return Err(StreamError::OutOfOrder); };
        if written_frames > reserved { return Err(StreamError::InvalidBufferSize); }
        self.render_loan = None;
        self.queued_frames += written_frames;
        Ok(())
    }

    fn ensure_open(&self) -> Result<(), StreamError> {
        match self.state {
            StreamState::Invalidated => Err(StreamError::Invalidated),
            StreamState::Closed => Err(StreamError::Closed),
            StreamState::Initialized | StreamState::Running | StreamState::Stopped => Ok(()),
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
        assert_eq!(render.device_advance(1), Err(StreamError::NotRunning));
        assert!(render.client_write(8).is_ok());
        assert_eq!(render.current_padding(), 8);
        assert_eq!(render.client_write(1), Err(StreamError::WouldBlock));
        render.start().unwrap();
        assert!(render.device_advance(4).is_ok());
        assert_eq!(render.available_frames(), 4);

        let mut capture = AudioStream::new(geometry, AudioDirection::Capture);
        assert_eq!(capture.device_advance(8), Err(StreamError::NotRunning));
        capture.start().unwrap();
        assert!(capture.device_advance(8).is_ok());
        assert_eq!(capture.device_advance(1), Err(StreamError::WouldBlock));
        assert!(capture.client_read(4).is_ok());
        assert_eq!(capture.current_padding(), 4);
    }

    #[test]
    fn stopping_corks_device_clock_without_dropping_render_padding() {
        let geometry = StreamGeometry::from_frames(format(), 8, 4).unwrap();
        let mut stream = AudioStream::new(geometry, AudioDirection::Render);
        stream.start().unwrap();
        stream.client_write(4).unwrap();
        stream.stop().unwrap();
        assert_eq!(stream.device_advance(2), Err(StreamError::NotRunning));
        assert_eq!(stream.current_padding(), 4);
        stream.start().unwrap();
        stream.device_advance(2).unwrap();
        assert_eq!(stream.current_padding(), 2);
    }

    #[test]
    fn render_buffer_loan_commits_only_after_valid_release() {
        let geometry = StreamGeometry::from_frames(format(), 8, 4).unwrap();
        let mut render = AudioStream::with_format(format(), geometry, AudioDirection::Render);
        assert_eq!(render.state(), StreamState::Initialized);
        assert!(render.render_get_buffer(4).is_ok());
        assert_eq!(render.render_get_buffer(1), Err(StreamError::OutOfOrder));
        assert_eq!(render.render_release_buffer(5), Err(StreamError::InvalidBufferSize));
        assert_eq!(render.current_padding(), 0);
        assert!(render.render_release_buffer(3).is_ok());
        assert_eq!(render.current_padding(), 3);
        assert_eq!(render.format(), Some(format()));
    }

    #[test]
    fn invalidation_and_close_are_terminal_for_stream_clients() {
        let geometry = StreamGeometry::from_frames(format(), 8, 4).unwrap();
        let mut invalidated = AudioStream::with_format(format(), geometry, AudioDirection::Capture);
        invalidated.invalidate();
        assert_eq!(invalidated.state(), StreamState::Invalidated);
        assert_eq!(invalidated.start(), Err(StreamError::Invalidated));
        assert_eq!(invalidated.client_write(1), Err(StreamError::Invalidated));
        assert_eq!(invalidated.client_read(1), Err(StreamError::Invalidated));

        let mut closed = AudioStream::with_format(format(), geometry, AudioDirection::Render);
        closed.start().unwrap();
        closed.render_get_buffer(2).unwrap();
        closed.close();
        assert_eq!(closed.state(), StreamState::Closed);
        assert_eq!(closed.current_padding(), 0);
        assert_eq!(closed.stop(), Err(StreamError::Closed));
        assert_eq!(closed.render_release_buffer(0), Err(StreamError::Closed));
        closed.invalidate();
        assert_eq!(closed.state(), StreamState::Closed);
    }

    #[test]
    fn stream_start_stop_reset_has_explicit_ordering() {
        let geometry = StreamGeometry::from_frames(format(), 8, 4).unwrap();
        let mut stream = AudioStream::with_format(format(), geometry, AudioDirection::Render);
        stream.start().unwrap();
        assert_eq!(stream.start(), Err(StreamError::AlreadyStarted));
        assert_eq!(stream.reset(), Err(StreamError::NotStopped));
        stream.stop().unwrap();
        stream.reset().unwrap();
        assert_eq!(stream.state(), StreamState::Stopped);
    }
}
