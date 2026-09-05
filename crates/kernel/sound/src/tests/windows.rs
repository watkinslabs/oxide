// Contract provenance: the native PCM owner commits application progress only
// after a valid transfer boundary; the Windows adapter exposes that boundary
// as one outstanding render buffer loan.
use super::*;

fn format() -> PcmFormat { PcmFormat::from_alsa(crate::uapi::FMT_S16_LE, 2, 48_000).unwrap() }

#[test]
fn duration_geometry_matches_wasapi_frame_rounding() {
    let g = StreamGeometry::from_durations(format(), 10_000_000, 1_000_000).unwrap();
    assert_eq!((g.buffer_frames, g.period_frames, g.buffer_bytes), (48_000, 4_800, 192_000));
    assert_eq!(g.duration_hns(format().rate_hz()).unwrap(), 10_000_000);
}

#[test]
fn render_and_capture_preserve_padding_bounds() {
    let g = StreamGeometry::from_frames(format(), 8, 4).unwrap();
    let mut render = AudioStream::new(g, AudioDirection::Render);
    assert!(render.client_write(8).is_ok());
    assert_eq!(render.client_write(1), Err(StreamError::WouldBlock));
    assert!(render.device_advance(4).is_ok());
    assert_eq!(render.current_padding(), 4);
    let mut capture = AudioStream::new(g, AudioDirection::Capture);
    assert!(capture.device_advance(8).is_ok());
    assert_eq!(capture.device_advance(1), Err(StreamError::WouldBlock));
    assert!(capture.client_read(4).is_ok());
    assert_eq!(capture.current_padding(), 4);
}

#[test]
fn render_buffer_loan_commits_only_on_valid_release() {
    let g = StreamGeometry::from_frames(format(), 8, 4).unwrap();
    let mut render = AudioStream::new(g, AudioDirection::Render);
    assert!(render.render_get_buffer(4).is_ok());
    assert_eq!(render.current_padding(), 0);
    assert_eq!(render.render_get_buffer(1), Err(StreamError::OutOfOrder));
    assert_eq!(render.render_release_buffer(5), Err(StreamError::InvalidBufferSize));
    assert_eq!(render.current_padding(), 0);
    assert!(render.render_release_buffer(3).is_ok());
    assert_eq!(render.current_padding(), 3);
    assert_eq!(render.render_release_buffer(1), Err(StreamError::OutOfOrder));
    assert_eq!(render.render_get_buffer(6), Err(StreamError::BufferTooLarge));
    assert!(render.render_get_buffer(5).is_ok());
    assert!(render.render_release_buffer(0).is_ok());
    assert_eq!(render.current_padding(), 3);
}

#[test]
fn rejects_invalid_windows_geometry_and_formats() {
    assert_eq!(PcmFormat::from_alsa(crate::uapi::FMT_MU_LAW, 2, 48_000), Err(FormatError::UnsupportedFormat));
    assert_eq!(PcmFormat::from_alsa(crate::uapi::FMT_S16_LE, 0, 48_000), Err(FormatError::InvalidChannels));
    assert_eq!(StreamGeometry::from_frames(format(), 8, 9), Err(StreamError::PeriodExceedsBuffer));
    assert_eq!(StreamGeometry::from_frames(format(), MAX_BUFFER_FRAMES + 1, 1), Err(StreamError::BufferTooLarge));
}

#[test]
fn stream_lifecycle_matches_wasapi_start_stop_reset_contract() {
    let f = format();
    let g = StreamGeometry::from_frames(f, 8, 4).unwrap();
    let mut stream = AudioStream::with_format(f, g, AudioDirection::Render);
    assert_eq!(stream.state(), StreamState::Initialized);
    assert_eq!(stream.start(), Ok(()));
    assert_eq!(stream.start(), Err(StreamError::AlreadyStarted));
    assert_eq!(stream.reset(), Err(StreamError::NotStopped));
    assert_eq!(stream.stop(), Ok(()));
    assert_eq!(stream.stop(), Ok(()));
    assert_eq!(stream.reset(), Ok(()));
    assert_eq!(stream.state(), StreamState::Stopped);
    assert_eq!(stream.format(), Some(f));
    assert_eq!(stream.negotiated_format(), Some(crate::uapi::FMT_S16_LE));
}

#[test]
fn invalidated_endpoint_rejects_all_client_lifecycle_operations() {
    let g = StreamGeometry::from_frames(format(), 8, 4).unwrap();
    let mut stream = AudioStream::new(g, AudioDirection::Capture);
    stream.invalidate();
    assert_eq!(stream.state(), StreamState::Invalidated);
    assert_eq!(stream.start(), Err(StreamError::Invalidated));
    assert_eq!(stream.stop(), Err(StreamError::Invalidated));
    assert_eq!(stream.reset(), Err(StreamError::Invalidated));
    assert_eq!(stream.client_write(1), Err(StreamError::Invalidated));
    assert_eq!(stream.client_read(1), Err(StreamError::Invalidated));
    assert_eq!(stream.render_get_buffer(1), Err(StreamError::Invalidated));
}

#[test]
fn negotiated_format_is_immutable_and_geometry_rejects_tampering() {
    let f = format();
    assert_eq!(f.alsa_format(), crate::uapi::FMT_S16_LE);
    assert_eq!(f.channels(), 2);
    assert_eq!(f.rate_hz(), 48_000);
    assert_eq!(f.frame_bytes(), 4);
    let forged = PcmFormat { frame_bytes: 8, ..f };
    assert_eq!(forged.validate(), Err(FormatError::InvalidFrameBytes));
    assert_eq!(StreamGeometry::from_frames(forged, 8, 4), Err(StreamError::InvalidFormat));
}

#[test]
fn close_releases_loans_and_rejects_operations_without_reviving_endpoint() {
    let f = format();
    let g = StreamGeometry::from_frames(f, 8, 4).unwrap();
    let mut stream = AudioStream::with_format(f, g, AudioDirection::Render);
    stream.start().unwrap();
    stream.render_get_buffer(2).unwrap();
    stream.close();
    assert_eq!(stream.state(), StreamState::Closed);
    assert_eq!(stream.current_padding(), 0);
    assert_eq!(stream.stop(), Err(StreamError::Closed));
    assert_eq!(stream.start(), Err(StreamError::Closed));
    assert_eq!(stream.reset(), Err(StreamError::Closed));
    assert_eq!(stream.render_release_buffer(0), Err(StreamError::Closed));
    assert_eq!(stream.client_write(1), Err(StreamError::Closed));
    stream.invalidate();
    assert_eq!(stream.state(), StreamState::Closed);
}
