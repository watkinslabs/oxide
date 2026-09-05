// Contract provenance: the native PCM owner commits application progress only
// after a valid transfer boundary; the Windows adapter exposes that boundary
// as one outstanding render buffer loan.
use super::*;

fn format() -> PcmFormat { PcmFormat::from_alsa(crate::uapi::FMT_S16_LE, 2, 48_000).unwrap() }

#[test]
fn duration_geometry_matches_wasapi_frame_rounding() {
    let g = StreamGeometry::from_durations(format(), 10_000_000, 1_000_000).unwrap();
    assert_eq!((g.buffer_frames, g.period_frames, g.buffer_bytes), (48_000, 4_800, 192_000));
    assert_eq!(g.duration_hns(format().rate_hz).unwrap(), 10_000_000);
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
