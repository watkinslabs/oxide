//! The degenerate-extent contract: which answered measurements collapse a
//! caller's rectangle.
use super::*;

fn request(count: u32, kind: u32) -> MeasureRequest {
    MeasureRequest { version: VERSION, size: core::mem::size_of::<MeasureRequest>() as u32, dc: 1, kind,
        count, height: 16, width: 0, weight: 400, italic: 0, max_extent: -1, flags: 0,
        text: 0x1000, metrics: 0x5000, extent: 0x2000, fit: 0x3000, cumulative: 0x4000,
        break_extra: 0, break_rem: 0 }
}

fn output(width: i32, height: i32, count: u32) -> MeasureOutput {
    MeasureOutput { metrics: [0u8; TEXTMETRIC_BYTES], width, height, fit: 0, count, reserved: 0, cumulative: 0 }
}

#[test]
fn a_measured_run_with_no_area_is_degenerate_in_either_dimension() {
    let ask = request(2, MEASURE_EXTENT);
    assert!(output(0, 18, 2).degenerate_extent(&ask), "zero width sizes an empty label rectangle");
    assert!(output(14, 0, 2).degenerate_extent(&ask), "zero height sizes an empty label rectangle");
    assert!(output(0, 0, 2).degenerate_extent(&ask));
    assert!(!output(14, 18, 2).degenerate_extent(&ask), "a real box is not degenerate");
}

#[test]
fn an_empty_run_and_a_metrics_query_measure_to_nothing_legitimately() {
    assert!(!output(0, 0, 0).degenerate_extent(&request(0, MEASURE_EXTENT)),
        "no units to measure is not a collapsed answer");
    assert!(!output(0, 0, 0).degenerate_extent(&request(0, MEASURE_METRICS)),
        "a metrics query carries no extent to collapse");
}
