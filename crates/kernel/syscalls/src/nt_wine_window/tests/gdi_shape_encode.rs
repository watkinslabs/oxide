use super::*;
use ipc::win32_gdi::region::scan::Point;

#[test]
fn a_zero_size_query_asks_for_the_point_count() {
    assert_eq!(path_plan(0, 7), PathPlan::Count(7));
    assert_eq!(path_plan(0, 0), PathPlan::Count(0));
}

#[test]
fn a_buffer_smaller_than_the_path_is_refused_before_any_copy() {
    assert_eq!(path_plan(3, 4), PathPlan::Refuse);
    assert_eq!(path_plan(4, 4), PathPlan::Copy(4));
    assert_eq!(path_plan(9, 4), PathPlan::Copy(4));
    assert_eq!(path_plan(-1, 4), PathPlan::Refuse);
}

#[test]
fn a_null_region_data_buffer_asks_for_the_size_and_a_short_one_reports_zero() {
    assert_eq!(data_plan(0, 0, 48), DataPlan::Size(48));
    assert_eq!(data_plan(0x1000, 47, 48), DataPlan::Refuse);
    assert_eq!(data_plan(0x1000, 48, 48), DataPlan::Copy(48));
    assert_eq!(data_plan(0x1000, 64, 48), DataPlan::Copy(48));
}

#[test]
fn point_images_are_two_little_endian_signed_words_each() {
    let bytes = point_bytes(&[Point { x: -1, y: 2 }]).unwrap();
    assert_eq!(bytes.len(), POINT_BYTES);
    assert_eq!(&bytes[0..4], &(-1i32).to_le_bytes());
    assert_eq!(&bytes[4..8], &2i32.to_le_bytes());
    assert!(point_bytes(&[]).unwrap().is_empty());
}

#[test]
fn a_rectangle_image_reads_back_signed_edges() {
    let mut bytes = [0u8; 16];
    for (index, value) in [-3i32, -4, 5, 6].into_iter().enumerate() {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    assert_eq!(rect_from_bytes(bytes), ipc::win32_gdi::Rect { left: -3, top: -4, right: 5, bottom: 6 });
}

#[test]
fn the_layout_and_dpi_request_bits_are_stripped_from_the_region_code() {
    assert_eq!(region_code(4), 4);
    assert_eq!(region_code((RGN_MIRROR_RTL | 1) as i32), 1);
    assert_eq!(region_code((RGN_MONITOR_DPI | 4) as i32), 4);
    assert_eq!(region_code((RGN_MIRROR_RTL | RGN_MONITOR_DPI | 3) as i32), 3);
}
