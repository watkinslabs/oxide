use super::*;

#[test]
fn cursor_hotspot_is_linux_signed_i32_range() {
    for id in [PROP_PLANE_HOTSPOT_X, PROP_PLANE_HOTSPOT_Y] {
        let (_, flags, values) = desc(id).expect("cursor hotspot property");
        assert_eq!(flags, PROP_SIGNED_RANGE);
        assert_eq!(values, &[i32::MIN as u64, i32::MAX as u64]);
    }
}
