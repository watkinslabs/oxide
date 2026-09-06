//! Hosted boundary executes production metric routing and canonical immutable settings.
use ipc::win32_gdi::{stock_object, StockDescription, FontRecord, GdiError};
#[path = "../../ipc/src/win32_gdi/nonclient.rs"]
mod owner;
#[path = "../src/nt_wine_window/metrics.rs"]
mod metrics;

#[test]
fn non_display_metrics_do_not_require_a_desktop_or_native_callback() {
    for (index, value) in [(2,16), (3,16), (5,1), (6,1), (7,3), (8,3), (9,16), (10,16),
        (11,32), (12,32), (13,32), (14,32), (20,16), (21,16), (30,18), (32,4), (33,4),
        (45,2), (46,2), (49,16), (50,16), (52,15), (54,18)] {
        assert_eq!(metrics::route(index | 0x1234_0000_0000, owner::system_metric_default,
            |_| panic!("scalar setting entered native callback"), || panic!("scalar setting queried display")), value);
    }
    let profile = owner::nonclient_defaults(504).unwrap();
    let integer = |offset| i32::from_le_bytes(profile[offset..offset+4].try_into().unwrap());
    assert_eq!(owner::system_metric_default(2), Some(integer(8)));
    assert_eq!(owner::system_metric_default(9), Some(integer(12)));
    assert_eq!(owner::system_metric_default(30), Some(integer(16)));
    assert_eq!(owner::system_metric_default(52), Some(integer(116)));
    assert_eq!(owner::system_metric_default(54), Some(integer(216)));
}

#[test]
fn font_metric_route_preserves_native_continuation_result_without_display_access() {
    for index in [4,15,31,51,53,55,57] {
        let continuation = 0xface_1234_0000_0000 | index;
        assert_eq!(metrics::route(index, owner::system_metric_default, |actual| {
            assert_eq!(actual as u64, index); continuation
        }, || panic!("font metric queried display")), continuation);
        assert_eq!(metrics::route(index, owner::system_metric_default, |_| 0, || None), 0);
    }
    for index in [0,1,76,77,78,79,80,u64::MAX] {
        assert_eq!(metrics::route(index, owner::system_metric_default,
            |_| panic!("display or unknown index entered font callback"), || None), 0);
    }
}
