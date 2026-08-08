use alloc::vec::Vec;

use super::*;
use crate::config::Field;

/// Eleven `u32` in a fixed order. A consumer reads the struct positionally, so
/// the length and the order are the contract.
#[test]
fn a_status_reply_is_eleven_words_in_field_order() {
    let s = Status {
        mask: 1, enabled: 2, failure: 3, pid: 4, rate_limit: 5, backlog_limit: 6,
        lost: 7, backlog: 8, feature_bitmap: 9, backlog_wait_time: 10,
        backlog_wait_time_actual: 11,
    };
    let bytes = s.encode();
    assert_eq!(bytes.len(), AUDIT_STATUS_LEN);
    assert_eq!(AUDIT_STATUS_LEN, 44);
    let words: Vec<u32> = bytes.chunks(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]])).collect();
    assert_eq!(words, Vec::from([1u32, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]));
    assert_eq!(Status::decode(&bytes), s);
}

/// An older client sends the prefix it was built against; the missing tail
/// must read as zero rather than failing the request.
#[test]
fn a_short_status_request_zero_extends() {
    let mut short = Vec::new();
    short.extend_from_slice(&AUDIT_STATUS_ENABLED.to_le_bytes());
    short.extend_from_slice(&1u32.to_le_bytes());
    let s = Status::decode(&short);
    assert_eq!(s.mask, AUDIT_STATUS_ENABLED);
    assert_eq!(s.enabled, 1);
    assert_eq!(s.backlog_wait_time_actual, 0);
    assert_eq!(Status::decode(&[]), Status::default());
}

#[test]
fn a_status_reply_reports_the_live_configuration_and_backlog() {
    let mut cfg = Config::default();
    crate::config::set(&mut cfg, Field::Enabled, AUDIT_ON).unwrap();
    crate::config::set(&mut cfg, Field::RateLimit, 11).unwrap();
    cfg.count_lost();
    let s = Status::from_config(&cfg, 4242, 3);
    assert_eq!(s.mask, 0, "the mask selects fields on the way in only");
    assert_eq!(s.enabled, AUDIT_ON);
    assert_eq!(s.pid, 4242);
    assert_eq!(s.rate_limit, 11);
    assert_eq!(s.lost, 1);
    assert_eq!(s.backlog, 3);
    assert_eq!(s.feature_bitmap, AUDIT_FEATURE_BITMAP_ALL);
    assert_eq!(s.backlog_wait_time, AUDIT_BACKLOG_WAIT_TIME);
}

#[test]
fn the_feature_bitmap_names_every_defined_bit() {
    assert_eq!(AUDIT_FEATURE_BITMAP_ALL, 0x7f);
}

#[test]
fn a_features_request_is_four_words() {
    let mut data = Vec::new();
    for v in [1u32, 2, 3, 4] { data.extend_from_slice(&v.to_le_bytes()); }
    assert_eq!(FeatureRequest::decode(&data),
        FeatureRequest { vers: 1, mask: 2, features: 3, lock: 4 });
    assert_eq!(data.len(), AUDIT_FEATURES_LEN);
}

#[test]
fn a_features_reply_names_the_version_the_changeable_mask_and_the_live_state() {
    let mut cfg = Config::default();
    let bit = feature_to_mask(AUDIT_FEATURE_LOGINUID_IMMUTABLE);
    crate::config::apply_features(&mut cfg, FeatureRequest {
        vers: AUDIT_FEATURE_VERSION, mask: bit, features: bit, lock: bit }).unwrap();
    let bytes = FeatureRequest::reply(&cfg);
    assert_eq!(bytes.len(), AUDIT_FEATURES_LEN);
    let got = FeatureRequest::decode(&bytes);
    assert_eq!(got.vers, AUDIT_FEATURE_VERSION);
    assert_eq!(got.mask, feature_to_mask(AUDIT_FEATURE_ONLY_UNSET_LOGINUID) | bit);
    assert_eq!(got.features, bit);
    assert_eq!(got.lock, bit);
}
