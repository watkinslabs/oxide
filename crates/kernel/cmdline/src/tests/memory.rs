use crate::memory::{CoreValue, MemoryCoreRequest, memory_core_request};

#[test]
fn later_memory_core_values_replace_only_their_own_parameter() {
    assert_eq!(memory_core_request(b"kernelcore=1G movablecore=512M kernelcore=2G"), MemoryCoreRequest {
        kernelcore: Some(CoreValue::Bytes(2 * 1024 * 1024 * 1024)),
        movablecore: Some(CoreValue::Bytes(512 * 1024 * 1024)),
    });
}

#[test]
fn values_preserve_percent_or_binary_byte_units() {
    assert_eq!(memory_core_request(b"kernelcore=12% movablecore=0x400M"), MemoryCoreRequest {
        kernelcore: Some(CoreValue::Percent(12)),
        movablecore: Some(CoreValue::Bytes(0x400 * 1024 * 1024)),
    });
    assert_eq!(memory_core_request(b"movablecore=0100K"), MemoryCoreRequest {
        kernelcore: None,
        movablecore: Some(CoreValue::Bytes(64 * 1024)),
    });
}

#[test]
fn kernelcore_mirror_remains_distinct_from_a_numeric_request() {
    assert_eq!(memory_core_request(b"kernelcore=mirror movablecore=1G"), MemoryCoreRequest {
        kernelcore: Some(CoreValue::Mirror),
        movablecore: Some(CoreValue::Bytes(1024 * 1024 * 1024)),
    });
}

#[test]
fn exact_names_and_malformed_numbers_cannot_select_a_neighboring_parameter() {
    assert_eq!(memory_core_request(b"notkernelcore=1G kernelcore=oops movablecore_extra=1G"), MemoryCoreRequest {
        kernelcore: Some(CoreValue::Bytes(0)),
        movablecore: None,
    });
}
