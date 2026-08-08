use super::*;
use alloc::string::ToString;

#[test]
fn a_record_file_is_named_type_backend_index() {
    let id = RecordId { ty: RecordType::Dmesg, index: 0 };
    assert_eq!(file_name(id, "ramoops"), "dmesg-ramoops-0".to_string());
    let id = RecordId { ty: RecordType::Console, index: 0 };
    assert_eq!(file_name(id, "ramoops"), "console-ramoops-0".to_string());
    let id = RecordId { ty: RecordType::Dmesg, index: 12 };
    assert_eq!(file_name(id, "ramoops"), "dmesg-ramoops-12".to_string());
}

#[test]
fn every_record_gets_a_distinct_name() {
    // Two records of the same class in different zones, and two classes in
    // zone zero, must never collide — a collision would hide a crash report.
    let names = [
        file_name(RecordId { ty: RecordType::Dmesg, index: 0 }, "ramoops"),
        file_name(RecordId { ty: RecordType::Dmesg, index: 1 }, "ramoops"),
        file_name(RecordId { ty: RecordType::Console, index: 0 }, "ramoops"),
    ];
    assert_eq!(names[0], "dmesg-ramoops-0".to_string());
    assert_ne!(names[0], names[1]);
    assert_ne!(names[0], names[2]);
}
