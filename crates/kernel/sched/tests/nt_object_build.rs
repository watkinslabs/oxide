use sched::nt_object::{NtHandleTable, NtObjectType};

#[test]
fn nt_object_state_builds_without_the_live_runtime() {
    let table = NtHandleTable::new();
    let object = table.new_object(NtObjectType::Event);
    let handle = table.insert(object, 0x10).expect("host build retains NT object state");
    assert!(table.get(handle, 0x10).is_some());
}
