use super::*;

#[test]
fn every_published_export_selects_a_service_except_the_two_machine_code_entries() {
    let mut without = alloc::vec::Vec::new();
    for (index, name) in NTDLL_EXPORTS.iter().enumerate() {
        if service_for_index(index).is_none() { without.push(core::str::from_utf8(name).unwrap()); }
    }
    assert_eq!(without, ["DbgBreakPoint", "__chkstk", "__C_specific_handler"]);
}

#[test]
fn a_name_outside_the_catalog_selects_nothing() {
    assert_eq!(service_for_export(b"NtNotAnExport"), None);
    assert_eq!(service_for_index(NTDLL_EXPORTS.len()), None);
}

#[test]
fn an_export_name_selects_the_service_its_index_selects() {
    for (index, name) in NTDLL_EXPORTS.iter().enumerate() {
        assert_eq!(service_for_export(name), service_for_index(index), "{}", core::str::from_utf8(name).unwrap());
    }
}
