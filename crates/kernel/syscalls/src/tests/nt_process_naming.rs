use super::*;

#[test]
fn a_windows_path_yields_its_own_basename() {
    assert_eq!(comm_of("C:\\windows\\system32\\notepad.exe"), "notepad.exe");
}

#[test]
fn a_host_path_yields_its_basename_too() {
    assert_eq!(comm_of("/usr/lib64/wine/x86_64-windows/notepad.exe"), "notepad.exe");
}

#[test]
fn a_bare_name_is_already_the_comm() {
    assert_eq!(comm_of("notepad.exe"), "notepad.exe");
}

#[test]
fn a_trailing_separator_does_not_produce_an_empty_name() {
    // An empty comm would leave the process nameless in every task manager.
    assert_eq!(comm_of("C:\\windows\\"), "C:\\windows\\");
    assert_eq!(comm_of("/usr/bin/"), "/usr/bin/");
}

#[test]
fn the_empty_path_is_returned_unchanged_rather_than_panicking() {
    assert_eq!(comm_of(""), "");
}
