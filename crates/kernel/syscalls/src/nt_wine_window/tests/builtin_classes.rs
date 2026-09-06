use super::*;
extern crate alloc;
use alloc::vec::Vec;

#[test]
fn the_table_matches_the_reference() {
    assert_eq!(BUILTINS.len(), 12);
    let edit = BUILTINS.iter().find(|b| b.name == "Edit").unwrap();
    assert_eq!((edit.style, edit.extra, edit.brush, edit.proc_index), (0x88, 8, 0, 11));
    let button = BUILTINS.iter().find(|b| b.name == "Button").unwrap();
    assert_eq!((button.style, button.extra), (0x8b, 20));
    let scroll = BUILTINS.iter().find(|b| b.name == "ScrollBar").unwrap();
    assert_eq!((scroll.extra, scroll.proc_index), (28, 0));
    assert_eq!(BUILTINS.iter().find(|b| b.name == "#32768").unwrap().brush, 5);
    assert_eq!(BUILTINS.iter().find(|b| b.name == "MDIClient").unwrap().brush, 13);
    assert_eq!(BUILTINS.iter().find(|b| b.name == "#32770").unwrap().extra, 30);
    assert!(BUILTINS.iter().all(|b| b.proc_index < PROC_COUNT));
    let mut names: Vec<_> = BUILTINS.iter().map(|b| b.name).collect(); names.sort(); names.dedup();
    assert_eq!(names.len(), 12);
}

#[test]
fn registration_uses_the_array_entry_and_skips_missing_procedures() {
    let mut seen = Vec::new();
    let count = register_all(|index| if index == PROC_EDIT { Some(0) } else { Some(0x1000 + index as u64) },
        |builtin, wndproc| { seen.push((builtin.name, wndproc)); true });
    assert_eq!(count, 11);
    assert!(seen.iter().all(|(name, _)| *name != "Edit"));
    assert!(seen.contains(&("Button", 0x1000 + PROC_BUTTON as u64)));
    assert!(seen.contains(&("Static", 0x1000 + PROC_STATIC as u64)));
}

#[test]
fn a_refused_registration_is_not_counted() {
    let count = register_all(|index| Some(0x2000 + index as u64), |builtin, _| builtin.name != "IME");
    assert_eq!(count, 11);
    assert_eq!(register_all(|_| None, |_, _| panic!("no procedure, no registration")), 0);
}
