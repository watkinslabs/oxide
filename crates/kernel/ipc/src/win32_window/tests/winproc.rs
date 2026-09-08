//! Window-procedure handle table contract.
use super::*;

const PROC_A: u64 = 0x0000_7ffd_1234_0010;
const PROC_B: u64 = 0x0000_7ffd_1234_0020;

#[test]
fn handle_encoding_is_the_tag_plus_the_index() {
    assert_eq!(make_winproc(0), 0xffff_0000);
    assert_eq!(make_winproc(NB_BUILTIN_PROCS), 0xffff_0011);
    assert_eq!(make_winproc(MAX_WINPROCS - 1), 0xffff_0fff);
}

#[test]
fn builtin_slots_exist_before_any_client_publication() {
    let procs = WinProcs::new();
    assert_eq!(procs.used(), NB_BUILTIN_PROCS);
    assert_eq!(procs.slot(make_winproc(0)), WinProcSlot::Index(0));
    assert_eq!(procs.slot(make_winproc(NB_BUILTIN_PROCS - 1)), WinProcSlot::Index(NB_BUILTIN_PROCS - 1));
    assert_eq!(procs.slot(make_winproc(NB_BUILTIN_PROCS)), WinProcSlot::NotAHandle);
}

#[test]
fn only_an_exact_tagged_word_is_a_handle() {
    let procs = WinProcs::new();
    assert_eq!(procs.slot(PROC_A), WinProcSlot::NotAHandle);
    assert_eq!(procs.slot(0), WinProcSlot::NotAHandle);
    // The tag in the low half-word, or extra high bits, is not the encoding.
    assert_eq!(procs.slot(0x0000_ffff), WinProcSlot::NotAHandle);
    assert_eq!(procs.slot(0x0001_ffff_0000), WinProcSlot::NotAHandle);
    // An index past the table names a 16-bit procedure, not a bad handle.
    assert_eq!(procs.slot(make_winproc(MAX_WINPROCS)), WinProcSlot::Proc16);
    assert_eq!(procs.slot(0xffff_ffff), WinProcSlot::Proc16);
}

#[test]
fn allocation_answers_a_handle_and_reuses_it_per_flavour() {
    let mut procs = WinProcs::new();
    let handle = procs.alloc(PROC_A, false);
    assert_eq!(handle, make_winproc(NB_BUILTIN_PROCS));
    assert_eq!(procs.alloc(PROC_A, false), handle);
    // The other flavour of the same address is a separate registration.
    let ansi = procs.alloc(PROC_A, true);
    assert_ne!(ansi, handle);
    assert_eq!(procs.alloc(PROC_B, false), make_winproc(NB_BUILTIN_PROCS + 2));
}

#[test]
fn allocation_answers_the_input_unchanged_when_it_allocates_nothing() {
    let mut procs = WinProcs::new();
    // A null procedure is answered as itself, never as a fresh handle.
    assert_eq!(procs.alloc(0, false), 0);
    assert_eq!(procs.used(), NB_BUILTIN_PROCS);
    // A word that is already a handle is answered as that handle.
    let handle = procs.alloc(PROC_A, false);
    assert_eq!(procs.alloc(handle, false), handle);
    assert_eq!(procs.alloc(handle, true), handle);
    // A 16-bit handle is answered unchanged.
    let proc16 = make_winproc(MAX_WINPROCS + 7);
    assert_eq!(procs.alloc(proc16, false), proc16);
}

#[test]
fn a_full_table_answers_the_procedure_not_zero() {
    let mut procs = WinProcs::new();
    for index in 0..(MAX_WINPROCS - NB_BUILTIN_PROCS) { assert_ne!(procs.alloc(PROC_A + index as u64 * 16, false), 0); }
    assert_eq!(procs.used(), MAX_WINPROCS);
    let overflow = PROC_A + 0x10_0000;
    assert_eq!(procs.alloc(overflow, false), overflow);
}

#[test]
fn the_dialog_query_answers_the_registered_flavour() {
    let mut procs = WinProcs::new();
    let unicode = procs.alloc(PROC_A, false);
    assert_eq!(procs.dialog_proc(unicode, false), PROC_A);
    // The flavour that was never registered is genuinely absent.
    assert_eq!(procs.dialog_proc(unicode, true), 0);
    let ansi = procs.alloc(PROC_B, true);
    assert_eq!(procs.dialog_proc(ansi, true), PROC_B);
}

#[test]
fn the_dialog_query_answers_a_non_handle_unchanged() {
    let procs = WinProcs::new();
    assert_eq!(procs.dialog_proc(PROC_A, false), PROC_A);
    assert_eq!(procs.dialog_proc(PROC_A, true), PROC_A);
    assert_eq!(procs.dialog_proc(0, false), 0);
    // A handle past the table answers the 16-bit placeholder.
    assert_eq!(procs.dialog_proc(make_winproc(MAX_WINPROCS + 1), false), WINPROC_PROC16);
}

#[test]
fn published_builtins_are_answerable_and_match_either_flavour() {
    let mut procs = WinProcs::new();
    let ansi: [u64; NB_BUILTIN_PROCS] = core::array::from_fn(|index| 0x1000 + index as u64 * 16);
    let unicode: [u64; NB_BUILTIN_PROCS] = core::array::from_fn(|index| 0x2000 + index as u64 * 16);
    procs.publish_builtins(&ansi, &unicode);
    assert_eq!(procs.dialog_proc(make_winproc(3), true), ansi[3]);
    assert_eq!(procs.dialog_proc(make_winproc(3), false), unicode[3]);
    // A builtin slot is found for either flavour of its procedure.
    assert_eq!(procs.alloc(ansi[5], false), make_winproc(5));
    assert_eq!(procs.alloc(unicode[5], true), make_winproc(5));
    assert_eq!(procs.used(), NB_BUILTIN_PROCS);
}
