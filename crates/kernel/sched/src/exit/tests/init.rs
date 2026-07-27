use crate::exit::init::*;

#[test]
fn the_last_thread_of_global_init_panics_the_machine() {
    assert_eq!(init_exit(true, true, true), InitExit::PanicMachine);
}

#[test]
fn one_thread_of_init_exiting_is_ordinary() {
    assert_eq!(init_exit(false, true, true), InitExit::None);
}

#[test]
fn a_pid_namespace_init_takes_its_namespace_with_it() {
    assert_eq!(init_exit(true, false, true), InitExit::ZapNamespace);
}

#[test]
fn an_ordinary_process_death_has_no_init_consequence() {
    assert_eq!(init_exit(true, false, false), InitExit::None);
}
