// Access-mask contract per NT object type: the numeric mask each type answers
// for, the four generic expansions, and the requests a loader actually makes.

use super::*;

fn mapped(descr: &ObjectAccess, desired: u32) -> u32 { descr.map(desired) }

#[test]
fn standard_rights_are_the_published_numbers() {
    assert_eq!(STANDARD_RIGHTS_REQUIRED, 0x000f_0000);
    assert_eq!(READ_CONTROL, 0x0002_0000);
    assert_eq!(STANDARD_RIGHTS_READ, READ_CONTROL);
    assert_eq!(STANDARD_RIGHTS_WRITE, READ_CONTROL);
    assert_eq!(STANDARD_RIGHTS_EXECUTE, READ_CONTROL);
    assert_eq!(SYNCHRONIZE, 0x0010_0000);
    assert_eq!(MAXIMUM_ALLOWED, 0x0200_0000);
    assert_eq!((GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, GENERIC_ALL),
               (0x8000_0000, 0x4000_0000, 0x2000_0000, 0x1000_0000));
}

#[test]
fn every_type_answers_for_its_published_all_access() {
    assert_eq!(EVENT_ALL_ACCESS, 0x001f_0003);
    assert_eq!(MUTANT_ALL_ACCESS, 0x001f_0001);
    assert_eq!(SEMAPHORE_ALL_ACCESS, 0x001f_0003);
    assert_eq!(TIMER_ALL_ACCESS, 0x001f_0003);
    assert_eq!(IO_COMPLETION_ALL_ACCESS, 0x001f_0003);
    assert_eq!(KEYEDEVENT_ALL_ACCESS, 0x000f_0003);
    assert_eq!(KEYED_EVENT.valid, 0x001f_0003);
}

#[test]
fn event_maps_the_four_generic_rights() {
    assert_eq!(mapped(&EVENT, GENERIC_READ), READ_CONTROL | EVENT_QUERY_STATE);
    assert_eq!(mapped(&EVENT, GENERIC_WRITE), READ_CONTROL | EVENT_MODIFY_STATE);
    assert_eq!(mapped(&EVENT, GENERIC_EXECUTE), READ_CONTROL | SYNCHRONIZE);
    assert_eq!(mapped(&EVENT, GENERIC_ALL), EVENT_ALL_ACCESS);
}

#[test]
fn mutant_maps_the_four_generic_rights() {
    assert_eq!(mapped(&MUTANT, GENERIC_READ), READ_CONTROL | MUTANT_QUERY_STATE);
    assert_eq!(mapped(&MUTANT, GENERIC_WRITE), READ_CONTROL);
    assert_eq!(mapped(&MUTANT, GENERIC_EXECUTE), READ_CONTROL | SYNCHRONIZE);
    assert_eq!(mapped(&MUTANT, GENERIC_ALL), MUTANT_ALL_ACCESS);
}

#[test]
fn semaphore_maps_the_four_generic_rights() {
    assert_eq!(mapped(&SEMAPHORE, GENERIC_READ), READ_CONTROL | SEMAPHORE_QUERY_STATE);
    assert_eq!(mapped(&SEMAPHORE, GENERIC_WRITE), READ_CONTROL | SEMAPHORE_MODIFY_STATE);
    assert_eq!(mapped(&SEMAPHORE, GENERIC_EXECUTE), READ_CONTROL | SYNCHRONIZE);
    assert_eq!(mapped(&SEMAPHORE, GENERIC_ALL), SEMAPHORE_ALL_ACCESS);
}

#[test]
fn timer_maps_the_four_generic_rights() {
    assert_eq!(mapped(&TIMER, GENERIC_READ), READ_CONTROL | TIMER_QUERY_STATE);
    assert_eq!(mapped(&TIMER, GENERIC_WRITE), READ_CONTROL | TIMER_MODIFY_STATE);
    assert_eq!(mapped(&TIMER, GENERIC_EXECUTE), READ_CONTROL | SYNCHRONIZE);
    assert_eq!(mapped(&TIMER, GENERIC_ALL), TIMER_ALL_ACCESS);
}

#[test]
fn completion_maps_the_four_generic_rights() {
    assert_eq!(mapped(&IO_COMPLETION, GENERIC_READ), READ_CONTROL | IO_COMPLETION_QUERY_STATE);
    assert_eq!(mapped(&IO_COMPLETION, GENERIC_WRITE), READ_CONTROL | IO_COMPLETION_MODIFY_STATE);
    assert_eq!(mapped(&IO_COMPLETION, GENERIC_EXECUTE), READ_CONTROL | SYNCHRONIZE);
    assert_eq!(mapped(&IO_COMPLETION, GENERIC_ALL), IO_COMPLETION_ALL_ACCESS);
}

#[test]
fn keyed_event_maps_the_four_generic_rights_and_grants_no_generic_wait() {
    assert_eq!(mapped(&KEYED_EVENT, GENERIC_READ), READ_CONTROL | KEYEDEVENT_WAIT);
    assert_eq!(mapped(&KEYED_EVENT, GENERIC_WRITE), READ_CONTROL | KEYEDEVENT_WAKE);
    assert_eq!(mapped(&KEYED_EVENT, GENERIC_EXECUTE), READ_CONTROL);
    assert_eq!(mapped(&KEYED_EVENT, GENERIC_ALL), KEYEDEVENT_ALL_ACCESS);
    for generic in [GENERIC_READ, GENERIC_WRITE, GENERIC_EXECUTE, GENERIC_ALL] {
        assert_eq!(mapped(&KEYED_EVENT, generic) & SYNCHRONIZE, 0);
    }
    assert_eq!(KEYED_EVENT.grant(SYNCHRONIZE), Some(SYNCHRONIZE));
    assert_eq!(keyed_event_access(true), KEYEDEVENT_WAKE);
    assert_eq!(keyed_event_access(false), KEYEDEVENT_WAIT);
}

#[test]
fn directory_maps_the_four_generic_rights() {
    assert_eq!(DIRECTORY_ALL_ACCESS, 0x000f_000f);
    assert_eq!(mapped(&DIRECTORY, GENERIC_READ), READ_CONTROL | DIRECTORY_TRAVERSE | DIRECTORY_QUERY);
    assert_eq!(mapped(&DIRECTORY, GENERIC_WRITE), READ_CONTROL | DIRECTORY_CREATE_SUBDIRECTORY | DIRECTORY_CREATE_OBJECT);
    assert_eq!(mapped(&DIRECTORY, GENERIC_EXECUTE), READ_CONTROL | DIRECTORY_TRAVERSE | DIRECTORY_QUERY);
    assert_eq!(mapped(&DIRECTORY, GENERIC_ALL), DIRECTORY_ALL_ACCESS);
    // A directory answers for no wait-object right.
    assert!(!DIRECTORY.admitted(SYNCHRONIZE));
}

#[test]
fn no_generic_bit_survives_a_mapping() {
    let generics = GENERIC_READ | GENERIC_WRITE | GENERIC_EXECUTE | GENERIC_ALL;
    for descr in [&EVENT, &MUTANT, &SEMAPHORE, &TIMER, &IO_COMPLETION, &KEYED_EVENT, &DIRECTORY] {
        assert_eq!(mapped(descr, generics) & generics, 0);
        assert_eq!(mapped(descr, MAXIMUM_ALLOWED) & (generics | MAXIMUM_ALLOWED), 0);
    }
}

#[test]
fn maximum_allowed_resolves_to_every_right_the_type_grants() {
    assert_eq!(mapped(&EVENT, MAXIMUM_ALLOWED), EVENT_ALL_ACCESS);
    assert_eq!(mapped(&MUTANT, MAXIMUM_ALLOWED), MUTANT_ALL_ACCESS);
    assert_eq!(mapped(&SEMAPHORE, MAXIMUM_ALLOWED), SEMAPHORE_ALL_ACCESS);
    assert_eq!(mapped(&TIMER, MAXIMUM_ALLOWED), TIMER_ALL_ACCESS);
    assert_eq!(mapped(&IO_COMPLETION, MAXIMUM_ALLOWED), IO_COMPLETION_ALL_ACCESS);
    assert_eq!(mapped(&KEYED_EVENT, MAXIMUM_ALLOWED), KEYEDEVENT_ALL_ACCESS);
}

#[test]
fn the_standard_rights_a_loader_asks_for_are_admitted() {
    // A request naming the standard rights together with synchronise is what
    // the runtime's own object creation carries; refusing it fails the load.
    let request = STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE;
    for descr in [&EVENT, &MUTANT, &SEMAPHORE, &TIMER, &IO_COMPLETION, &KEYED_EVENT] {
        assert_eq!(descr.grant(request), Some(request));
    }
}

#[test]
fn a_generic_write_handle_carries_the_specific_modify_right() {
    // The defect this guards: a granted mask that kept the generic bit could
    // not satisfy a later check for the specific right it stands for.
    assert_eq!(EVENT.grant(GENERIC_WRITE).unwrap() & EVENT_MODIFY_STATE, EVENT_MODIFY_STATE);
    assert_eq!(SEMAPHORE.grant(GENERIC_WRITE).unwrap() & SEMAPHORE_MODIFY_STATE, SEMAPHORE_MODIFY_STATE);
    assert_eq!(TIMER.grant(GENERIC_WRITE).unwrap() & TIMER_MODIFY_STATE, TIMER_MODIFY_STATE);
    assert_eq!(IO_COMPLETION.grant(GENERIC_WRITE).unwrap() & IO_COMPLETION_MODIFY_STATE, IO_COMPLETION_MODIFY_STATE);
    assert_eq!(MUTANT.grant(GENERIC_READ).unwrap() & MUTANT_QUERY_STATE, MUTANT_QUERY_STATE);
    assert_eq!(KEYED_EVENT.grant(GENERIC_WRITE).unwrap() & KEYEDEVENT_WAKE, KEYEDEVENT_WAKE);
}

#[test]
fn a_right_no_type_defines_is_refused() {
    let stray = 0x0000_0800;
    for descr in [&EVENT, &MUTANT, &SEMAPHORE, &TIMER, &IO_COMPLETION, &KEYED_EVENT, &DIRECTORY] {
        assert!(!descr.admitted(stray));
        assert_eq!(descr.grant(stray), None);
    }
    // A mutant answers for no modify-state right of its own.
    assert!(!MUTANT.admitted(0x0002));
}
