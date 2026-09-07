use super::*;

const TID: u64 = 5;
const OTHER_TID: u64 = 6;

#[test]
fn a_new_window_carries_no_association() {
    let mut state = WindowManager::new();
    let window = state.create(TID, None, 0).unwrap();
    assert_eq!(state.window_imc(window), None);
    assert_eq!(state.imc_window_facts(window), Some(WindowFacts { thread_id: TID, imc: None, focused: false }));
}

#[test]
fn the_association_is_stored_on_the_window_record() {
    let mut state = WindowManager::new();
    let window = state.create(TID, None, 0).unwrap();
    let imc = ImcId::from_raw(4);
    assert_eq!(state.set_window_imc(window, imc), Ok(()));
    assert_eq!(state.window_imc(window), imc);
    assert_eq!(state.imc_window_facts(window).unwrap().imc, imc);
    assert_eq!(state.set_window_imc(window, None), Ok(()));
    assert_eq!(state.window_imc(window), None);
}

#[test]
fn facts_report_the_owning_thread_and_the_focus() {
    let mut state = WindowManager::new();
    let window = state.create(TID, None, 0).unwrap();
    let elsewhere = state.create(OTHER_TID, None, 0).unwrap();
    state.set_focus(TID, Some(window)).unwrap();
    assert_eq!(state.imc_window_facts(window).unwrap().focused, true);
    assert_eq!(state.imc_window_facts(elsewhere), Some(WindowFacts { thread_id: OTHER_TID, imc: None, focused: false }));
}

#[test]
fn an_unknown_window_has_no_facts_and_refuses_the_association() {
    let mut state = WindowManager::new();
    let unknown = WindowId::from_raw(9999).unwrap();
    assert_eq!(state.imc_window_facts(unknown), None);
    assert_eq!(state.window_imc(unknown), None);
    assert_eq!(state.set_window_imc(unknown, ImcId::from_raw(1)), Err(WindowError::NoSuchWindow));
}

#[test]
fn destroying_a_window_drops_its_association_with_the_record() {
    let mut state = WindowManager::new();
    let window = state.create(TID, None, 0).unwrap();
    state.set_window_imc(window, ImcId::from_raw(2)).unwrap();
    state.destroy(window).unwrap();
    assert_eq!(state.window_imc(window), None);
    assert_eq!(state.imc_window_facts(window), None);
}
