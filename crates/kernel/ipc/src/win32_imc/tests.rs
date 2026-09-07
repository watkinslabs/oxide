use super::*;

const TID: u64 = 41;
const OTHER: u64 = 42;

fn facts(flags: u32, ctx: Option<ImcId>, ctx_thread: Option<u64>, window: Option<WindowFacts>) -> AssociateFacts {
    AssociateFacts { flags, ctx, ctx_thread, default_ctx: None, current_tid: TID, window }
}

fn window(imc: Option<ImcId>, focused: bool) -> Option<WindowFacts> { Some(WindowFacts { thread_id: TID, imc, focused }) }

#[test]
fn create_reports_owner_thread_and_client_pointer() {
    let mut contexts = InputContexts::new();
    let id = contexts.create(TID, 0xdead_beef).unwrap();
    assert_eq!(contexts.query(id, INPUT_CONTEXT_THREAD_ID), Ok(TID));
    assert_eq!(contexts.query(id, INPUT_CONTEXT_CLIENT_PTR), Ok(0xdead_beef));
}

#[test]
fn unknown_attribute_reads_zero_and_refuses_the_write() {
    let mut contexts = InputContexts::new();
    let id = contexts.create(TID, 7).unwrap();
    assert_eq!(contexts.query(id, 9), Ok(0));
    assert_eq!(contexts.update(id, 9, 5), Ok(false));
    assert_eq!(contexts.query(id, INPUT_CONTEXT_CLIENT_PTR), Ok(7));
}

#[test]
fn thread_id_is_read_only() {
    let mut contexts = InputContexts::new();
    let id = contexts.create(TID, 0).unwrap();
    assert_eq!(contexts.update(id, INPUT_CONTEXT_THREAD_ID, OTHER), Ok(false));
    assert_eq!(contexts.query(id, INPUT_CONTEXT_THREAD_ID), Ok(TID));
}

#[test]
fn client_pointer_is_updatable() {
    let mut contexts = InputContexts::new();
    let id = contexts.create(TID, 0).unwrap();
    assert_eq!(contexts.update(id, INPUT_CONTEXT_CLIENT_PTR, 0x1234), Ok(true));
    assert_eq!(contexts.query(id, INPUT_CONTEXT_CLIENT_PTR), Ok(0x1234));
}

#[test]
fn destroyed_handle_is_invalid_for_every_attribute() {
    let mut contexts = InputContexts::new();
    let id = contexts.create(TID, 0).unwrap();
    assert!(contexts.destroy(id));
    assert!(!contexts.destroy(id));
    assert_eq!(contexts.query(id, INPUT_CONTEXT_CLIENT_PTR), Err(InvalidHandle));
    assert_eq!(contexts.update(id, INPUT_CONTEXT_CLIENT_PTR, 1), Err(InvalidHandle));
}

#[test]
fn handles_are_never_zero_and_never_reused() {
    let mut contexts = InputContexts::new();
    let first = contexts.create(TID, 0).unwrap();
    assert!(contexts.destroy(first));
    let second = contexts.create(TID, 0).unwrap();
    assert_ne!(first, second);
    assert_ne!(second.raw(), 0);
}

#[test]
fn list_reports_only_the_named_thread_capped_at_the_count() {
    let mut contexts = InputContexts::new();
    let a = contexts.create(TID, 0).unwrap();
    let other = contexts.create(OTHER, 0).unwrap();
    let b = contexts.create(TID, 0).unwrap();
    assert_eq!(contexts.list(TID, 8), alloc::vec![a, b]);
    assert_eq!(contexts.list(TID, 1), alloc::vec![a]);
    assert_eq!(contexts.list(OTHER, 8), alloc::vec![other]);
    assert!(contexts.list(TID, 0).is_empty());
}

#[test]
fn the_default_context_is_created_once_per_thread() {
    let mut contexts = InputContexts::new();
    assert_eq!(contexts.existing_default(TID), None);
    let first = contexts.default_context(TID).unwrap();
    assert_eq!(contexts.default_context(TID), Some(first));
    assert_eq!(contexts.existing_default(TID), Some(first));
    assert_ne!(contexts.default_context(OTHER), Some(first));
    assert_eq!(contexts.query(first, INPUT_CONTEXT_THREAD_ID), Ok(TID));
    assert_eq!(contexts.query(first, INPUT_CONTEXT_CLIENT_PTR), Ok(0));
}

#[test]
fn destroying_the_default_context_lets_the_thread_take_a_new_one() {
    let mut contexts = InputContexts::new();
    let first = contexts.default_context(TID).unwrap();
    assert!(contexts.destroy(first));
    assert_eq!(contexts.existing_default(TID), None);
    assert_ne!(contexts.default_context(TID), Some(first));
}

#[test]
fn disable_thread_ime_accepts_zero_the_caller_and_the_all_threads_selector() {
    let mut contexts = InputContexts::new();
    assert!(!contexts.ime_disabled(TID));
    assert!(contexts.disable_thread_ime(TID, 0));
    assert!(contexts.ime_disabled(TID));
    assert!(!contexts.ime_disabled(OTHER));
    assert!(contexts.disable_thread_ime(TID, TID));
    assert!(!contexts.disable_thread_ime(TID, OTHER));
    assert!(!contexts.ime_disabled(OTHER));
    assert!(contexts.disable_thread_ime(TID, DISABLE_IME_ALL_THREADS));
    assert!(contexts.ime_disabled(OTHER));
}

#[test]
fn thread_cleanup_destroys_the_default_context_and_the_disable_flag_only() {
    let mut contexts = InputContexts::new();
    let mine = contexts.create(TID, 0).unwrap();
    let default = contexts.default_context(TID).unwrap();
    contexts.disable_thread_ime(TID, 0);
    contexts.cleanup_thread(TID);
    assert_eq!(contexts.query(default, INPUT_CONTEXT_CLIENT_PTR), Err(InvalidHandle));
    assert_eq!(contexts.query(mine, INPUT_CONTEXT_CLIENT_PTR), Ok(0));
    assert_eq!(contexts.existing_default(TID), None);
    assert!(!contexts.ime_disabled(TID));
}

#[test]
fn thread_cleanup_leaves_the_session_wide_disable_standing() {
    let mut contexts = InputContexts::new();
    contexts.disable_thread_ime(TID, DISABLE_IME_ALL_THREADS);
    contexts.cleanup_thread(TID);
    assert!(contexts.ime_disabled(TID));
}

#[test]
fn associate_refuses_every_flag_word_outside_the_admitted_three() {
    let ctx = ImcId::from_raw(3);
    for flags in [IACE_CHILDREN, IACE_DEFAULT | IACE_IGNORENOCONTEXT, 0x40, u32::MAX] {
        assert_eq!(associate(facts(flags, ctx, Some(TID), window(None, false))), AssociateOutcome { result: AICR_FAILED, assign: None }, "flags {flags:#x}");
    }
}

#[test]
fn associate_refuses_a_context_owned_by_another_thread() {
    let ctx = ImcId::from_raw(3);
    assert_eq!(associate(facts(0, ctx, Some(OTHER), window(None, false))).result, AICR_FAILED);
    assert_eq!(associate(facts(0, ctx, None, window(None, false))).result, AICR_FAILED);
}

#[test]
fn associate_refuses_a_window_the_process_does_not_own() {
    let ctx = ImcId::from_raw(3);
    assert_eq!(associate(facts(0, ctx, Some(TID), None)).result, AICR_FAILED);
    assert_eq!(associate(facts(0, None, None, None)).result, AICR_FAILED);
}

#[test]
fn associate_refuses_another_threads_window_only_when_a_context_is_named() {
    let ctx = ImcId::from_raw(3);
    let elsewhere = Some(WindowFacts { thread_id: OTHER, imc: None, focused: false });
    assert_eq!(associate(facts(0, ctx, Some(TID), elsewhere)).result, AICR_FAILED);
    assert_eq!(associate(facts(0, None, None, elsewhere)), AssociateOutcome { result: AICR_OK, assign: Some(None) });
}

#[test]
fn associate_stores_the_context_and_reports_the_focus_change() {
    let ctx = ImcId::from_raw(3);
    assert_eq!(associate(facts(0, ctx, Some(TID), window(None, false))), AssociateOutcome { result: AICR_OK, assign: Some(ctx) });
    assert_eq!(associate(facts(0, ctx, Some(TID), window(None, true))), AssociateOutcome { result: AICR_FOCUS_CHANGED, assign: Some(ctx) });
    assert_eq!(associate(facts(0, ctx, Some(TID), window(ctx, true))), AssociateOutcome { result: AICR_OK, assign: Some(ctx) });
}

#[test]
fn associate_clears_the_association_with_a_null_context() {
    let ctx = ImcId::from_raw(3);
    assert_eq!(associate(facts(0, None, None, window(ctx, true))), AssociateOutcome { result: AICR_FOCUS_CHANGED, assign: Some(None) });
}

#[test]
fn ignore_no_context_leaves_an_unassociated_window_alone() {
    let ctx = ImcId::from_raw(3);
    assert_eq!(associate(facts(IACE_IGNORENOCONTEXT, ctx, Some(TID), window(None, true))), AssociateOutcome { result: AICR_OK, assign: None });
    assert_eq!(associate(facts(IACE_IGNORENOCONTEXT, ctx, Some(TID), window(ImcId::from_raw(9), true))), AssociateOutcome { result: AICR_FOCUS_CHANGED, assign: Some(ctx) });
}

#[test]
fn default_flag_substitutes_the_thread_default_and_ignores_the_named_context() {
    let named = ImcId::from_raw(3);
    let default = ImcId::from_raw(8);
    let mut input = facts(IACE_DEFAULT, named, Some(OTHER), window(None, false));
    input.default_ctx = default;
    assert_eq!(associate(input), AssociateOutcome { result: AICR_OK, assign: Some(default) });
    input.default_ctx = None;
    assert_eq!(associate(input).result, AICR_FAILED);
}
